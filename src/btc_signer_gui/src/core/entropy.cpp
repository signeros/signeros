// SPDX-License-Identifier: MIT

#include "entropy.h"

#include <fcntl.h>
#include <linux/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>

// Present since Linux 3.17, but spelled out so a stale toolchain header cannot
// silently turn the non-blocking probe into a blocking one.
#ifndef GRND_NONBLOCK
#define GRND_NONBLOCK 0x0001
#endif

#include <wally_core.h>
#include <wally_crypto.h>

#if defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#include <x86intrin.h>
#define SIGNEROS_X86 1
#endif

namespace signeros {
namespace {

constexpr std::size_t kHashLen = 64;      // SHA-512
constexpr std::size_t kKernelBytes = 64;  // one full hash block from the kernel
constexpr std::size_t kCpuWords = 32;     // 256 bytes of CPU TRNG output
constexpr std::size_t kJitterSamples = 512;

// ---------------------------------------------------------------------------
// Timing
// ---------------------------------------------------------------------------

std::uint64_t nowNanos()
{
    struct timespec ts {};
    if (::clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ULL +
           static_cast<std::uint64_t>(ts.tv_nsec);
}

std::uint64_t cycleCounter()
{
#ifdef SIGNEROS_X86
    return static_cast<std::uint64_t>(__rdtsc());
#else
    return nowNanos();
#endif
}

// ---------------------------------------------------------------------------
// The CPU's own TRNG.
//
// RDSEED is the one to want: it is the conditioned output of the on-die entropy
// source, specified as full-entropy, whereas RDRAND is a DRBG reseeded from it.
// RDSEED is allowed to fail when the source has not accumulated enough entropy
// yet - the carry flag says so - which is why every read is retried and the
// result is counted rather than assumed.
//
// Both instructions are unprivileged, so this needs no device node and no
// permission: /dev/hwrng is root-only on this image (see etc/mdev.conf) and is
// deliberately not used.
// ---------------------------------------------------------------------------

#ifdef SIGNEROS_X86

bool rdseed64(std::uint64_t *out)
{
    unsigned char ok = 0;
    std::uint64_t value = 0;
    __asm__ __volatile__("rdseed %0; setc %1"
                         : "=r"(value), "=qm"(ok)
                         :
                         : "cc");
    *out = value;
    return ok != 0;
}

bool rdrand64(std::uint64_t *out)
{
    unsigned char ok = 0;
    std::uint64_t value = 0;
    __asm__ __volatile__("rdrand %0; setc %1"
                         : "=r"(value), "=qm"(ok)
                         :
                         : "cc");
    *out = value;
    return ok != 0;
}

void cpuPause()
{
    __builtin_ia32_pause();
}

#endif // SIGNEROS_X86

} // namespace

// ---------------------------------------------------------------------------

bool cpuHasRdseed()
{
#ifdef SIGNEROS_X86
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid_max(0, nullptr) < 7)
        return false;
    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx) == 0)
        return false;
    return (ebx & (1u << 18)) != 0;   // CPUID.(EAX=7,ECX=0):EBX.RDSEED[bit 18]
#else
    return false;
#endif
}

bool cpuHasRdrand()
{
#ifdef SIGNEROS_X86
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx) == 0)
        return false;
    return (ecx & (1u << 30)) != 0;   // CPUID.(EAX=1):ECX.RDRAND[bit 30]
#else
    return false;
#endif
}

bool kernelEntropyReady()
{
    unsigned char probe = 0;
#ifdef SYS_getrandom
    const long rc = ::syscall(SYS_getrandom, &probe, sizeof(probe), GRND_NONBLOCK);
    secureWipe(&probe, sizeof(probe));
    if (rc == 1)
        return true;
    if (rc < 0 && errno == EAGAIN)
        return false;
    // ENOSYS on a kernel too old for the syscall: fall through to the device,
    // which on such a kernel is the only answer available.
#endif
    struct stat st {};
    return ::stat("/dev/urandom", &st) == 0;
}

// ---------------------------------------------------------------------------

std::string EntropyReport::describe() const
{
    std::string s = "kernel=";
    s += kernelOk ? (kernelWasReady ? "seeded" : "READ-BUT-NOT-SEEDED") : "UNAVAILABLE";
    s += " cpu-trng=";
    if (cpuRdseed)
        s += "rdseed";
    else if (cpuRdrand)
        s += "rdrand";
    else
        s += "none";
    s += "(" + std::to_string(cpuSamples) + " words)";
    s += " jitter=" + std::to_string(jitterSamples);
    s += " user=" + std::to_string(userSamples);
    return s;
}

// ---------------------------------------------------------------------------

EntropyPool::EntropyPool()
{
    reset();
}

EntropyPool::~EntropyPool()
{
    // state_'s own destructor wipes it; this makes the intent explicit for
    // anyone reading the flow rather than the container.
    state_.clear();
}

void EntropyPool::reset()
{
    // A fixed, public starting key. The pool's unpredictability comes entirely
    // from what is mixed in, never from a secret initial value - pretending
    // otherwise would only hide how much real entropy is present.
    static const char kDomain[] = "SignerOS/entropy-pool/v1";
    unsigned char seed[kHashLen] = {};
    wally_sha512(reinterpret_cast<const unsigned char *>(kDomain),
                 sizeof(kDomain) - 1, seed, sizeof(seed));
    std::memcpy(state_.data(), seed, kHashLen);
    state_.setSize(kHashLen);
    secureWipe(seed, sizeof(seed));

    userSamples_ = 0;
    counter_ = 0;
}

void EntropyPool::mix(const void *data, std::size_t len)
{
    if (data == nullptr || len == 0)
        return;

    // state <- HMAC-SHA512(key = state, msg = sample). Keyed by the whole
    // previous state, so the chain is irreversible in both directions: knowing
    // the final state tells an attacker nothing about an earlier one, and
    // knowing an earlier one tells them nothing without every sample since.
    SecureBuffer<kHashLen> next;
    if (wally_hmac_sha512(state_.data(), kHashLen,
                          static_cast<const unsigned char *>(data), len,
                          next.data(), kHashLen) != WALLY_OK)
        return;

    std::memcpy(state_.data(), next.data(), kHashLen);
    // next's destructor wipes it.
}

void EntropyPool::mixUserEvent(std::int32_t x, std::int32_t y, std::uint32_t extra)
{
    // The coordinates are what the operator did; the two clocks are when they
    // did it, sampled here rather than taken from the event, so the measurement
    // includes this process's own scheduling latency. The counter keeps two
    // identical events from folding in identically.
    struct {
        std::int32_t x;
        std::int32_t y;
        std::uint32_t extra;
        std::uint32_t pad;
        std::uint64_t nanos;
        std::uint64_t cycles;
        std::uint64_t counter;
    } sample = { x, y, extra, 0, nowNanos(), cycleCounter(), ++counter_ };

    mix(&sample, sizeof(sample));
    secureWipe(&sample, sizeof(sample));
    ++userSamples_;
}

bool EntropyPool::finalise(unsigned char *out, std::size_t bytes,
                           EntropyReport *report, std::string *err)
{
    if (out == nullptr || bytes == 0 || bytes > kHashLen) {
        if (err) *err = "internal error: bad entropy request size";
        return false;
    }

    EntropyReport rep;
    rep.userSamples = userSamples_;

    // --- 1. the kernel CSPRNG -------------------------------------------
    //
    // Read NON-blocking, deliberately.
    //
    // getrandom(2) with flags=0 waits until the CRNG is initialised, and on a
    // machine that offers the kernel nothing to seed from that wait has no
    // bound. This process is a full-screen kiosk on an appliance with no shell,
    // no console and no second application: a syscall that never returns is not
    // a delay, it is a brick. So the pool's readiness is asked about rather than
    // waited on, recorded honestly in the report, and turned into a refusal
    // below if the CPU could not make up for it.
    {
        SecureBuffer<kKernelBytes> kernel;
        std::size_t got = 0;

#ifdef SYS_getrandom
        while (got < kKernelBytes) {
            const long n = ::syscall(SYS_getrandom, kernel.data() + got,
                                     kKernelBytes - got, GRND_NONBLOCK);
            if (n > 0) {
                got += static_cast<std::size_t>(n);
                continue;
            }
            if (n < 0 && errno == EINTR)
                continue;
            break;   // EAGAIN (not seeded yet), or ENOSYS on an ancient kernel
        }
#endif
        rep.kernelWasReady = (got == kKernelBytes);

        if (got < kKernelBytes) {
            // Either the syscall does not exist, or the CRNG is not initialised.
            // /dev/urandom is the same generator through a door that never
            // blocks; before initialisation its output is best-effort rather
            // than guaranteed, which is exactly why kernelWasReady is reported
            // separately and why this alone is not allowed to be the only
            // source.
            const int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
            if (fd >= 0) {
                while (got < kKernelBytes) {
                    const ssize_t n = ::read(fd, kernel.data() + got, kKernelBytes - got);
                    if (n > 0) {
                        got += static_cast<std::size_t>(n);
                        continue;
                    }
                    if (n < 0 && errno == EINTR)
                        continue;
                    break;
                }
                ::close(fd);
            }
        }

        if (got == kKernelBytes) {
            rep.kernelOk = true;
            mix(kernel.data(), kKernelBytes);
        }
    }

    // --- 2. the CPU's hardware TRNG, read directly ----------------------
#ifdef SIGNEROS_X86
    {
        const bool haveSeed = cpuHasRdseed();
        const bool haveRand = cpuHasRdrand();
        rep.cpuRdrand = haveRand;

        if (haveSeed || haveRand) {
            SecureBuffer<kCpuWords * sizeof(std::uint64_t)> words;
            std::size_t n = 0;

            for (std::size_t i = 0; i < kCpuWords; ++i) {
                std::uint64_t value = 0;
                bool ok = false;

                // RDSEED is specified to fail when the entropy source has not
                // caught up. Ten tries with a PAUSE between them is the retry
                // discipline Intel documents; giving up on a word is fine,
                // because the count is reported and the kernel source is
                // independent of this one.
                if (haveSeed) {
                    for (int attempt = 0; attempt < 10 && !ok; ++attempt) {
                        ok = rdseed64(&value);
                        if (!ok)
                            cpuPause();
                    }
                    if (ok)
                        rep.cpuRdseed = true;
                }
                if (!ok && haveRand) {
                    for (int attempt = 0; attempt < 10 && !ok; ++attempt) {
                        ok = rdrand64(&value);
                        if (!ok)
                            cpuPause();
                    }
                }
                if (!ok)
                    continue;

                std::memcpy(words.data() + n * sizeof(value), &value, sizeof(value));
                secureWipe(&value, sizeof(value));
                ++n;
            }

            rep.cpuSamples = n;
            if (n > 0)
                mix(words.data(), n * sizeof(std::uint64_t));
        }
    }
#endif

    // --- 3. timing jitter ------------------------------------------------
    {
        SecureBuffer<kJitterSamples * sizeof(std::uint32_t)> jitter;
        std::uint64_t prev = cycleCounter();
        for (std::size_t i = 0; i < kJitterSamples; ++i) {
            // A memory read the compiler cannot fold away, so the loop's
            // latency depends on cache and scheduler state rather than being
            // constant. The low bits of the delta are the sample.
            const std::uint64_t now = cycleCounter();
            const std::uint32_t delta = static_cast<std::uint32_t>(now - prev);
            std::memcpy(jitter.data() + i * sizeof(delta), &delta, sizeof(delta));
            prev = now;
#ifdef SIGNEROS_X86
            cpuPause();
#endif
        }
        rep.jitterSamples = kJitterSamples;
        mix(jitter.data(), kJitterSamples * sizeof(std::uint32_t));
    }

    // Wall-clock and process identity: worth nothing on their own, free to add,
    // and they make two machines started from an identical image diverge even
    // if everything above somehow agreed.
    {
        struct {
            std::uint64_t nanos;
            std::uint64_t cycles;
            std::int32_t pid;
            std::int32_t pad;
            const void *stackAddress;
        } misc = { nowNanos(), cycleCounter(), ::getpid(), 0, &rep };
        mix(&misc, sizeof(misc));
    }

    // --- the refusal ------------------------------------------------------
    //
    // At least one source has to be one we can actually stand behind: an
    // initialised kernel CRNG, or the CPU's own generator. Jitter and mouse
    // movement are real contributions, but they are not a basis on which to
    // mint a key that will hold someone's savings, and neither is a CRNG that
    // has told us it is not seeded yet.
    //
    // There is no override. A signer that says "randomness looks weak, continue
    // anyway?" has already lost the argument, because the operator has no way
    // to evaluate the question and every incentive to press yes.
    if (!(rep.kernelOk && rep.kernelWasReady) && rep.cpuSamples == 0) {
        if (err) {
            *err = rep.kernelOk
                ? "the kernel's random pool reports that it is not seeded yet, "
                  "and this CPU offers neither RDSEED nor RDRAND. No wallet will "
                  "be created, because the seed could be guessable. Keep using "
                  "the machine for a few seconds - moving the mouse and typing "
                  "is what seeds the pool - and try again."
                : "no trustworthy source of randomness is available on this "
                  "machine: the kernel random pool could not be read at all and "
                  "this CPU offers neither RDSEED nor RDRAND. No wallet will be "
                  "created, because its seed could be guessable.";
        }
        if (report) *report = rep;
        return false;
    }

    // --- output -----------------------------------------------------------
    {
        static const char kLabel[] = "SignerOS/wallet-entropy/v1";
        SecureBuffer<kHashLen> okm;
        if (wally_hmac_sha512(state_.data(), kHashLen,
                              reinterpret_cast<const unsigned char *>(kLabel),
                              sizeof(kLabel) - 1,
                              okm.data(), kHashLen) != WALLY_OK) {
            if (err) *err = "the entropy pool could not be finalised (HMAC failed)";
            if (report) *report = rep;
            return false;
        }
        std::memcpy(out, okm.data(), bytes);

        // Fold the output back in, so a second finalise() on the same pool
        // cannot repeat the first. Nothing in the flow does that today; this is
        // here so that it stays safe if something ever does.
        mix(okm.data(), kHashLen);
    }

    if (report) *report = rep;
    return true;
}

} // namespace signeros
