// SPDX-License-Identifier: MIT

#include "entropy.h"

#include <fcntl.h>
#include <linux/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <array>
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

// Fill up to `want` words from ONE instruction. Returns how many were obtained.
//
// RDSEED is specified to fail when its entropy source has not caught up - the
// carry flag says so - which makes a failure back-pressure rather than an
// error. Ten tries with a PAUSE between them is the retry discipline Intel
// documents; giving up on a word is fine, because the count is reported and
// every other source is independent of this one.
//
// One instruction per call, rather than the per-word fallback this used to be,
// because the caller counts the two separately. A loop that silently answered a
// failed RDSEED with an RDRAND word and added it to the same tally is precisely
// how RDRAND came to pass for RDSEED here.
std::size_t drawCpuWords(bool (*read)(std::uint64_t *), std::size_t want,
                         std::uint64_t *out)
{
    std::size_t got = 0;
    for (std::size_t i = 0; i < want; ++i) {
        std::uint64_t value = 0;
        bool ok = false;
        for (int attempt = 0; attempt < 10 && !ok; ++attempt) {
            ok = read(&value);
            if (!ok)
                cpuPause();
        }
        if (!ok)
            continue;
        out[got++] = value;
        secureWipe(&value, sizeof(value));
    }
    return got;
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

bool cpuWordsLookSane(const std::uint64_t *words, std::size_t n)
{
    // A single word cannot be checked against anything, and a generator that
    // yielded one word out of thirty-two attempts is starved to the point of
    // being no source at all. Both answer no.
    if (words == nullptr || n < 2)
        return false;

    for (std::size_t i = 0; i < n; ++i) {
        // The two constants a broken generator has actually been observed to
        // hand back while setting the carry flag.
        if (words[i] == 0 || words[i] == ~UINT64_C(0))
            return false;

        // Any repeat at all, not a "how many changed" threshold: two
        // independent 64-bit draws collide with probability 2^-64, so this
        // cannot fire on a working CPU and needs no number chosen for it.
        for (std::size_t j = 0; j < i; ++j) {
            if (words[i] == words[j])
                return false;
        }
    }
    return true;
}

bool entropyPolicySatisfied(const EntropyReport &report)
{
    // RDRAND is absent from this expression on purpose, and that absence is the
    // whole of GitHub issue #3.
    //
    // RDSEED is the conditioned output of the on-die entropy source. RDRAND is
    // a DRBG sitting in front of it: what it returns is AES-CTR over a seed
    // nobody outside the CPU can inspect, so "it answered" is not evidence that
    // anything unpredictable happened behind it - and the one failure mode that
    // has actually shipped, a constant returned with the carry flag set, looks
    // identical from here to a working part. cpuWordsLookSane() catches the
    // constant; nothing catches a DRBG that is merely reseeding from something
    // the attacker knows.
    //
    // So RDRAND is mixed in whenever it is available, and it is never the
    // reason this machine agrees to mint a key. What is left as a reason: a
    // kernel CRNG that reports itself initialised - it was credited 256 bits
    // from somewhere - or RDSEED.
    return (report.kernelOk && report.kernelWasReady) || report.rdseedWords > 0;
}

// ---------------------------------------------------------------------------

std::string EntropyReport::describe() const
{
    std::string s = "kernel=";
    s += kernelOk ? (kernelWasReady ? "seeded" : "READ-BUT-NOT-SEEDED") : "UNAVAILABLE";
    // Per instruction, in words, because "the CPU contributed" is the claim
    // this line exists to stop anybody making: only one of the two counts.
    s += " cpu-rdseed=" + std::to_string(rdseedWords) + "w";
    s += " cpu-rdrand=" + std::to_string(rdrandWords) + "w";
    if (cpuRejected > 0)
        s += " cpu-REJECTED=" + std::to_string(cpuRejected) + "w";
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

namespace {

// What to tell the operator when entropyPolicySatisfied() says no.
//
// Three sentences, always in the same order: what is wrong with the kernel,
// what is wrong with the CPU, and what to do about it. The last one is omitted
// when there is nothing to do - waiting does not help a pool that could not be
// read at all - because an instruction that does not work is worse than none.
std::string refusalMessage(const EntropyReport &rep)
{
    std::string s = rep.kernelOk
        ? "the kernel's random pool reports that it is not seeded yet"
        : "the kernel's random pool could not be read at all";

    s += ", and ";

    if (rep.cpuRejected > 0) {
        s += "this CPU's hardware generator answered with a constant instead of "
             "with random words - a known way for it to fail while still "
             "reporting success - so nothing it produced has been counted";
    } else if (rep.rdrandWords > 0) {
        s += "the only hardware generator this CPU offers is RDRAND, which is a "
             "deterministic generator standing in front of an entropy source "
             "nobody outside the CPU can inspect. It has been mixed in, but it "
             "is not on its own something to mint a key from";
    } else if (cpuHasRdseed() || cpuHasRdrand()) {
        s += "this CPU's hardware generator produced nothing";
    } else {
        s += "this CPU offers neither RDSEED nor RDRAND";
    }

    s += ". No wallet will be created, because the seed could be guessable.";

    if (rep.kernelOk) {
        s += " Keep using the machine for a few seconds - moving the mouse and "
             "typing is what seeds the kernel pool - and try again.";
    }
    return s;
}

} // namespace

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
            //
            // The read is worth making even when it is refused as a source: an
            // unseeded read makes the kernel run try_to_generate_entropy(), its
            // own timing-jitter seeder (drivers/char/random.c). That is what
            // makes the refusal's "try again" honest advice rather than a
            // shrug - the attempt that failed also pushed the pool along.
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
    //
    // Two passes over two instructions rather than one loop with a per-word
    // fallback, because what each of them produced has to be counted on its
    // own: RDSEED can carry the refusal below and RDRAND cannot. RDSEED first,
    // for as many words as it will give; RDRAND fills whatever is left.
#ifdef SIGNEROS_X86
    {
        // Locked and self-wiping like every other buffer here, and typed as
        // words rather than bytes so the sanity check below reads what was
        // written without a cast the compiler is entitled to disbelieve.
        SecureObject<std::array<std::uint64_t, kCpuWords>> draw;
        std::uint64_t *words = draw.get()->data();

        std::size_t seedGot = 0;
        std::size_t randGot = 0;

        if (cpuHasRdseed())
            seedGot = drawCpuWords(rdseed64, kCpuWords, words);
        if (cpuHasRdrand() && seedGot < kCpuWords)
            randGot = drawCpuWords(rdrand64, kCpuWords - seedGot, words + seedGot);

        // Everything drawn goes into the pool whether or not it is counted.
        // Folding a constant into an HMAC chain cannot make the state worse,
        // and "mixed, never chosen" is the rule this file is built on. What the
        // sanity check decides is only what may be *credited* - and crediting
        // is what the refusal reads.
        if (seedGot + randGot > 0)
            mix(words, (seedGot + randGot) * sizeof(std::uint64_t));

        // Each source stands or falls on its own run. A stuck RDRAND must not
        // be able to discredit an RDSEED that was working, and - the case that
        // matters - a working RDSEED must not launder a stuck RDRAND.
        if (cpuWordsLookSane(words, seedGot))
            rep.rdseedWords = seedGot;
        else
            rep.cpuRejected += seedGot;

        if (cpuWordsLookSane(words + seedGot, randGot))
            rep.rdrandWords = randGot;
        else
            rep.cpuRejected += randGot;

        rep.cpuRdseed = rep.rdseedWords > 0;
        rep.cpuRdrand = rep.rdrandWords > 0;
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
    // initialised kernel CRNG, or RDSEED. Jitter, mouse movement and RDRAND are
    // all real contributions and all of them are in the pool by now, but none
    // of them is a basis on which to mint a key that will hold someone's
    // savings - and neither is a CRNG that has told us it is not seeded yet.
    //
    // There is no override. A signer that says "randomness looks weak, continue
    // anyway?" has already lost the argument, because the operator has no way
    // to evaluate the question and every incentive to press yes.
    if (!entropyPolicySatisfied(rep)) {
        if (err) *err = refusalMessage(rep);
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
