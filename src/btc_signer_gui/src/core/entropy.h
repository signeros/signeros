// SPDX-License-Identifier: MIT
//
// entropy.h - the entropy pool a freshly created wallet is born from.
//
// This is the one place in SignerOS where the quality of a random number
// decides whether money can be stolen. Signing does not need entropy at all -
// libwally uses RFC6979 deterministic nonces, so a lying RNG cannot leak a
// private key through a biased k (see the note in the kernel defconfig). Seed
// generation is the opposite: the seed IS the entropy, and a predictable one is
// a wallet an attacker can empty from the other side of the world without ever
// touching this machine.
//
// So this file does not trust any single source. It mixes several independent
// ones through HMAC-SHA512, in an extract-style chain:
//
//     state <- HMAC-SHA512(key = state, msg = sample)
//
// Any one source that the attacker cannot predict makes the result
// unpredictable, no matter how thoroughly the others are compromised. That is
// the entire argument, and it is why the sources are deliberately unalike:
//
//   1. The kernel CSPRNG. Seeded from interrupt timing, the CPU's RDSEED at
//      boot, and the seeding the kernel does before userspace exists. Read
//      non-blocking, because a getrandom(2) that waits for an unseeded pool has
//      no bound and this process is a kiosk with no shell behind it - so
//      "is it seeded" is asked rather than waited on, and reported either way.
//   2. The CPU's own hardware TRNG, read directly with RDSEED (RDRAND as a
//      fallback), bypassing the kernel entirely. An unprivileged instruction,
//      so no device node and no permission is involved. This is a genuinely
//      separate path to the same silicon the kernel used - it is here so that a
//      compromised kernel pool is not the only thing standing between the user
//      and a predictable seed, and vice versa.
//   3. Timing jitter: the low bits of the timestamp counter sampled across a
//      short unpredictable-latency loop. Weak on its own, free, and independent
//      of both of the above.
//   4. Whatever the operator physically contributes - pointer movement,
//      touches, keystrokes - fed in by the GUI through mix(). Physical, outside
//      the machine, and the only source a purely software attacker cannot see.
//
// No Qt here, on purpose: this is key material, so it is built and exercised by
// scripts/host_selftest.sh with no display in sight.

#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

#include "secure_memory.h"

namespace signeros {

// What actually contributed, so the user interface can state it rather than
// claim it. Everything here is shape, not content: safe to display and to log.
struct EntropyReport {
    bool kernelOk = false;          // a full block was read from the kernel
    bool kernelWasReady = false;    // ...and it came from an initialised CRNG,
                                    // rather than best-effort /dev/urandom
    bool cpuRdseed = false;         // RDSEED is present and produced values
    bool cpuRdrand = false;         // RDRAND is present (fallback, or as well)
    std::size_t cpuSamples = 0;     // 64-bit words obtained from the CPU TRNG
    std::size_t jitterSamples = 0;
    std::size_t userSamples = 0;    // events the operator contributed

    // A one-line human summary of the above, for the screen and the self-test.
    std::string describe() const;
};

// True when the CPU advertises the instruction. Checked through CPUID, not by
// executing it and hoping: RDSEED on a CPU without it is #UD.
bool cpuHasRdseed();
bool cpuHasRdrand();

// True when the kernel CSPRNG reports itself initialised right now
// (getrandom(GRND_NONBLOCK) succeeds). False means a read would block, which on
// this appliance means "keep moving the mouse".
bool kernelEntropyReady();

// ---------------------------------------------------------------------------
// EntropyPool
//
// Accumulates samples, then produces final entropy exactly once per finalise().
// The running state is a locked, self-wiping buffer: it is pre-image material
// for a seed, so it is treated as a secret in its own right.
// ---------------------------------------------------------------------------
class EntropyPool {
public:
    // The minimum number of physical samples the GUI asks the operator for
    // before it will offer to generate. Not a security bound - the kernel and
    // the CPU TRNG are what the guarantee rests on - but it is a cheap,
    // visible, independent contribution, and asking for it is also what makes
    // the user understand where their seed came from.
    static constexpr std::size_t kUserSampleTarget = 256;

    EntropyPool();
    ~EntropyPool();

    EntropyPool(const EntropyPool &) = delete;
    EntropyPool &operator=(const EntropyPool &) = delete;

    // Forget everything, including the state. Called when the creation flow is
    // left, so a pool cannot span two wallets.
    void reset();

    // Fold arbitrary bytes into the state. Cheap enough to call per input
    // event; nothing is stored beyond the 64-byte chaining value.
    void mix(const void *data, std::size_t len);

    // Convenience for the GUI: one pointer or key event, with its coordinates,
    // an opaque per-event value, and the arrival time sampled here rather than
    // passed in, so the timing is measured as close to the interrupt as this
    // process can get.
    void mixUserEvent(std::int32_t x, std::int32_t y, std::uint32_t extra);

    std::size_t userSamples() const { return userSamples_; }
    bool userTargetReached() const { return userSamples_ >= kUserSampleTarget; }

    // Draw from the kernel and the CPU, fold in everything collected so far,
    // and write `bytes` of final entropy to `out`.
    //
    // Refuses - returns false, writes nothing - unless at least one source we
    // can stand behind contributed: an initialised kernel CRNG, or the CPU's
    // own generator. There is no "best effort" and no override here: a seed
    // that might be guessable is worse than no wallet at all.
    bool finalise(unsigned char *out, std::size_t bytes,
                  EntropyReport *report, std::string *err);

private:
    // The chaining value. HMAC-SHA512 keys are the full 64 bytes.
    SecureBuffer<64> state_;
    std::size_t userSamples_ = 0;
    std::uint64_t counter_ = 0;
};

} // namespace signeros
