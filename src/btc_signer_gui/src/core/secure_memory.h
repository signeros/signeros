// SPDX-License-Identifier: MIT
//
// secure_memory.h - fixed-size, page-locked, self-wiping containers for key
// material.
//
// Rules this file exists to enforce:
//
//   * Secrets never live on the heap. Every container here has its storage
//     inline, so a mnemonic sits in the object (stack, or static storage) and
//     nowhere else. No realloc leaves a copy behind, and there is no
//     allocator metadata pointing at it.
//   * Secrets never reach a swap device or a core dump: mlock() on
//     construction, munlock() after the wipe. (There is no swap device on
//     SignerOS, and CONFIG_COREDUMP is off - this is the third layer.)
//   * Secrets are zeroed the moment they go out of scope, with a wipe the
//     compiler is not allowed to elide.
//
// Nothing here depends on Qt, on purpose: the signing core builds and runs
// without a GUI, which is what makes scripts/host_selftest.sh possible.

#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace signeros {

// ---------------------------------------------------------------------------
// secureWipe
//
// Zeroes n bytes such that the write survives optimisation. Layered on
// purpose: wally_bzero() (which resolves to memset_s/explicit_bzero/
// SecureZeroMemory upstream), then explicit_bzero() where the C library has
// it, then a volatile-pointer loop, then an empty asm barrier that reads the
// buffer so the compiler cannot prove the stores are dead.
//
// libwally-core is additionally built with --disable-builtin-memset
// (-fno-builtin-memset), so even the innermost memset cannot be turned into a
// no-op at -Os.
// ---------------------------------------------------------------------------
void secureWipe(void *p, std::size_t n) noexcept;

// mlock/munlock, best effort. Returns false when RLIMIT_MEMLOCK forbids it,
// which the caller reports rather than treating as fatal: a signer that
// refuses to run is worse than one running with a soft warning, and there is
// no swap on this system for pages to leak into.
bool lockPages(void *p, std::size_t n) noexcept;
void unlockPages(void *p, std::size_t n) noexcept;

// True if every page of every SecureBuffer/SecureString so far could be
// locked. Surfaced on the signing screen.
bool allPagesLocked() noexcept;

// Applies process-wide protections: no core dumps, not ptrace-able (also
// enforced by kernel.yama.ptrace_scope=3), and mlockall() so future
// allocations cannot be paged out either. Safe to call once from main().
void hardenProcess() noexcept;

// ---------------------------------------------------------------------------
// SecureBuffer<N> - fixed-capacity byte buffer for binary secrets
// (BIP39 seed, private keys, signature hashes).
// ---------------------------------------------------------------------------
template <std::size_t N>
class SecureBuffer {
public:
    SecureBuffer() noexcept {
        lockPages(buf_, N);
        secureWipe(buf_, N);
    }
    ~SecureBuffer() {
        secureWipe(buf_, N);
        unlockPages(buf_, N);
    }

    SecureBuffer(const SecureBuffer &) = delete;
    SecureBuffer &operator=(const SecureBuffer &) = delete;
    SecureBuffer(SecureBuffer &&) = delete;
    SecureBuffer &operator=(SecureBuffer &&) = delete;

    unsigned char *data() noexcept { return buf_; }
    const unsigned char *data() const noexcept { return buf_; }
    static constexpr std::size_t capacity() noexcept { return N; }

    std::size_t size() const noexcept { return len_; }
    void setSize(std::size_t n) noexcept { len_ = (n <= N) ? n : N; }

    void clear() noexcept {
        secureWipe(buf_, N);
        len_ = 0;
    }

private:
    alignas(16) unsigned char buf_[N] = {};
    std::size_t len_ = 0;
};

// ---------------------------------------------------------------------------
// SecureString - fixed-capacity NUL-terminated secret text.
//
// Holds the mnemonic and the BIP39 passphrase. Capacity is sized for the worst
// case (24 words x 8 characters + 23 separators = 215) with room to spare.
//
// The interface is deliberately keystroke-shaped - append(char), backspace(),
// backspaceWord() - because that is how the on-screen keyboard feeds it. The
// text is never handed to a QString, so it never lands in Qt's heap.
// ---------------------------------------------------------------------------
class SecureString {
public:
    static constexpr std::size_t kCapacity = 320;

    SecureString() noexcept {
        lockPages(buf_, sizeof(buf_));
        secureWipe(buf_, sizeof(buf_));
    }
    ~SecureString() {
        secureWipe(buf_, sizeof(buf_));
        unlockPages(buf_, sizeof(buf_));
    }

    SecureString(const SecureString &) = delete;
    SecureString &operator=(const SecureString &) = delete;

    const char *c_str() const noexcept { return buf_; }
    char *mutableData() noexcept { return buf_; }
    std::size_t size() const noexcept { return len_; }
    bool empty() const noexcept { return len_ == 0; }
    bool full() const noexcept { return len_ + 1 >= kCapacity; }
    static constexpr std::size_t capacity() noexcept { return kCapacity; }

    // "Are these two the same text?" - the question a passphrase typed twice
    // exists to ask, answered without either buffer being copied out to
    // somewhere that is not wiped.
    //
    // The loop does not stop at the first differing byte. The lengths are
    // already visible on screen so there is nothing to hide there, but how far
    // down two secrets agree is not something this process should be timing.
    bool equals(const SecureString &other) const noexcept {
        if (len_ != other.len_)
            return false;
        unsigned char diff = 0;
        for (std::size_t i = 0; i < len_; ++i)
            diff |= static_cast<unsigned char>(buf_[i] ^ other.buf_[i]);
        return diff == 0;
    }

    bool append(char c) noexcept;
    bool append(const char *s, std::size_t n) noexcept;
    void backspace() noexcept;      // one character
    void backspaceWord() noexcept;  // the trailing word and its separator
    void clear() noexcept;

    // Adopt exactly n bytes of external text (used when reading a mnemonic
    // file in self-test mode), then wipe the source yourself.
    bool assign(const char *s, std::size_t n) noexcept;

    // Whitespace-separated word count, and the length of the trailing
    // in-progress word. Both are shape, not content: safe to display.
    std::size_t wordCount() const noexcept;
    std::size_t trailingWordLength() const noexcept;

    // Copies the trailing in-progress word into out (NUL-terminated).
    // Only used to compute BIP39 suggestions; wipe out when done.
    std::size_t copyTrailingWord(char *out, std::size_t outLen) const noexcept;

    // Collapses runs of whitespace and strips leading/trailing whitespace, in
    // place. BIP39 validation wants exactly single-space separation.
    void normaliseWhitespace() noexcept;

    // -----------------------------------------------------------------------
    // The grid view
    //
    // The same buffer read as a fixed number of fields separated by exactly one
    // space each, any of which may be EMPTY. This is what a mnemonic grid needs
    // and what append()/backspace() cannot express: the operator stands in a
    // cell, moves to any other cell, and empties one to re-type it while the
    // words after it stay where they are.
    //
    // The slot count is deliberately not a member. It is the number of
    // separators in the buffer plus one, so there is no second piece of state
    // that can drift out of agreement with the text it describes;
    // setSlotCount() is what establishes it, and clear() resets it by resetting
    // the text.
    //
    // Nothing here is *named* `slots`, including the parameters: Qt #defines
    // that word, this header is included from translation units that have
    // already included Qt, and a local called `slots` there disappears into a
    // syntax error some distance from its cause. Ask seed_view.h, which has the
    // same note for the same reason.
    //
    // wordCount() keeps counting NON-EMPTY fields, which is exactly "how many
    // cells are filled". So `wordCount() == slotCount()` is the test for a
    // complete grid, and a complete grid holds no adjacent separators - it is
    // already in the single-space form BIP39 validation wants.
    // -----------------------------------------------------------------------

    // Grows by appending empty slots, or shrinks by dropping the slots past the
    // new end - wiped, not left behind the terminator. False only if the buffer
    // has no room or `count` is 0.
    bool setSlotCount(std::size_t count) noexcept;
    std::size_t slotCount() const noexcept;

    // Where slot `index` begins and how long it is; false when there is no such
    // slot. The span points into the locked buffer, so comparing two slots
    // through it copies no secret anywhere.
    bool slotSpan(std::size_t index, std::size_t *start, std::size_t *len) const noexcept;
    std::size_t slotLength(std::size_t index) const noexcept;

    // NUL-terminated copy of one slot, for the BIP39 suggestion lookup. Wipe it
    // when done.
    std::size_t copySlot(std::size_t index, char *out, std::size_t outLen) const noexcept;

    // Editing within one slot. A separator is structure here rather than a
    // character, so appendToSlot() and setSlot() refuse a space outright: the
    // only thing that may change the number of slots is setSlotCount().
    bool appendToSlot(std::size_t index, char c) noexcept;
    void backspaceInSlot(std::size_t index) noexcept;
    void clearSlot(std::size_t index) noexcept;
    bool setSlot(std::size_t index, const char *s, std::size_t n) noexcept;

    // The first slot with nothing in it, or slotCount() when all are filled.
    std::size_t firstEmptySlot() const noexcept;

private:
    // Insert/remove in the middle, with the shifted-past tail wiped rather than
    // left readable behind the new terminator. Private because every legal
    // edit of a secret goes through the slot vocabulary above: an arbitrary
    // offset into a mnemonic is not something a screen should be able to name.
    bool insertAt(std::size_t pos, const char *s, std::size_t n) noexcept;
    void eraseAt(std::size_t pos, std::size_t n) noexcept;

    alignas(16) char buf_[kCapacity] = {};
    std::size_t len_ = 0;
};

// ---------------------------------------------------------------------------
// SecureObject<T> - one instance of a POD secret in static storage.
//
// Used for the BIP32 master key (struct ext_key). Static storage rather than
// the heap, and exactly one instance, so at any moment there is precisely one
// page range in the process that can contain a master private key, it is
// locked, and its lifetime is explicit.
// ---------------------------------------------------------------------------
template <typename T>
class SecureObject {
public:
    SecureObject() noexcept {
        lockPages(&storage_, sizeof(storage_));
        secureWipe(&storage_, sizeof(storage_));
    }
    ~SecureObject() {
        secureWipe(&storage_, sizeof(storage_));
        unlockPages(&storage_, sizeof(storage_));
    }

    SecureObject(const SecureObject &) = delete;
    SecureObject &operator=(const SecureObject &) = delete;

    T *get() noexcept { return reinterpret_cast<T *>(&storage_); }
    const T *get() const noexcept { return reinterpret_cast<const T *>(&storage_); }

    bool valid() const noexcept { return valid_; }
    void markValid() noexcept { valid_ = true; }

    void clear() noexcept {
        secureWipe(&storage_, sizeof(storage_));
        valid_ = false;
    }

private:
    alignas(16) unsigned char storage_[sizeof(T)] = {};
    bool valid_ = false;
};

} // namespace signeros
