// SPDX-License-Identifier: MIT

#include "secure_memory.h"

#include <strings.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <unistd.h>

#if defined(__has_include)
#if __has_include(<features.h>)
#include <features.h>
#endif
#endif

#include <wally_core.h>

namespace signeros {
namespace {

bool g_allLocked = true;

} // namespace

// ---------------------------------------------------------------------------

void secureWipe(void *p, std::size_t n) noexcept
{
    if (p == nullptr || n == 0)
        return;

    // Layer 1: libwally's own secure clear. Upstream is built with
    // -fno-builtin-memset so this cannot be optimised away inside the library.
    wally_bzero(p, n);

#if defined(__GLIBC__) && defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 25)
    // Layer 2: the C library's non-elidable zeroing.
    explicit_bzero(p, n);
#endif
#endif

    // Layer 3: a volatile store loop, in case neither of the above applied.
    volatile unsigned char *vp = static_cast<volatile unsigned char *>(p);
    for (std::size_t i = 0; i < n; ++i)
        vp[i] = 0;

    // Layer 4: pretend the memory is read here, so no compiler can prove the
    // stores above are dead and delete them.
    __asm__ __volatile__("" : : "r"(p) : "memory");
}

bool lockPages(void *p, std::size_t n) noexcept
{
    if (p == nullptr || n == 0)
        return true;
    if (::mlock(p, n) == 0)
        return true;
    g_allLocked = false;
    return false;
}

void unlockPages(void *p, std::size_t n) noexcept
{
    if (p != nullptr && n != 0)
        (void)::munlock(p, n);
}

bool allPagesLocked() noexcept
{
    return g_allLocked;
}

void hardenProcess() noexcept
{
    // No core dumps: a core file of this process is a seed on disk. The kernel
    // is built without CONFIG_COREDUMP and signer-session sets `ulimit -c 0`;
    // this is the in-process third layer.
    struct rlimit rl {};
    rl.rlim_cur = 0;
    rl.rlim_max = 0;
    (void)::setrlimit(RLIMIT_CORE, &rl);

    // Not dumpable also means not ptrace-able by a same-uid process, and
    // strips read access to /proc/self/mem for anything but root.
    (void)::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);

#if defined(PR_SET_NO_NEW_PRIVS)
    // Nothing this process execs can gain privileges. It never execs anything,
    // which is the point: if it ever does, it cannot become root.
    (void)::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif

    // Every page of this process, current and future, stays resident. Without
    // MCL_FUTURE, a secret that landed in a page allocated after startup would
    // be unprotected. Needs RLIMIT_MEMLOCK headroom, which signer-session
    // grants with `ulimit -l unlimited` before dropping privileges.
    if (::mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        g_allLocked = false;
}

// ---------------------------------------------------------------------------
// SecureString
// ---------------------------------------------------------------------------

bool SecureString::append(char c) noexcept
{
    if (len_ + 1 >= kCapacity)
        return false;
    buf_[len_++] = c;
    buf_[len_] = '\0';
    return true;
}

bool SecureString::append(const char *s, std::size_t n) noexcept
{
    if (s == nullptr)
        return false;
    if (len_ + n + 1 > kCapacity)
        return false;
    for (std::size_t i = 0; i < n; ++i)
        buf_[len_ + i] = s[i];
    len_ += n;
    buf_[len_] = '\0';
    return true;
}

bool SecureString::assign(const char *s, std::size_t n) noexcept
{
    clear();
    return append(s, n);
}

void SecureString::backspace() noexcept
{
    if (len_ == 0)
        return;
    buf_[--len_] = '\0';
}

void SecureString::backspaceWord() noexcept
{
    // Drop any trailing separator first, then the word itself. Matches what a
    // user expects from "delete word" while entering a mnemonic.
    while (len_ > 0 && (buf_[len_ - 1] == ' ' || buf_[len_ - 1] == '\t'))
        buf_[--len_] = '\0';
    while (len_ > 0 && buf_[len_ - 1] != ' ' && buf_[len_ - 1] != '\t')
        buf_[--len_] = '\0';
}

void SecureString::clear() noexcept
{
    secureWipe(buf_, sizeof(buf_));
    len_ = 0;
}

std::size_t SecureString::wordCount() const noexcept
{
    std::size_t count = 0;
    bool inWord = false;
    for (std::size_t i = 0; i < len_; ++i) {
        const bool ws = (buf_[i] == ' ' || buf_[i] == '\t' ||
                         buf_[i] == '\n' || buf_[i] == '\r');
        if (!ws && !inWord) {
            ++count;
            inWord = true;
        } else if (ws) {
            inWord = false;
        }
    }
    return count;
}

std::size_t SecureString::trailingWordLength() const noexcept
{
    std::size_t n = 0;
    std::size_t i = len_;
    while (i > 0) {
        const char c = buf_[i - 1];
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r')
            break;
        ++n;
        --i;
    }
    return n;
}

std::size_t SecureString::copyTrailingWord(char *out, std::size_t outLen) const noexcept
{
    if (out == nullptr || outLen == 0)
        return 0;

    const std::size_t wordLen = trailingWordLength();
    const std::size_t n = (wordLen < outLen - 1) ? wordLen : outLen - 1;
    for (std::size_t i = 0; i < n; ++i)
        out[i] = buf_[len_ - wordLen + i];
    out[n] = '\0';
    return n;
}

void SecureString::normaliseWhitespace() noexcept
{
    std::size_t w = 0;
    bool pendingSpace = false;

    for (std::size_t r = 0; r < len_; ++r) {
        const char c = buf_[r];
        const bool ws = (c == ' ' || c == '\t' || c == '\n' || c == '\r');
        if (ws) {
            if (w > 0)
                pendingSpace = true;
            continue;
        }
        if (pendingSpace) {
            buf_[w++] = ' ';
            pendingSpace = false;
        }
        buf_[w++] = c;
    }

    // Wipe the tail we just shortened past, so no fragment of the old text
    // survives behind the NUL terminator.
    if (w < len_)
        secureWipe(buf_ + w, len_ - w);
    len_ = w;
    buf_[len_] = '\0';
}

// ---------------------------------------------------------------------------
// The grid view. See the block comment in secure_memory.h for what a "slot" is
// and why the count lives in the text rather than in a member.
// ---------------------------------------------------------------------------

bool SecureString::insertAt(std::size_t pos, const char *s, std::size_t n) noexcept
{
    if (s == nullptr || pos > len_)
        return false;
    if (n == 0)
        return true;
    if (len_ + n + 1 > kCapacity)
        return false;

    // Backwards, so an overlapping shift does not overwrite what it is about
    // to read.
    for (std::size_t i = len_; i-- > pos;)
        buf_[i + n] = buf_[i];
    for (std::size_t i = 0; i < n; ++i)
        buf_[pos + i] = s[i];

    len_ += n;
    buf_[len_] = '\0';
    return true;
}

void SecureString::eraseAt(std::size_t pos, std::size_t n) noexcept
{
    if (pos >= len_ || n == 0)
        return;
    if (n > len_ - pos)
        n = len_ - pos;

    for (std::size_t i = pos; i + n < len_; ++i)
        buf_[i] = buf_[i + n];

    // The characters the shift left behind at the end are still the secret's
    // last n bytes. Wipe them rather than trusting the terminator to hide them.
    secureWipe(buf_ + (len_ - n), n);
    len_ -= n;
    buf_[len_] = '\0';
}

std::size_t SecureString::slotCount() const noexcept
{
    std::size_t n = 1;
    for (std::size_t i = 0; i < len_; ++i) {
        if (buf_[i] == ' ')
            ++n;
    }
    return n;
}

bool SecureString::slotSpan(std::size_t index, std::size_t *start,
                            std::size_t *len) const noexcept
{
    std::size_t slot = 0;
    std::size_t begin = 0;
    // <= len_ so the final slot, which has no separator after it, is closed by
    // the end of the buffer.
    for (std::size_t i = 0; i <= len_; ++i) {
        if (i != len_ && buf_[i] != ' ')
            continue;
        if (slot == index) {
            if (start != nullptr) *start = begin;
            if (len != nullptr) *len = i - begin;
            return true;
        }
        ++slot;
        begin = i + 1;
    }
    return false;
}

std::size_t SecureString::slotLength(std::size_t index) const noexcept
{
    std::size_t start = 0;
    std::size_t len = 0;
    return slotSpan(index, &start, &len) ? len : 0;
}

std::size_t SecureString::copySlot(std::size_t index, char *out,
                                   std::size_t outLen) const noexcept
{
    if (out == nullptr || outLen == 0)
        return 0;
    out[0] = '\0';

    std::size_t start = 0;
    std::size_t len = 0;
    if (!slotSpan(index, &start, &len))
        return 0;

    const std::size_t n = (len < outLen - 1) ? len : outLen - 1;
    for (std::size_t i = 0; i < n; ++i)
        out[i] = buf_[start + i];
    out[n] = '\0';
    return n;
}

bool SecureString::setSlotCount(std::size_t count) noexcept
{
    if (count == 0)
        return false;

    const std::size_t cur = slotCount();
    if (cur == count)
        return true;

    if (cur < count) {
        // Each new slot is one more separator and nothing else: empty.
        const std::size_t add = count - cur;
        if (len_ + add + 1 > kCapacity)
            return false;
        for (std::size_t i = 0; i < add; ++i)
            buf_[len_ + i] = ' ';
        len_ += add;
        buf_[len_] = '\0';
        return true;
    }

    // Shrinking throws away whatever was typed into the slots past the new end.
    // It is wiped here rather than merely cut off, so a 24-word entry narrowed
    // to 12 does not leave the last twelve words sitting in the buffer.
    std::size_t start = 0;
    std::size_t len = 0;
    if (!slotSpan(count - 1, &start, &len))
        return false;
    const std::size_t keep = start + len;
    if (keep < len_)
        secureWipe(buf_ + keep, len_ - keep);
    len_ = keep;
    buf_[len_] = '\0';
    return true;
}

bool SecureString::appendToSlot(std::size_t index, char c) noexcept
{
    if (c == ' ')
        return false;
    std::size_t start = 0;
    std::size_t len = 0;
    if (!slotSpan(index, &start, &len))
        return false;
    return insertAt(start + len, &c, 1);
}

void SecureString::backspaceInSlot(std::size_t index) noexcept
{
    std::size_t start = 0;
    std::size_t len = 0;
    if (!slotSpan(index, &start, &len) || len == 0)
        return;
    eraseAt(start + len - 1, 1);
}

void SecureString::clearSlot(std::size_t index) noexcept
{
    std::size_t start = 0;
    std::size_t len = 0;
    if (!slotSpan(index, &start, &len) || len == 0)
        return;
    eraseAt(start, len);
}

bool SecureString::setSlot(std::size_t index, const char *s, std::size_t n) noexcept
{
    if (s == nullptr)
        return false;
    for (std::size_t i = 0; i < n; ++i) {
        if (s[i] == ' ')
            return false;
    }

    std::size_t start = 0;
    std::size_t len = 0;
    if (!slotSpan(index, &start, &len))
        return false;

    // eraseAt only moves what is after `start`, so the offset stays good.
    eraseAt(start, len);
    return insertAt(start, s, n);
}

std::size_t SecureString::firstEmptySlot() const noexcept
{
    const std::size_t count = slotCount();
    for (std::size_t i = 0; i < count; ++i) {
        if (slotLength(i) == 0)
            return i;
    }
    return count;
}

} // namespace signeros
