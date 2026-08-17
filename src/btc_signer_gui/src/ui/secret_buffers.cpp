// SPDX-License-Identifier: MIT

#include "ui/secret_buffers.h"

#include "core/secure_memory.h"

namespace signeros {

// Function-local statics rather than namespace-scope objects: construction is
// ordered and happens on first use, which matters because the constructor calls
// mlock(2) and the destructor wipes. A namespace-scope object would be
// destroyed during static destruction in an order this file does not control.
//
// Static storage rather than the heap, because a heap-allocated secret can be
// left behind by a reallocation or a missed destructor, and because it makes
// the number of places in this process that can contain a seed a fact you can
// count rather than a claim.

SecureString &mnemonicBuffer()
{
    static SecureString s;
    return s;
}

SecureString &passphraseBuffer()
{
    static SecureString s;
    return s;
}

SecureString &verificationBuffer()
{
    static SecureString s;
    return s;
}

SecureString &passphraseConfirmBuffer()
{
    static SecureString s;
    return s;
}

QString revealedSecret(const SecureString &s, int lineLength)
{
    if (lineLength < 1)
        lineLength = 1;

    const char *p = s.c_str();
    const std::size_t n = s.size();
    const std::size_t width = static_cast<std::size_t>(lineLength);

    QString out;
    // Reserved so the appends below cannot reallocate: a reallocation would
    // leave the partly built secret in a freed heap block that nothing wipes.
    out.reserve(static_cast<int>(n + n / width + 2));
    for (std::size_t i = 0; i < n; ++i) {
        if (i > 0 && i % width == 0)
            out += QLatin1Char('\n');
        // Latin-1 rather than a UTF-8 decode: both entry paths accept printable
        // ASCII only, so the byte and the character are the same thing and
        // there is no intermediate buffer to hold a decoded copy.
        out += QLatin1Char(p[i]);
    }
    return out;
}

void wipeAllSecrets()
{
    mnemonicBuffer().clear();
    passphraseBuffer().clear();
    verificationBuffer().clear();
    passphraseConfirmBuffer().clear();
}

bool passphraseConfirmed()
{
    // Compared in constant time and without either buffer being copied
    // anywhere: SecureString::equals() is a byte compare over the two locked
    // pages, so "do these match" never produces a third copy of the answer.
    return passphraseBuffer().equals(passphraseConfirmBuffer());
}

} // namespace signeros
