// SPDX-License-Identifier: MIT
//
// osk.h - the on-screen keyboard.
//
// This exists because SignerOS must be usable on a machine with a touchscreen
// and no physical keyboard, and because it is the only input path for the one
// piece of data that must never touch a heap-allocated string: the mnemonic.
//
// The keyboard emits individual characters. It never assembles, stores or
// displays the text - the screen that owns it appends each character into a
// SecureString. That is what keeps the mnemonic out of Qt's memory.

#pragma once

#include <QWidget>

class QStackedLayout;
class QVBoxLayout;

namespace signeros {

class OnScreenKeyboard : public QWidget {
    Q_OBJECT

public:
    enum class Mode {
        // Lowercase a-z plus space: exactly the BIP39 alphabet, so a mnemonic
        // cannot be mistyped into a character that could never be in it.
        Bip39,
        // Everything, for a BIP39 passphrase (which may be any UTF-8 text; this
        // keyboard covers printable ASCII).
        FullText,
    };

    explicit OnScreenKeyboard(QWidget *parent = nullptr);

    void setMode(Mode mode);
    Mode mode() const { return mode_; }

signals:
    void characterTyped(char c);
    void backspacePressed();
    void deleteWordPressed();
    void clearAllPressed();
    void acceptPressed();
    // "put the keyboard away" - see the comment on the key in osk.cpp.
    void hidePressed();

private:
    QWidget *buildLetterPage(bool upper);
    QWidget *buildSymbolPage();
    QWidget *buildRow(const char *keys, bool upper, QWidget *parent);
    // QVBoxLayout is forward-declared above, at global scope. Writing
    // `class QVBoxLayout *layout` inline here instead would declare a *new*
    // type, signeros::QVBoxLayout, and every use of the name inside this
    // namespace - in this header and in everything that includes it - would
    // then resolve to that incomplete type rather than Qt's class.
    void addControlRow(QWidget *page, QVBoxLayout *layout, bool allowLayerSwitch);
    void showPage(int index);

    Mode mode_ = Mode::Bip39;
    QStackedLayout *pages_ = nullptr;
    int lowerIndex_ = 0;
    int upperIndex_ = 1;
    int symbolIndex_ = 2;
};

} // namespace signeros
