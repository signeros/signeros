// SPDX-License-Identifier: MIT
//
// osk_panel.h - the on-screen keyboard as a layer over the page, not a row in
// it.
//
// It used to be a widget in each page's column, which meant every page had to
// find room for it. On the crowded ones - the signing screen with three entry
// cards and a payment summary, the import screen with a 24-cell grid - there
// was no room, so bringing the keyboard up squeezed everything, including the
// keyboard: rows of keys a few pixels tall that you could see but not aim at.
// A keyboard that is hardest to hit on the pages that need it most is not a
// keyboard.
//
// So it floats. The panel is a child of the *screen*, positioned across the
// bottom of it, on top of whatever the page was drawing there. It is opaque and
// it covers things, which is fine: a keyboard is modal by nature, and what it
// covers is a page the operator has stopped reading in order to type.
//
// Two consequences, both handled here rather than by each page:
//
//   * It carries its own echo line. The field being typed into is usually
//     underneath the panel now, so the panel repeats it: which field, and what
//     is in it, right above the keys. The operator sees what they are typing
//     without having to see past the keyboard.
//   * It carries its own "hide keys" key (in the keyboard's control row), since
//     the page's own buttons are behind it.
//   * It carries the BIP39 word suggestions, for the same reason as the echo:
//     the page's own suggestion row is underneath the panel and unreachable
//     while it is up. In the panel they sit directly on top of the keys, where
//     a word you are half way through typing is one tap away - which is where
//     every phone keyboard puts them, and for the same reason.
//
// One panel per screen, not per page: the screen decides which page's input the
// keystrokes belong to, exactly as it does for a physical keyboard.

#pragma once

#include <QString>
#include <QStringList>
#include <QWidget>

#include "ui/osk.h"

class QLabel;
class QPushButton;

namespace signeros {

class OskPanel : public QWidget {
    Q_OBJECT

public:
    explicit OskPanel(QWidget *parent = nullptr);

    void setMode(OnScreenKeyboard::Mode mode);

    // The line above the keys: what is being typed into, and what is in it.
    // `colour` is a theme colour for the value, or nullptr for the default.
    void setEcho(const QString &caption, const QString &text,
                 const char *colour = nullptr);

    // The word suggestions, already labelled by the screen (it knows whether
    // the "1 " accelerator prefix is worth showing). An empty list hides the
    // row - and the row is not there at all for anything but a mnemonic.
    void setSuggestions(const QStringList &labels);

    // Lay the panel across the bottom of its parent. Called by the screen's
    // resizeEvent and whenever the panel is shown.
    void reposition();

    void setPanelVisible(bool visible);
    bool panelVisible() const { return isVisible(); }

signals:
    void characterTyped(char c);
    void backspacePressed();
    void deleteWordPressed();
    void clearAllPressed();
    void suggestionChosen(int index);
    // The "hide keys" key. The screen listens so its own toggle button and the
    // panel cannot disagree about whether the keyboard is up.
    void hideRequested();

private:
    OnScreenKeyboard *keys_ = nullptr;
    QLabel *echoCaption_ = nullptr;
    QLabel *echoText_ = nullptr;

    // Same count as every screen's own row, so a screen can hand its list
    // straight over.
    static constexpr int kSuggestionCount = 5;
    QWidget *suggestionRow_ = nullptr;
    QPushButton *suggestions_[kSuggestionCount] = {};
};

} // namespace signeros
