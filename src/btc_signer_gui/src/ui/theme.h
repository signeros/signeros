// SPDX-License-Identifier: MIT
//
// theme.h - one place for every visual decision.
//
// Constraints this theme is designed around, which are not the usual ones:
//
//   * The panel may be a 1024x600 industrial LCD or a 4K laptop screen, and
//     there is no compositor doing any scaling for us.
//   * The user may be operating it with a finger on a resistive touchscreen, so
//     nothing interactive is smaller than a fingertip.
//   * The most important thing on screen is always an amount or an address.
//     Those are monospaced, high contrast, and never truncated silently.
//   * There is no mouse cursor and no window chrome.

#pragma once

#include <QFont>
#include <QString>

class QApplication;
class QFrame;
class QLabel;
class QPushButton;
class QWidget;

namespace signeros {

void applyTheme(QApplication *app);

namespace theme {

// Palette. Deliberately dark: these machines get used in badly lit places, and
// a dark panel makes the orange "this is the number that matters" accents and
// the red warnings jump out.
inline const char *bg()        { return "#0d1117"; }
inline const char *panel()     { return "#161b22"; }
inline const char *panelAlt()  { return "#1c2330"; }
inline const char *border()    { return "#30363d"; }
inline const char *text()      { return "#e6edf3"; }
inline const char *textDim()   { return "#9aa4b2"; }
inline const char *accent()    { return "#f7931a"; }   // bitcoin orange
inline const char *ok()        { return "#3fb950"; }
inline const char *warn()      { return "#d29922"; }
inline const char *danger()    { return "#f85149"; }
// Used only where a second, cooler accent is genuinely needed to separate two
// kinds of information (the splash, the entropy meter). Never for money.
inline const char *accentCool() { return "#4f9cf9"; }

// Scaled pixels. The same number that sizes every font and margin in this
// theme, exposed so screens can scale their own spacing from the panel size
// instead of hard-coding numbers that only look right on one display.
int px(int base);

// The screen this build is running on is as likely to be a 24" desktop monitor
// as a 7" panel, and text that fills a 1920px line is unreadable regardless of
// how well it is typeset. Wraps `content` in a column that stays centred and
// never grows past `maxWidthPx` (already scaled).
QWidget *centeredColumn(QWidget *content, int maxWidthPx, QWidget *parent = nullptr);

// Whether a mouse cursor is drawn at all.
//
// The appliance's own panel is a touchscreen and wants none; a machine driven
// by a mouse, a trackpad or a tablet is unusable without one. main() decides
// from the devices it found in /dev/input and sets this before any widget is
// constructed - the buttons and the top-level window read it while they are
// being built, so setting it later has no effect.
void setCursorVisible(bool visible);
bool cursorVisible();

QFont uiFont(int pixelSize, bool bold = false);
QFont monoFont(int pixelSize, bool bold = false);

// Section header with a rule under it.
QWidget *sectionHeader(const QString &title, QWidget *parent = nullptr);

QLabel *heading(const QString &text, QWidget *parent = nullptr);
QLabel *body(const QString &text, QWidget *parent = nullptr);
QLabel *dim(const QString &text, QWidget *parent = nullptr);
QLabel *mono(const QString &text, int pixelSize = 16, QWidget *parent = nullptr);

QPushButton *primaryButton(const QString &text, QWidget *parent = nullptr);
QPushButton *secondaryButton(const QString &text, QWidget *parent = nullptr);
QPushButton *dangerButton(const QString &text, QWidget *parent = nullptr);
QPushButton *keyButton(const QString &text, QWidget *parent = nullptr);

QFrame *hLine(QWidget *parent = nullptr);

// A bordered card used for each input/output row and each finding.
QFrame *card(QWidget *parent = nullptr);

// Marks a card as the one keystrokes are currently going into: accent border,
// lifted background. Used by the signing screen, where the field being typed
// into is not a QWidget with focus - the screen keeps the focus itself and
// routes characters into a SecureString - so Qt's own focus ring never appears
// and the operator has nothing to go on unless we draw it ourselves.
void setCardFocused(QFrame *card, bool focused);

} // namespace theme
} // namespace signeros
