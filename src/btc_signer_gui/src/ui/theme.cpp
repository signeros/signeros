// SPDX-License-Identifier: MIT

#include "ui/theme.h"

#include <QApplication>
#include <QFrame>
#include <QGuiApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScreen>
#include <QStyle>
#include <QVBoxLayout>
#include <QWidget>

namespace signeros {
namespace {

// Scale everything from the shortest screen edge so the same build is legible
// on a 600px industrial panel and on a 2160px laptop screen. Computed once, on
// first use, after QApplication exists.
int uiScalePercent()
{
    static int scale = 0;
    if (scale != 0)
        return scale;

    scale = 100;
    if (const QScreen *s = QGuiApplication::primaryScreen()) {
        const int shortEdge = qMin(s->geometry().width(), s->geometry().height());
        if (shortEdge >= 1900)
            scale = 175;
        else if (shortEdge >= 1300)
            scale = 140;
        else if (shortEdge >= 1000)
            scale = 115;
        else if (shortEdge < 620)
            scale = 85;
    }
    return scale;
}

bool g_cursorVisible = false;

} // namespace

namespace theme {

int px(int base)
{
    return (base * uiScalePercent()) / 100;
}

void setCursorVisible(bool visible)
{
    g_cursorVisible = visible;
}

bool cursorVisible()
{
    return g_cursorVisible;
}

QFont uiFont(int pixelSize, bool bold)
{
    QFont f(QStringLiteral("DejaVu Sans"));
    f.setPixelSize(px(pixelSize));
    f.setBold(bold);
    return f;
}

QFont monoFont(int pixelSize, bool bold)
{
    // Addresses, txids and amounts are always monospaced: it is the difference
    // between "did I check every character" and "it looked about right".
    QFont f(QStringLiteral("DejaVu Sans Mono"));
    f.setStyleHint(QFont::Monospace);
    f.setPixelSize(px(pixelSize));
    f.setBold(bold);
    return f;
}

QLabel *heading(const QString &text, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(22, true));
    l->setWordWrap(true);
    return l;
}

QLabel *body(const QString &text, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(16));
    l->setWordWrap(true);
    return l;
}

QLabel *dim(const QString &text, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(uiFont(14));
    l->setWordWrap(true);
    l->setStyleSheet(QStringLiteral("color: %1;").arg(textDim()));
    return l;
}

QLabel *mono(const QString &text, int pixelSize, QWidget *parent)
{
    auto *l = new QLabel(text, parent);
    l->setFont(monoFont(pixelSize));
    l->setWordWrap(true);
    // Long addresses wrap rather than being elided: a truncated address is a
    // verification failure waiting to happen.
    l->setTextInteractionFlags(Qt::NoTextInteraction);
    return l;
}

QWidget *sectionHeader(const QString &title, QWidget *parent)
{
    auto *w = new QWidget(parent);
    auto *v = new QVBoxLayout(w);
    v->setContentsMargins(0, px(10), 0, px(4));
    v->setSpacing(px(4));

    auto *l = new QLabel(title.toUpper(), w);
    QFont f = uiFont(13, true);
    f.setLetterSpacing(QFont::AbsoluteSpacing, 1.5);
    l->setFont(f);
    l->setStyleSheet(QStringLiteral("color: %1;").arg(accent()));
    v->addWidget(l);
    v->addWidget(hLine(w));
    return w;
}

QFrame *hLine(QWidget *parent)
{
    auto *f = new QFrame(parent);
    f->setFrameShape(QFrame::HLine);
    f->setFrameShadow(QFrame::Plain);
    f->setFixedHeight(1);
    f->setStyleSheet(QStringLiteral("background: %1; border: none;").arg(border()));
    return f;
}

QWidget *centeredColumn(QWidget *content, int maxWidthPx, QWidget *parent)
{
    // A row with elastic margins either side. On a 1024x600 panel the stretches
    // collapse to nothing and the column takes the full width; on a 27" monitor
    // they absorb the difference and the text keeps a readable measure instead
    // of running the whole way across the glass.
    auto *w = new QWidget(parent);
    auto *h = new QHBoxLayout(w);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(0);
    h->addStretch(1);
    content->setParent(w);
    content->setMaximumWidth(maxWidthPx);
    h->addWidget(content, 1000);   // wins the space until it hits its maximum
    h->addStretch(1);
    return w;
}

QFrame *card(QWidget *parent)
{
    auto *f = new QFrame(parent);
    f->setObjectName(QStringLiteral("card"));
    return f;
}

void setCardFocused(QFrame *c, bool focused)
{
    if (c == nullptr)
        return;

    const QString want = focused ? QStringLiteral("cardFocus") : QStringLiteral("card");
    if (c->objectName() == want)
        return;
    c->setObjectName(want);

    // An objectName selector is resolved when the widget is polished, which has
    // already happened by the time anything switches fields. Without this the
    // name changes and the border does not.
    c->style()->unpolish(c);
    c->style()->polish(c);
    c->update();
}

namespace {

QPushButton *makeButton(const QString &text, const char *role, QWidget *parent)
{
    auto *b = new QPushButton(text, parent);
    b->setProperty("role", QString::fromLatin1(role));
    b->setFont(uiFont(18, true));
    b->setMinimumHeight(px(56));
    b->setMinimumWidth(px(140));
    if (!cursorVisible())
        b->setCursor(Qt::BlankCursor);
    b->setFocusPolicy(Qt::StrongFocus);
    return b;
}

} // namespace

QPushButton *primaryButton(const QString &text, QWidget *parent)
{
    return makeButton(text, "primary", parent);
}

QPushButton *secondaryButton(const QString &text, QWidget *parent)
{
    return makeButton(text, "secondary", parent);
}

QPushButton *dangerButton(const QString &text, QWidget *parent)
{
    return makeButton(text, "danger", parent);
}

QPushButton *keyButton(const QString &text, QWidget *parent)
{
    auto *b = new QPushButton(text, parent);
    b->setProperty("role", QStringLiteral("key"));
    b->setFont(monoFont(20, true));
    b->setMinimumHeight(px(52));
    b->setMinimumWidth(px(48));
    if (!cursorVisible())
        b->setCursor(Qt::BlankCursor);
    // Keys must not steal focus from the entry field they feed.
    b->setFocusPolicy(Qt::NoFocus);
    b->setAutoRepeat(false);
    return b;
}

} // namespace theme

// ---------------------------------------------------------------------------

void applyTheme(QApplication *app)
{
    app->setFont(theme::uiFont(16));
    // An application-wide override would blank the cursor on every widget, so
    // it is only installed when there is no pointing device to draw one for.
    if (!theme::cursorVisible())
        app->setOverrideCursor(Qt::BlankCursor);

    const QString sheet = QStringLiteral(R"(
        QWidget {
            background: %1;
            color: %3;
        }
        /* Labels inherit the page background from the rule above, which paints
           a rectangle of it over whatever they sit on - so every line of text
           inside a card was drawn on a visible band of the wrong colour.
           Transparent is what a label should be everywhere; the two that want a
           background of their own (the warning banner, the status bar) set it
           explicitly and still win. */
        QLabel { background: transparent; }

        QFrame#card {
            background: %2;
            border: 1px solid %4;
            border-radius: 6px;
        }
        QFrame#cardWarn  { background: %2; border: 1px solid %7; border-radius: 6px; }
        QFrame#cardDanger{ background: %2; border: 1px solid %8; border-radius: 6px; }
        /* The card that is currently receiving keystrokes. See
           theme::setCardFocused(): on the signing screen no widget holds the
           Qt focus, so this border is the only thing that says where typing
           goes. It has to be unmistakable at a glance and from a metre away,
           hence the accent colour rather than a lighter grey. */
        QFrame#cardFocus { background: %6; border: 2px solid %5; border-radius: 6px; }

        /* The file-name field on the save-as pages - the one real text input in
           the application (see save_as.h for why it is allowed to be one).
           Styled to look like what it is: a box you type into, with a caret. */
        QLineEdit {
            background: %1;
            border: 1px solid %4;
            border-radius: 4px;
            padding: 6px 8px;
            color: %3;
            selection-background-color: %5;
            selection-color: #10141c;
        }
        QLineEdit:focus { border: 1px solid %5; }

        /* The floating on-screen keyboard (ui/osk_panel.h). Opaque, because it
           is laid over the page rather than into it, and lit along the top edge
           so it reads as a layer that arrived rather than as part of the page
           it is covering. */
        QWidget#oskPanel {
            background: %2;
            border-top: 2px solid %5;
        }

        QScrollArea, QScrollArea > QWidget > QWidget { background: %1; }
        QScrollBar:vertical {
            background: %2; width: 18px; margin: 0;
            border: 1px solid %4; border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: %4; min-height: 40px; border-radius: 4px;
        }
        QScrollBar::add-line, QScrollBar::sub-line { height: 0; }

        QListWidget {
            background: %2;
            border: 1px solid %4;
            border-radius: 6px;
            padding: 4px;
        }
        QListWidget::item {
            padding: 12px 10px;
            border-radius: 4px;
        }
        QListWidget::item:selected {
            background: %5;
            color: #10141c;
        }

        QPushButton {
            border-radius: 6px;
            padding: 8px 18px;
            border: 1px solid %4;
            background: %6;
            color: %3;
        }
        QPushButton:disabled {
            color: %9;
            border-color: %4;
            background: %2;
        }
        QPushButton:pressed { background: %4; }

        /* Checked state for the toggle-style buttons: the word-count choice on
           the wallet screen, and "mnemonic / extended private key" and
           "typing: key / passphrase" on the signing screen. Without this rule
           a checkable button looked exactly like an unchecked one, so on the
           signing screen the field you were actually typing into was
           indistinguishable from the one you were not - and the default word
           count was invisible. */
        QPushButton:checked {
            background: %6;
            color: %5;
            border: 2px solid %5;
        }

        QProgressBar {
            background: %2;
            border: 1px solid %4;
            border-radius: 6px;
            text-align: center;
        }
        QProgressBar::chunk {
            background: %5;
            border-radius: 5px;
        }

        QPushButton[role="primary"] {
            background: %5;
            color: #10141c;
            border: 1px solid %5;
        }
        QPushButton[role="primary"]:pressed { background: #c9760f; }
        QPushButton[role="primary"]:disabled { background: %2; color: %9; border-color: %4; }

        QPushButton[role="danger"] {
            background: %8;
            color: #10141c;
            border: 1px solid %8;
        }
        QPushButton[role="danger"]:pressed { background: #c1392f; }

        /* The two cards on the home screen. Laid out by child labels, so the
           button contributes only the frame, the focus ring and the click
           target - hence no padding and no text alignment of its own. */
        QPushButton[role="choice"] {
            background: %2;
            border: 1px solid %4;
            border-radius: 10px;
            padding: 0;
            text-align: left;
        }
        QPushButton[role="choice"]:focus {
            border: 2px solid %5;
            background: %6;
        }
        QPushButton[role="choice"]:pressed { background: %6; }

        QPushButton[role="key"] {
            background: %6;
            border: 1px solid %4;
        }
        QPushButton[role="key"]:pressed { background: %5; color: #10141c; }

        QPushButton:focus { border: 2px solid %5; }
    )")
        .arg(theme::bg())        // %1
        .arg(theme::panel())     // %2
        .arg(theme::text())      // %3
        .arg(theme::border())    // %4
        .arg(theme::accent())    // %5
        .arg(theme::panelAlt())  // %6
        .arg(theme::warn())      // %7
        .arg(theme::danger())    // %8
        .arg(theme::textDim());  // %9

    app->setStyleSheet(sheet);
}

} // namespace signeros
