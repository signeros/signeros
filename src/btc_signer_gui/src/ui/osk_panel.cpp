// SPDX-License-Identifier: MIT

#include "ui/osk_panel.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include "ui/theme.h"

namespace signeros {

OskPanel::OskPanel(QWidget *parent) : QWidget(parent)
{
    // Named so the stylesheet can give it a solid background and a lit top
    // edge. Without a background of its own a plain QWidget would let the page
    // underneath show through between the keys.
    setObjectName(QStringLiteral("oskPanel"));
    // A plain QWidget ignores the background and border a stylesheet gives it
    // unless it is told to draw them. Without this the panel is transparent and
    // the page shows through between the keys - which is exactly the "I cannot
    // tell which key I am hitting" this layer exists to fix.
    setAttribute(Qt::WA_StyledBackground, true);
    setAutoFillBackground(true);

    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(theme::px(14), theme::px(8), theme::px(14), theme::px(10));
    v->setSpacing(theme::px(6));

    auto *echoRow = new QHBoxLayout;
    echoRow->setSpacing(theme::px(12));

    echoCaption_ = new QLabel(this);
    echoCaption_->setFont(theme::uiFont(13, true));
    echoCaption_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
    echoRow->addWidget(echoCaption_, 0);

    echoText_ = new QLabel(this);
    echoText_->setFont(theme::monoFont(18, true));
    echoText_->setTextFormat(Qt::PlainText);
    // One long token with nothing to wrap at must not be able to widen this
    // panel - it is as wide as the screen and no wider. See revealedSecret().
    echoText_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    echoRow->addWidget(echoText_, 1);

    v->addLayout(echoRow);
    v->addWidget(theme::hLine(this));

    // Between the echo and the keys: what you are typing, then what it could
    // be, then the letters. Directly on top of the keys because that is where
    // the thumb already is.
    suggestionRow_ = new QWidget(this);
    auto *sug = new QHBoxLayout(suggestionRow_);
    sug->setContentsMargins(0, 0, 0, 0);
    sug->setSpacing(theme::px(8));
    for (int i = 0; i < kSuggestionCount; ++i) {
        suggestions_[i] = theme::keyButton(QString(), suggestionRow_);
        suggestions_[i]->setFont(theme::monoFont(17, true));
        connect(suggestions_[i], &QPushButton::clicked, this,
                [this, i]() { emit suggestionChosen(i); });
        sug->addWidget(suggestions_[i], 1);
    }
    suggestionRow_->hide();
    v->addWidget(suggestionRow_);

    keys_ = new OnScreenKeyboard(this);
    connect(keys_, &OnScreenKeyboard::characterTyped, this, &OskPanel::characterTyped);
    connect(keys_, &OnScreenKeyboard::backspacePressed, this, &OskPanel::backspacePressed);
    connect(keys_, &OnScreenKeyboard::deleteWordPressed, this, &OskPanel::deleteWordPressed);
    connect(keys_, &OnScreenKeyboard::clearAllPressed, this, &OskPanel::clearAllPressed);
    connect(keys_, &OnScreenKeyboard::hidePressed, this, [this]() {
        setPanelVisible(false);
        emit hideRequested();
    });
    v->addWidget(keys_, 1);

    // Nothing on the panel may take the keyboard focus away from the screen
    // that owns it: a physical keystroke has to keep reaching that screen's
    // keyPressEvent even while the on-screen keys are up.
    setFocusPolicy(Qt::NoFocus);

    hide();
}

void OskPanel::setMode(OnScreenKeyboard::Mode mode)
{
    keys_->setMode(mode);
}

void OskPanel::setEcho(const QString &caption, const QString &text, const char *colour)
{
    // One line, whatever the field does with its own. revealedSecret() breaks a
    // long passphrase into lines so a card can hold it; here that would make the
    // panel grow upwards over the page every time somebody typed. Long content
    // shows its tail, which is where the caret is and therefore the part being
    // looked at.
    QString flat = text;
    flat.replace(QLatin1Char('\n'), QLatin1Char(' '));
    const int kMax = 56;
    if (flat.size() > kMax)
        flat = QStringLiteral("< ") + flat.right(kMax);

    echoCaption_->setText(caption);
    echoText_->setText(flat);
    echoText_->setStyleSheet(
        colour != nullptr ? QStringLiteral("color: %1;").arg(QString::fromLatin1(colour))
                          : QString());
}

void OskPanel::setSuggestions(const QStringList &labels)
{
    const int had = suggestionRow_->isVisible() ? 1 : 0;

    for (int i = 0; i < kSuggestionCount; ++i) {
        const bool used = i < labels.size();
        // Cleared rather than merely hidden: a wordlist entry is a fragment of
        // the mnemonic being typed, and it does not get to outlive the
        // keystroke that produced it any more than the screens' own copies do.
        suggestions_[i]->setText(used ? labels.at(i) : QString());
        suggestions_[i]->setVisible(used);
    }
    suggestionRow_->setVisible(!labels.isEmpty());

    // The row changes the panel's height, so the panel has to be laid out
    // again or the keys move under the bottom edge of the screen.
    if (isVisible() && had != (suggestionRow_->isVisible() ? 1 : 0))
        reposition();
}

void OskPanel::reposition()
{
    QWidget *p = parentWidget();
    if (p == nullptr)
        return;

    // Tall enough for the keys to be worth aiming at, and never taller than
    // three fifths of the screen: the field the operator is typing into is
    // above the panel on the pages that could not fit a keyboard in the flow,
    // and burying that as well would only move the problem.
    int h = sizeHint().height();
    const int cap = (p->height() * 3) / 5;
    if (h > cap)
        h = cap;
    setGeometry(0, p->height() - h, p->width(), h);
}

void OskPanel::setPanelVisible(bool visible)
{
    if (!visible) {
        hide();
        return;
    }
    reposition();
    show();
    // Above every page of the stack it is floating over, whatever was added to
    // the parent after it.
    raise();
}

} // namespace signeros
