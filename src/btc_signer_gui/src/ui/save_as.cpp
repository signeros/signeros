// SPDX-License-Identifier: MIT

#include "ui/save_as.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QPushButton>
#include <QShowEvent>
#include <QTimer>
#include <QVBoxLayout>

#include "core/psbt_engine.h"   // sanitiseFileName
#include "ui/theme.h"

namespace signeros {
namespace {

bool isPrintableAscii(QChar c)
{
    return c.unicode() >= 0x20 && c.unicode() <= 0x7e;
}

} // namespace

SaveAsPage::SaveAsPage(QWidget *parent) : QWidget(parent)
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(theme::px(24), theme::px(16), theme::px(24), theme::px(16));
    v->setSpacing(theme::px(10));

    // Everything above the keyboard is fixed height. Without that the leftover
    // space is shared out among the labels, which on a tall screen puts a hand
    // of blank rows between the heading and the field it belongs to.
    heading_ = theme::heading(QString(), this);
    heading_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    v->addWidget(heading_);

    subtitle_ = new QLabel(this);
    subtitle_->setFont(theme::monoFont(15));
    subtitle_->setWordWrap(true);
    subtitle_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Fixed);
    subtitle_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
    v->addWidget(subtitle_);

    v->addWidget(theme::hLine(this));

    QFrame *box = theme::card(this);
    box->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Fixed);
    // The lit border every other entry field on this machine uses. This page is
    // the only one with a single field, so it is always the focused one.
    box->setObjectName(QStringLiteral("cardFocus"));
    auto *bv = new QVBoxLayout(box);
    bv->setContentsMargins(theme::px(14), theme::px(10), theme::px(14), theme::px(12));
    bv->setSpacing(theme::px(6));

    auto *caption = new QLabel(QStringLiteral("FILE NAME"), box);
    caption->setFont(theme::uiFont(13, true));
    caption->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
    bv->addWidget(caption);

    nameLabel_ = new QLabel(box);
    nameLabel_->setFont(theme::monoFont(20, true));
    nameLabel_->setTextFormat(Qt::PlainText);
    nameLabel_->setWordWrap(true);
    nameLabel_->setMinimumHeight(theme::px(34));
    // A long name is one token with no spaces, so it gets the same treatment as
    // every other unbreakable string on this machine: it may not widen the
    // window. See revealedSecret() in secret_buffers.h for what happens when
    // something is allowed to.
    nameLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    bv->addWidget(nameLabel_);

    dirLabel_ = new QLabel(box);
    dirLabel_->setFont(theme::uiFont(14));
    dirLabel_->setWordWrap(true);
    dirLabel_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    bv->addWidget(dirLabel_);

    v->addWidget(box);

    error_ = new QLabel(this);
    error_->setFont(theme::uiFont(15, true));
    error_->setWordWrap(true);
    error_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
    error_->setSizePolicy(QSizePolicy::Preferred, QSizePolicy::Minimum);
    error_->hide();
    v->addWidget(error_);

    // Absorbs whatever the page does not use, so the field stays under its
    // heading instead of drifting down the screen.
    v->addStretch(1);

    hint_ = new QLabel(this);
    hint_->setFont(theme::uiFont(13));
    hint_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    hint_->setAlignment(Qt::AlignRight);
    hint_->setText(QStringLiteral("type to change the name  ·  Enter accepts it  "
                                 "·  F2 on-screen keys  ·  Esc back"));
    v->addWidget(hint_);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));

    QPushButton *backBtn = theme::secondaryButton(QStringLiteral("Back"), this);
    connect(backBtn, &QPushButton::clicked, this, &SaveAsPage::back);
    buttons->addWidget(backBtn);


    oskToggle_ = theme::secondaryButton(QStringLiteral("On-screen keys (F2)"), this);
    oskToggle_->setCheckable(true);
    connect(oskToggle_, &QPushButton::clicked, this, &SaveAsPage::keyboardRequested);
    buttons->addWidget(oskToggle_);

    clearBtn_ = theme::secondaryButton(QStringLiteral("Clear"), this);
    connect(clearBtn_, &QPushButton::clicked, this, [this]() {
        name_.clear();
        refresh();
    });
    buttons->addWidget(clearBtn_);

    buttons->addStretch(1);

    acceptBtn_ = theme::primaryButton(QStringLiteral("Save"), this);
    connect(acceptBtn_, &QPushButton::clicked, this, &SaveAsPage::accepted);
    buttons->addWidget(acceptBtn_);

    v->addLayout(buttons);

    // Nothing on this page may hold the keyboard focus - not the buttons, and
    // not the page itself. The screen above the stack keeps it and calls
    // handleKey(); see the comment there for what happens when a page inside a
    // QStackedWidget tries to read the keyboard itself.
    for (QPushButton *b : findChildren<QPushButton *>())
        b->setFocusPolicy(Qt::NoFocus);
    setFocusPolicy(Qt::NoFocus);

    caretTimer_ = new QTimer(this);
    caretTimer_->setInterval(530);
    connect(caretTimer_, &QTimer::timeout, this, [this]() {
        caretOn_ = !caretOn_;
        refresh();
    });
}

void SaveAsPage::begin(const QString &heading, const QString &subtitle,
                       const QString &proposedName, const QString &directory,
                       const QString &confirmLabel, bool showOnScreenKeyboard)
{
    heading_->setText(heading);
    subtitle_->setText(subtitle);
    subtitle_->setVisible(!subtitle.isEmpty());
    dirLabel_->setText(QStringLiteral("written to %1").arg(directory));
    acceptBtn_->setText(confirmLabel);
    error_->hide();

    name_ = proposedName;
    // Nothing is selected, so the default cannot be destroyed by the next
    // keystroke: an operator who wants their own name presses Clear (or the
    // keyboard's own delete-word) first, and one who does not press Enter.
    hint_->setVisible(!showOnScreenKeyboard);

    caretOn_ = true;
    caretTimer_->start();
    refresh();
}

void SaveAsPage::setKeyboardShown(bool shown)
{
    oskToggle_->setChecked(shown);
    hint_->setVisible(!shown);
}

QString SaveAsPage::fileName() const
{
    return name_.trimmed();
}

void SaveAsPage::setError(const QString &text)
{
    error_->setText(text);
    error_->setVisible(!text.isEmpty());
}

// "The name is what I want, write it." Public, because the first Enter after
// this page appears does not arrive here: it is delivered to whichever widget
// had the focus before the page switch - the screen that owns this page - and
// that screen calls this instead. The second and later ones do arrive here.
// Both paths land in one function so they cannot drift apart.
void SaveAsPage::accept()
{
    // A refusal here used to be silent, which on the one page whose hint line
    // promises "Enter accepts it" is indistinguishable from a broken keyboard.
    if (!acceptBtn_->isEnabled()) {
        setError(QStringLiteral("That name has nothing usable in it. Type a "
                                "name, or press Clear and start again."));
        return;
    }
    emit accepted();
}

void SaveAsPage::backspace()
{
    name_.chop(1);
    caretOn_ = true;
    refresh();
}

void SaveAsPage::clearName()
{
    name_.clear();
    caretOn_ = true;
    refresh();
}

void SaveAsPage::typeCharacter(char c)
{
    if (!isPrintableAscii(QChar(QLatin1Char(c))))
        return;
    if (name_.size() >= 120)
        return;
    name_ += QLatin1Char(c);
    caretOn_ = true;
    refresh();
}

void SaveAsPage::refresh()
{
    // Judged by the function that will actually be applied to it, so the button
    // and the writer cannot disagree about what a usable name is.
    const std::string cleaned =
        sanitiseFileName(name_.trimmed().toStdString(), std::string());
    acceptBtn_->setEnabled(!cleaned.empty());

    // The caret is drawn into the text, and its off phase is a space of the
    // same width in this monospaced font, so nothing reflows as it blinks.
    nameLabel_->setText(name_ + (caretOn_ ? QChar(0x2588)
                                          : QChar(QLatin1Char(' '))));
}

void SaveAsPage::showEvent(QShowEvent *event)
{
    QWidget::showEvent(event);
    caretOn_ = true;
    caretTimer_->start();
}

void SaveAsPage::hideEvent(QHideEvent *event)
{
    QWidget::hideEvent(event);
    caretTimer_->stop();
}

bool SaveAsPage::handleKey(QKeyEvent *event)
{
    const int k = event->key();

    if (k == Qt::Key_Return || k == Qt::Key_Enter) {
        accept();
        return true;
    }
    if (k == Qt::Key_Backspace) {
        name_.chop(1);
        caretOn_ = true;
        refresh();
        return true;
    }

    // A file name is not a secret, so unlike every other entry field on this
    // machine this one may read QKeyEvent::text(): that is what makes the
    // punctuation people put in file names - dots, dashes, underscores - come
    // out as themselves rather than as whatever a US keymap says the key is.
    const QString typed = event->text();
    if (typed.size() == 1 && isPrintableAscii(typed.at(0))) {
        typeCharacter(static_cast<char>(typed.at(0).unicode()));
        return true;
    }

    // Escape and F12 belong to AppWindow; anything else here is not ours.
    return false;
}

} // namespace signeros
