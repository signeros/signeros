// SPDX-License-Identifier: MIT

#include "ui/screen_home.h"

#include <QHBoxLayout>
#include <QLabel>
#include <QVariant>
#include <QPushButton>
#include <QVBoxLayout>

#include "ui/app_window.h"
#include "ui/theme.h"

namespace signeros {

HomeScreen::HomeScreen(AppWindow *app, QWidget *parent) : QWidget(parent), app_(app)
{
    auto *outer = new QVBoxLayout(this);
    outer->setContentsMargins(theme::px(24), theme::px(18), theme::px(24), theme::px(20));
    outer->setSpacing(theme::px(10));

    auto *column = new QWidget(this);
    auto *v = new QVBoxLayout(column);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(theme::px(12));

    v->addStretch(2);

    QLabel *title = theme::heading(QStringLiteral("What would you like to do?"), column);
    title->setAlignment(Qt::AlignCenter);
    title->setFont(theme::uiFont(30, true));
    v->addWidget(title);

    QLabel *sub = theme::dim(
        QStringLiteral("This machine has no network interfaces and no shell. "
                       "Nothing you do here can be reached from anywhere else."),
        column);
    sub->setAlignment(Qt::AlignCenter);
    v->addWidget(sub);

    v->addSpacing(theme::px(14));

    // --- the three choices ------------------------------------------------
    //
    // Import is its own card rather than a branch inside "Create a wallet".
    // They are different intentions - one mints a seed that did not exist, the
    // other describes one that already does - and putting the second inside the
    // first is how somebody ends up generating a wallet they did not want while
    // looking for the one they have.
    auto *choices = new QHBoxLayout;
    choices->setSpacing(theme::px(18));

    QPushButton *create = choice(
        QStringLiteral("Create a wallet"),
        QStringLiteral("Generate a brand new seed on this machine"),
        QStringLiteral("Writes only a watch-only file. The recovery words are "
                       "shown once, are never saved anywhere, and cannot be "
                       "recovered - you must write them down."),
        theme::accentCool(), column);
    connect(create, &QPushButton::clicked, app_, &AppWindow::showCreate);
    choices->addWidget(create, 1);

    signBtn_ = choice(
        QStringLiteral("Sign a transaction"),
        QStringLiteral("Review and sign a PSBT from the USB stick"),
        QStringLiteral("Reads a .psbt file, shows you exactly what it pays and "
                       "to whom, and signs it only after you have confirmed. "
                       "Your key is wiped immediately afterwards."),
        theme::accent(), column);
    connect(signBtn_, &QPushButton::clicked, app_, &AppWindow::showScan);
    choices->addWidget(signBtn_, 1);

    QPushButton *importBtn = choice(
        QStringLiteral("Export watch-only keys"),
        QStringLiteral("You already have recovery words"),
        QStringLiteral("Type them in and this writes the same watch-only file, "
                       "so a coordinator can build transactions for a wallet "
                       "this machine did not create. Nothing private is "
                       "written, and the words are wiped on the way out."),
        theme::accentCool(), column);
    connect(importBtn, &QPushButton::clicked, app_, &AppWindow::showImport);
    choices->addWidget(importBtn, 1);

    v->addLayout(choices);

    dataHint_ = theme::dim(QString(), column);
    dataHint_->setAlignment(Qt::AlignCenter);
    dataHint_->setWordWrap(true);
    v->addWidget(dataHint_);

    v->addStretch(3);

    // A wide screen would otherwise stretch these cards into billboards. Wider
    // than it was for two of them, because a third column of the same prose in
    // a 980px row leaves each card too narrow to read.
    outer->addWidget(theme::centeredColumn(column, theme::px(1180), this), 1);

    // --- the way out ------------------------------------------------------
    auto *bottom = new QHBoxLayout;
    bottom->addStretch(1);
    QPushButton *shutdown = theme::secondaryButton(QStringLiteral("Shut down"), this);
    connect(shutdown, &QPushButton::clicked, app_, &AppWindow::showShutdown);
    bottom->addWidget(shutdown);
    bottom->addStretch(1);
    outer->addLayout(bottom);

    connect(app_, &AppWindow::dataStatusChanged, this,
            [this](bool) { refreshDataHint(); });
}

QPushButton *HomeScreen::choice(const QString &title, const QString &subtitle,
                                const QString &note, const char *accentColour,
                                QWidget *parent)
{
    // A QPushButton rather than a clickable frame: it gets keyboard focus, the
    // Enter and Space activation, and the focus ring, all of which this screen
    // needs on a machine with no pointer. The text lives in child labels
    // because a button's own label cannot mix three sizes.
    auto *b = new QPushButton(parent);
    b->setProperty("role", QStringLiteral("choice"));
    b->setMinimumHeight(theme::px(210));
    b->setFocusPolicy(Qt::StrongFocus);
    if (!theme::cursorVisible())
        b->setCursor(Qt::BlankCursor);

    auto *v = new QVBoxLayout(b);
    v->setContentsMargins(theme::px(22), theme::px(20), theme::px(22), theme::px(20));
    v->setSpacing(theme::px(8));

    auto *t = new QLabel(title, b);
    t->setFont(theme::uiFont(24, true));
    t->setStyleSheet(QStringLiteral("color: %1; background: transparent;")
                         .arg(QString::fromLatin1(accentColour)));
    v->addWidget(t);

    auto *s = new QLabel(subtitle, b);
    s->setFont(theme::uiFont(16));
    s->setWordWrap(true);
    s->setStyleSheet(QStringLiteral("background: transparent;"));
    v->addWidget(s);

    v->addStretch(1);

    auto *n = new QLabel(note, b);
    n->setFont(theme::uiFont(13));
    n->setWordWrap(true);
    n->setStyleSheet(QStringLiteral("color: %1; background: transparent;")
                         .arg(QString::fromLatin1(theme::textDim())));
    v->addWidget(n);

    // The labels must not swallow the click: every pixel of the card is the
    // button.
    for (QLabel *l : b->findChildren<QLabel *>())
        l->setAttribute(Qt::WA_TransparentForMouseEvents, true);

    return b;
}

void HomeScreen::onEnter()
{
    refreshDataHint();
    // Signing is the common case, so it starts focused: on a keyboard-driven
    // machine that makes the routine path Enter, and the irreversible one a
    // deliberate move sideways.
    signBtn_->setFocus();
}

void HomeScreen::refreshDataHint()
{
    if (app_->dataMounted()) {
        dataHint_->setStyleSheet(QStringLiteral("color: %1;")
                                     .arg(QString::fromLatin1(theme::textDim())));
        dataHint_->setText(
            QStringLiteral("The %1 partition is mounted. Signed transactions and "
                           "watch-only exports are written there.")
                .arg(app_->config().dataLabel));
    } else {
        dataHint_->setStyleSheet(QStringLiteral("color: %1;")
                                     .arg(QString::fromLatin1(theme::warn())));
        dataHint_->setText(
            QStringLiteral("No %1 partition is mounted yet. You can still create a "
                           "wallet - you will be asked to insert the stick before "
                           "the watch-only file is written. Signing needs it too.")
                .arg(app_->config().dataLabel));
    }
}

} // namespace signeros
