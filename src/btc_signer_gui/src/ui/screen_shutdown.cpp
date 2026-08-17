// SPDX-License-Identifier: MIT

#include "ui/screen_shutdown.h"

#include <QFile>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QVBoxLayout>

#include "core/psbt_engine.h"
#include "core/secure_memory.h"
#include "ui/app_window.h"
#include "ui/theme.h"

namespace signeros {

ShutdownScreen::ShutdownScreen(AppWindow *app, QWidget *parent)
    : QWidget(parent), app_(app)
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(40, 30, 40, 30);
    v->setSpacing(14);

    v->addStretch(1);

    QLabel *h = theme::heading(QStringLiteral("Secure shutdown"), this);
    h->setAlignment(Qt::AlignCenter);
    h->setFont(theme::uiFont(28, true));
    v->addWidget(h);

    QLabel *body = theme::body(
        QStringLiteral(
            "Powering off will:\n\n"
            "  1.  wipe the mnemonic, seed and any derived private key from RAM\n"
            "  2.  flush and unmount the data partition, so a signed PSBT written\n"
            "      just now is safely on the stick\n"
            "  3.  overwrite free memory, then switch the machine off\n\n"
            "Wait for the machine to power down before removing the USB stick."),
        this);
    body->setAlignment(Qt::AlignCenter);
    body->setFont(theme::uiFont(17));
    v->addWidget(body);

    state_ = new QLabel(this);
    state_->setAlignment(Qt::AlignCenter);
    state_->setFont(theme::uiFont(15, true));
    state_->setWordWrap(true);
    v->addWidget(state_);

    v->addStretch(1);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(16);
    buttons->addStretch(1);

    QPushButton *cancel = theme::secondaryButton(QStringLiteral("Cancel"), this);
    cancel->setMinimumWidth(200);
    connect(cancel, &QPushButton::clicked, app_, &AppWindow::showHome);
    buttons->addWidget(cancel);

    QPushButton *off = theme::dangerButton(
        QStringLiteral("Secure Shutdown && Power Off"), this);
    off->setMinimumWidth(360);
    off->setMinimumHeight(80);
    off->setFont(theme::uiFont(20, true));
    connect(off, &QPushButton::clicked, app_, &AppWindow::requestPoweroff);
    buttons->addWidget(off);

    buttons->addStretch(1);
    v->addLayout(buttons);

    // Build identity, so an operator can tell two sticks apart and confirm they
    // are running the image they audited.
    buildInfo_ = theme::dim(QString(), this);
    buildInfo_->setAlignment(Qt::AlignCenter);
    v->addWidget(buildInfo_);
}

void ShutdownScreen::onEnter()
{
    const bool keyResident = app_->engine().hasKey();
    state_->setStyleSheet(QStringLiteral("color: %1;")
                              .arg(keyResident ? theme::warn() : theme::ok()));
    state_->setText(keyResident
        ? QStringLiteral("A signing key is still loaded in memory. It will be wiped "
                         "on shutdown, or immediately if you cancel and go back.")
        : QStringLiteral("No key material is currently loaded."));

    QString build = QStringLiteral("SignerOS " SIGNEROS_VERSION_STR
                                   "  -  libwally-core %1  -  network %2  -  pages locked: %3")
                        .arg(QString::fromStdString(PsbtEngine::libraryVersion()),
                             QString::fromLatin1(networkName(app_->config().network)),
                             allPagesLocked() ? QStringLiteral("yes")
                                              : QStringLiteral("NO"));

    QFile stamp(QStringLiteral("/etc/signeros-build"));
    if (stamp.open(QIODevice::ReadOnly | QIODevice::Text)) {
        const QString contents = QString::fromLatin1(stamp.readAll()).trimmed();
        stamp.close();
        if (!contents.isEmpty())
            build += QStringLiteral("\n") + contents.split(QLatin1Char('\n')).join(QStringLiteral("  "));
    }
    buildInfo_->setText(build);
}

} // namespace signeros
