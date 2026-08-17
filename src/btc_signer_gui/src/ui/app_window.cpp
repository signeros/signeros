// SPDX-License-Identifier: MIT

#include "ui/app_window.h"

#include <QApplication>
#include <QFile>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QScreen>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <sys/stat.h>

#include "ui/screen_create.h"
#include "ui/screen_home.h"
#include "ui/screen_import.h"
#include "ui/screen_inspect.h"
#include "ui/screen_scan.h"
#include "ui/screen_shutdown.h"
#include "ui/screen_sign.h"
#include "ui/screen_splash.h"
#include "ui/secret_buffers.h"
#include "ui/theme.h"

namespace signeros {

AppWindow::AppWindow(const AppConfig &config, QWidget *parent)
    : QWidget(parent), config_(config), engine_(config.network)
{
    setWindowTitle(QStringLiteral("SignerOS"));
    // See eventFilter(): one key, on the save-as pages, has to be caught
    // before Qt decides not to deliver it.
    qApp->installEventFilter(this);
    // No window manager exists to decorate this, but say so explicitly so the
    // same binary behaves the same way if it is ever run under one for
    // development.
    setWindowFlags(Qt::Window | Qt::FramelessWindowHint);
    if (!theme::cursorVisible())
        setCursor(Qt::BlankCursor);

    // Nothing gets to make this window bigger than the panel.
    //
    // showFullScreen() is not the last word on that: a widget whose content
    // cannot be wrapped raises the minimum width of the layout holding it, a
    // QStackedWidget takes the widest minimum of every page it holds, and the
    // minimum propagates all the way up here - at which point Qt makes the
    // window that wide and the buttons in the bottom right of *every* screen
    // sit past the edge of a display with no window manager to scroll them
    // back. A revealed 160-character passphrase is what found this.
    //
    // Capping the window turns that class of mistake into a clipped label:
    // local, visible, and confined to the screen that caused it.
    if (const QScreen *screen = QApplication::primaryScreen())
        setMaximumSize(screen->geometry().size());

    buildUi();

    // The data partition can appear or vanish at any moment: the operator may
    // plug the stick in after boot, or pull it out mid-session. Polling
    // /proc/mounts is how the UI stays honest about it without needing udev,
    // which cannot exist on a kernel with no network stack.
    mountPoll_ = new QTimer(this);
    mountPoll_->setInterval(1000);
    connect(mountPoll_, &QTimer::timeout, this, &AppWindow::pollDataMount);
    // Same tick carries anything the init scripts want said. They have no other
    // way to reach the operator once this window is up.
    connect(mountPoll_, &QTimer::timeout, this, &AppWindow::pollWarning);
    mountPoll_->start();
    pollDataMount();
    pollWarning();

    // Three seconds of splash, then the two choices. Deliberately the first
    // thing constructed and shown: no file has been read, no key can exist, and
    // the machine has nothing to say yet except what it is.
    stack_->setCurrentWidget(splash_);
    setStatusBarVisible(false);
    splash_->onEnter();
}

AppWindow::~AppWindow()
{
    // Whatever route we leave by, no key material survives it.
    engine_.clearKey();
    engine_.unload();
    wipeAllSecrets();
}

void AppWindow::buildUi()
{
    auto *root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // This is what makes the size cap in the constructor mean anything.
    //
    // A top-level widget's layout defaults to SetDefaultConstraint, which calls
    // setMinimumSize(totalMinimumSize()) on the window - and a minimum beats a
    // maximum when the two disagree, so a single widget that cannot be made
    // narrow drags the whole window past the edge of the panel and setMaximumSize
    // does not stop it. Found the honest way: a screen was added, the window
    // grew to about 1576 pixels on a 1280 pixel display, and every button in
    // the bottom right went over the side.
    //
    // With no constraint the layout stops reporting its minimum upwards. The
    // window is then the size of the screen, always, and a widget that does not
    // fit is clipped inside it - which is a visible, local defect on the screen
    // that caused it rather than an invisible, global one on all of them.
    root->setSizeConstraint(QLayout::SetNoConstraint);

    // --- status bar ------------------------------------------------------
    statusBar_ = new QWidget(this);
    statusBar_->setStyleSheet(QStringLiteral("background: %1;").arg(theme::panel()));
    auto *barLayout = new QHBoxLayout(statusBar_);
    barLayout->setContentsMargins(theme::px(18), theme::px(8), theme::px(18), theme::px(8));

    statusLeft_ = new QLabel(statusBar_);
    statusLeft_->setFont(theme::uiFont(15, true));
    barLayout->addWidget(statusLeft_);
    barLayout->addStretch(1);

    statusRight_ = new QLabel(statusBar_);
    statusRight_->setFont(theme::monoFont(14));
    barLayout->addWidget(statusRight_);

    root->addWidget(statusBar_);
    statusRule_ = theme::hLine(this);
    root->addWidget(statusRule_);

    // --- warning banner --------------------------------------------------
    //
    // Raised by the init scripts through /run/signeros-warning (see
    // usr/lib/signeros/functions.sh). Hidden unless there is something to say.
    //
    // This is where a message from outside the GUI belongs. The scripts used to
    // write straight to /dev/tty1, which works only until Qt takes the
    // framebuffer - after that it paints console text over whatever transaction
    // is on screen, which is both unreadable and alarming.
    warnBanner_ = new QLabel(this);
    warnBanner_->setFont(theme::uiFont(15, true));
    warnBanner_->setWordWrap(true);
    warnBanner_->setContentsMargins(18, 8, 18, 8);
    warnBanner_->setStyleSheet(QStringLiteral("background: %1; color: %2;")
                                   .arg(QString::fromLatin1(theme::panelAlt()),
                                        QString::fromLatin1(theme::warn())));
    warnBanner_->hide();
    root->addWidget(warnBanner_);

    // --- screens ---------------------------------------------------------
    stack_ = new QStackedWidget(this);
    splash_ = new SplashScreen(this);
    home_ = new HomeScreen(this);
    scan_ = new ScanScreen(this);
    inspect_ = new InspectScreen(this);
    sign_ = new SignScreen(this);
    create_ = new CreateScreen(this);
    import_ = new ImportScreen(this);
    shutdown_ = new ShutdownScreen(this);

    stack_->addWidget(splash_);
    stack_->addWidget(home_);
    stack_->addWidget(scan_);
    stack_->addWidget(inspect_);
    stack_->addWidget(sign_);
    stack_->addWidget(create_);
    stack_->addWidget(import_);
    stack_->addWidget(shutdown_);

    root->addWidget(stack_, 1);

    updateStatusBar();
}

// The splash owns the whole panel: a status bar over the top of it would be the
// one piece of ordinary application furniture on a screen whose entire job is
// to be the machine introducing itself.
void AppWindow::setStatusBarVisible(bool visible)
{
    statusBar_->setVisible(visible);
    statusRule_->setVisible(visible);
}

// Everything that leaves one screen for another goes through here, so there is
// exactly one place that has to remember to tell the screen being left to clean
// up after itself. Forgetting that on a device holding a seed is not a
// cosmetic bug.
void AppWindow::leaveCurrent()
{
    QWidget *current = stack_->currentWidget();
    if (current == splash_)
        splash_->onLeave();
    else if (current == scan_)
        scan_->onLeave();
    else if (current == sign_)
        sign_->onLeave();
    else if (current == create_)
        create_->onLeave();
    else if (current == import_)
        import_->onLeave();

    setStatusBarVisible(true);
}

void AppWindow::updateStatusBar()
{
    const bool mainnet = (config_.network == Network::Mainnet);
    statusLeft_->setText(
        QStringLiteral("SignerOS  -  air-gapped PSBT signer  -  <span style='color:%1'>%2</span>")
            .arg(QString::fromLatin1(mainnet ? theme::accent() : theme::warn()),
                 QString::fromLatin1(networkName(config_.network)).toUpper()));

    statusRight_->setText(
        QStringLiteral("<span style='color:%1'>%2</span>   no network interfaces")
            .arg(QString::fromLatin1(dataMounted_ ? theme::ok() : theme::danger()),
                 dataMounted_
                     ? QStringLiteral("%1 mounted").arg(config_.dataLabel)
                     : QStringLiteral("%1 missing").arg(config_.dataLabel)));
}

void AppWindow::pollDataMount()
{
    bool mounted = false;

    QFile mounts(QStringLiteral("/proc/mounts"));
    if (mounts.open(QIODevice::ReadOnly | QIODevice::Text)) {
        const QByteArray all = mounts.readAll();
        mounts.close();
        const QByteArray needle = QStringLiteral(" %1 ").arg(config_.dataDir).toUtf8();
        mounted = all.contains(needle);
    }

    // A mount entry is necessary but not sufficient: a stick pulled without
    // unmounting leaves the entry behind while every access returns EIO. Stat
    // the directory to be sure it is really usable.
    if (mounted) {
        struct stat st {};
        if (::stat(config_.dataDir.toLocal8Bit().constData(), &st) != 0 ||
            !S_ISDIR(st.st_mode))
            mounted = false;
    }

    if (mounted == dataMounted_)
        return;

    dataMounted_ = mounted;
    updateStatusBar();
    emit dataStatusChanged(dataMounted_);
}

void AppWindow::pollWarning()
{
    // Absent file means nothing is wrong, which is the normal case: the read is
    // one openat(2) per second on a tmpfs and never touches the data partition.
    QString text;
    QFile f(QStringLiteral("/run/signeros-warning"));
    if (f.open(QIODevice::ReadOnly | QIODevice::Text)) {
        text = QString::fromUtf8(f.readAll()).trimmed();
        f.close();
    }

    if (text == warnText_)
        return;

    warnText_ = text;
    warnBanner_->setText(text);
    warnBanner_->setVisible(!text.isEmpty());
}

// ---------------------------------------------------------------------------

void AppWindow::showHome()
{
    // The junction between the two things this device does, and therefore the
    // point at which nothing from either of them may still be resident: no
    // PSBT, no key, no seed, no passphrase.
    leaveCurrent();
    engine_.clearKey();
    engine_.unload();
    wipeAllSecrets();

    stack_->setCurrentWidget(home_);
    home_->onEnter();
}

void AppWindow::showScan()
{
    // Leaving the sign screen by any route wipes what was typed there.
    leaveCurrent();
    sign_->onLeave();
    engine_.unload();

    stack_->setCurrentWidget(scan_);
    scan_->onEnter();
}

void AppWindow::showInspect()
{
    leaveCurrent();
    stack_->setCurrentWidget(inspect_);
    inspect_->onEnter();
}

void AppWindow::showSign()
{
    leaveCurrent();
    stack_->setCurrentWidget(sign_);
    sign_->onEnter();
}

void AppWindow::showCreate()
{
    // Creating a wallet takes over the single process-wide master key slot, so
    // any loaded PSBT and any signing key go first.
    leaveCurrent();
    engine_.clearKey();
    engine_.unload();

    stack_->setCurrentWidget(create_);
    create_->onEnter();
}

void AppWindow::showImport()
{
    // Same reason as showCreate(): buildWalletExport() derives into the single
    // process-wide master key slot, so nothing else may be holding it.
    leaveCurrent();
    engine_.clearKey();
    engine_.unload();

    stack_->setCurrentWidget(import_);
    import_->onEnter();
}

void AppWindow::showShutdown()
{
    leaveCurrent();
    stack_->setCurrentWidget(shutdown_);
    shutdown_->onEnter();
}

void AppWindow::requestPoweroff()
{
    // Wipe first, exit second. If anything goes wrong between here and the
    // machine actually powering down, there is nothing left in this process to
    // find.
    engine_.clearKey();
    engine_.unload();
    sign_->onLeave();
    create_->onLeave();
    wipeAllSecrets();

    qApp->exit(kExitPoweroffRequested);
}

// Enter, on the two pages where nothing else can answer it.
//
// A save-as page (ui/save_as.h) lives inside the owning screen's QStackedWidget.
// On this platform a Return pressed while one of those is showing is delivered
// by QApplication to the screen - an application-wide filter sees it arrive
// there, with the screen enabled, visible and holding the focus - and
// QWidget::event() then does not call keyPressEvent() for it. Letters, digits
// and function keys on the very same page do arrive. That was traced with the
// screen and the page each reporting what they saw; no widget of ours consumes
// it, and there are no shortcuts in this application.
//
// So the one key this affects is answered where it demonstrably does arrive:
// here, before delivery. Everything else is left alone. Consuming the event
// (returning true) is what keeps this from also firing through the screen's own
// handler on a platform where the key does get through.
bool AppWindow::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::KeyPress) {
        const int k = static_cast<QKeyEvent *>(event)->key();
        if (k == Qt::Key_Return || k == Qt::Key_Enter) {
            if (SaveAsPage *page = activeSaveAsPage()) {
                page->accept();
                return true;
            }
        }
    }
    return QWidget::eventFilter(watched, event);
}

SaveAsPage *AppWindow::activeSaveAsPage() const
{
    QWidget *screen = stack_->currentWidget();
    if (screen == sign_)
        return sign_->activeSaveAsPage();
    if (screen == import_)
        return import_->activeSaveAsPage();
    if (screen == create_)
        return create_->activeSaveAsPage();
    return nullptr;
}

void AppWindow::keyPressEvent(QKeyEvent *event)
{
    // There is no way out of the kiosk: Escape, Alt-F4 and friends do nothing.
    // Shutting the machine down is a deliberate act on the shutdown screen.
    switch (event->key()) {
    case Qt::Key_Escape:
        // Escape now means "back to the start", not "back to the file list":
        // there are two flows to come back from, and the file list is only the
        // beginning of one of them. Wallet creation deliberately does not
        // answer to it - see below.
        if (stack_->currentWidget() == create_) {
            // A single stray keypress must not throw away a seed the operator
            // is halfway through writing down. Leaving the wizard is a button
            // on the screen, which says what it discards.
            return;
        }
        if (stack_->currentWidget() != home_ && stack_->currentWidget() != splash_)
            showHome();
        return;
    case Qt::Key_F12:
        showShutdown();
        return;
    default:
        break;
    }
    QWidget::keyPressEvent(event);
}

} // namespace signeros
