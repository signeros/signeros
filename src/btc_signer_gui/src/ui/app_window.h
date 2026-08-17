// SPDX-License-Identifier: MIT
//
// app_window.h - the kiosk shell: a borderless full-screen window holding a
// persistent status bar and one screen at a time.
//
// Navigation is explicit and shallow:
//
//     splash -> home -+-> create (a wizard, linear inside itself)
//                     |
//                     +-> import (existing words -> watch-only export)
//                     |
//                     +-> scan -> inspect -> sign
//
// with shutdown reachable from anywhere. There is nothing else: no menus, no
// settings, no way to reach a shell.
//
// The splash is the first screen rather than an overlay, so that the three
// seconds it holds are three seconds in which nothing else exists - no
// half-drawn file list behind it, no key material anywhere in the process.

#pragma once

#include <QString>
#include <QWidget>

#include "core/psbt_engine.h"

class QLabel;
class QStackedWidget;
class QTimer;

namespace signeros {

struct AppConfig {
    Network network = Network::Mainnet;
    QString dataDir = QStringLiteral("/mnt/data");
    QString dataLabel = QStringLiteral("PSBT_DATA");
    bool writeFinalTx = false;

    // Whether a physical keyboard was found at startup. The sign screen shows
    // its on-screen keyboard only when there is none.
    bool physicalKeyboard = false;
};

class SaveAsPage;
class SplashScreen;
class HomeScreen;
class ScanScreen;
class InspectScreen;
class SignScreen;
class CreateScreen;
class ImportScreen;
class ShutdownScreen;

class AppWindow : public QWidget {
    Q_OBJECT

public:
    // Exit status the kiosk uses to ask the root-owned session supervisor for a
    // secure poweroff. The unprivileged GUI cannot call reboot(2), and this one
    // integer is the entire privileged interface it has. See signer-session.
    static constexpr int kExitPoweroffRequested = 42;

    explicit AppWindow(const AppConfig &config, QWidget *parent = nullptr);
    ~AppWindow() override;

    const AppConfig &config() const { return config_; }
    PsbtEngine &engine() { return engine_; }

    bool dataMounted() const { return dataMounted_; }

    void showHome();
    void showScan();
    void showInspect();
    void showSign();
    void showCreate();
    void showImport();
    void showShutdown();

    // Called by ShutdownScreen. Wipes key material, then exits with
    // kExitPoweroffRequested.
    void requestPoweroff();

signals:
    void dataStatusChanged(bool mounted);

protected:
    void keyPressEvent(QKeyEvent *event) override;
    // Catches Enter on a save-as page; see the definition.
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    // The save-as page of whichever screen is showing, or nullptr.
    SaveAsPage *activeSaveAsPage() const;

    void buildUi();
    void pollDataMount();
    void pollWarning();
    void updateStatusBar();
    void setStatusBarVisible(bool visible);
    // Tells whatever screen is on its way out to clean up, and restores the
    // status bar the splash hides. Every show*() begins with this.
    void leaveCurrent();

    AppConfig config_;
    PsbtEngine engine_;

    QStackedWidget *stack_ = nullptr;
    QWidget *statusBar_ = nullptr;
    QLabel *statusLeft_ = nullptr;
    QLabel *statusRight_ = nullptr;
    QWidget *statusRule_ = nullptr;
    QLabel *warnBanner_ = nullptr;
    QString warnText_;
    QTimer *mountPoll_ = nullptr;

    SplashScreen *splash_ = nullptr;
    HomeScreen *home_ = nullptr;
    ScanScreen *scan_ = nullptr;
    InspectScreen *inspect_ = nullptr;
    SignScreen *sign_ = nullptr;
    CreateScreen *create_ = nullptr;
    ImportScreen *import_ = nullptr;
    ShutdownScreen *shutdown_ = nullptr;

    bool dataMounted_ = false;
};

} // namespace signeros
