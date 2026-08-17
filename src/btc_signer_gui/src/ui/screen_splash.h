// SPDX-License-Identifier: MIT
//
// screen_splash.h - the three seconds before the machine asks anything.
//
// Drawn entirely with QPainter: no image files, no resources, nothing added to
// the boot payload. Every byte of the rootfs is permanently resident RAM (see
// the note about binary size in CLAUDE.md), so a 200 KB background image would
// cost 200 KB of memory forever, on a device whose whole argument is that it
// keeps nothing it does not need.
//
// It is not decoration for its own sake. The operator has just booted an
// unfamiliar machine from a USB stick and needs to know, before anything else,
// that it is the right one and that it is not talking to anybody. That is what
// this screen says, in the three seconds it takes the eye to settle.

#pragma once

#include <QElapsedTimer>
#include <QWidget>

class QTimer;

namespace signeros {

class AppWindow;

class SplashScreen : public QWidget {
    Q_OBJECT

public:
    // How long the splash holds the screen. Long enough to read the line;
    // short enough that nobody waiting to sign resents it. Any key or tap ends
    // it early - a kiosk that cannot be hurried is a kiosk people learn to
    // dread.
    static constexpr int kDurationMs = 7000;

    explicit SplashScreen(AppWindow *app, QWidget *parent = nullptr);

    void onEnter();
    void onLeave();

protected:
    void paintEvent(QPaintEvent *event) override;
    void keyPressEvent(QKeyEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;

private:
    void tick();
    void finish();

    AppWindow *app_ = nullptr;
    QTimer *timer_ = nullptr;
    QElapsedTimer clock_;
    bool done_ = false;
};

} // namespace signeros
