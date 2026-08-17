// SPDX-License-Identifier: MIT
//
// Screen 4 - secure shutdown.
//
// The button does not power the machine off directly: this process is
// unprivileged and cannot. It exits with status 42, and the root-owned session
// supervisor turns that into /usr/sbin/secure-poweroff, which walks the normal
// shutdown path - kiosk stopped, data partition flushed and unmounted, free
// memory scrubbed, then poweroff.

#pragma once

#include <QWidget>

class QLabel;

namespace signeros {

class AppWindow;

class ShutdownScreen : public QWidget {
    Q_OBJECT

public:
    explicit ShutdownScreen(AppWindow *app, QWidget *parent = nullptr);

    void onEnter();

private:
    AppWindow *app_ = nullptr;
    QLabel *state_ = nullptr;
    QLabel *buildInfo_ = nullptr;
};

} // namespace signeros
