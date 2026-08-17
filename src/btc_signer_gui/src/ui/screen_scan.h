// SPDX-License-Identifier: MIT
//
// Screen 1 - pick a file.
//
// Lists *.psbt in the data partition. Refreshes itself, because the normal way
// to use this device is to boot it, notice the stick was not seated properly,
// push it in, and expect the file to appear.

#pragma once

#include <QWidget>

class QLabel;
class QListWidget;
class QPushButton;
class QTimer;

namespace signeros {

class AppWindow;

class ScanScreen : public QWidget {
    Q_OBJECT

public:
    explicit ScanScreen(AppWindow *app, QWidget *parent = nullptr);

    void refresh();
    void onEnter();
    void onLeave();

private:
    void openSelected();
    void updateButtons();

    AppWindow *app_ = nullptr;
    QListWidget *list_ = nullptr;
    QLabel *emptyHint_ = nullptr;
    QLabel *errorLabel_ = nullptr;
    QPushButton *inspectBtn_ = nullptr;
    QTimer *autoRefresh_ = nullptr;
};

} // namespace signeros
