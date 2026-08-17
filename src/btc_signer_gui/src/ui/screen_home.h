// SPDX-License-Identifier: MIT
//
// screen_home.h - the fork in the road: create a wallet, or sign a transaction.
//
// Two choices and nothing else. This device does exactly two things, and the
// screen that offers them should not imply otherwise by surrounding them with
// settings, menus or status widgets that lead nowhere.
//
// Each choice states its consequence underneath it, because these two are not
// symmetrical: signing is routine and reversible up to the moment you press the
// last button, while creating a wallet produces twelve or twenty-four words
// that exist nowhere else in the universe and that nobody - not us, not the
// machine - can ever recover for you. An operator should learn that here, not
// three screens in.

#pragma once

#include <QWidget>

class QLabel;
class QPushButton;

namespace signeros {

class AppWindow;

class HomeScreen : public QWidget {
    Q_OBJECT

public:
    explicit HomeScreen(AppWindow *app, QWidget *parent = nullptr);

    void onEnter();

private:
    // A large two-line choice card. Returns the button so the caller can wire
    // it up; the layout inside it is fixed.
    QPushButton *choice(const QString &title, const QString &subtitle,
                        const QString &note, const char *accentColour,
                        QWidget *parent);

    void refreshDataHint();

    AppWindow *app_ = nullptr;
    QLabel *dataHint_ = nullptr;
    QPushButton *signBtn_ = nullptr;
};

} // namespace signeros
