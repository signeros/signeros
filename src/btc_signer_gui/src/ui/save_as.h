// SPDX-License-Identifier: MIT
//
// save_as.h - the page that names a file before it is written.
//
// Every artefact this machine produces used to be named for the operator, from
// a timestamp, at the moment of writing: signed_20260811-190438.psbt. That is a
// fine default and a poor name. A stick that comes back from a week of use
// holds six of them and nothing says which transaction or which wallet any of
// them is, and the operator - who is the only person who knows - was never
// asked.
//
// So both writers now take the name from here. The default is still offered,
// already free of collisions, and pressing Enter accepts it: nobody who does
// not care has to do anything. The step costs one keypress and buys a file
// somebody can recognise a month later.
//
// The field is drawn by hand, like every other entry field on this machine,
// and the screen that owns this page feeds it keystrokes. It was a QLineEdit
// first, on the grounds that a file name is not a secret and a real text field
// is what one should look like. It could not be made to work: on this platform
// the field consumed Return without emitting returnPressed() and without
// letting the key propagate, and replacing it with a hand-drawn field that read
// the keyboard itself only moved the problem - letters arrived, Return did not.
// What works everywhere else in this application is the screen above the stack
// holding the focus, so that is what this page does too. See handleKey().
//
// One thing it does differently from the secret fields: it reads
// QKeyEvent::text(), because a file name has dots and dashes in it and no
// reason to be typed through a US keymap. The buffers that hold key material
// still read key() only.

#pragma once

#include <QString>
#include <QWidget>

class QKeyEvent;
class QLabel;
class QPushButton;
class QTimer;

namespace signeros {


class SaveAsPage : public QWidget {
    Q_OBJECT

public:
    explicit SaveAsPage(QWidget *parent = nullptr);

    // Called every time the page is shown, because every one of these changes:
    // the proposed name carries a fresh timestamp, and `subtitle` restates what
    // is about to be written in the words of the screen that is writing it.
    void begin(const QString &heading,
               const QString &subtitle,
               const QString &proposedName,
               const QString &directory,
               const QString &confirmLabel,
               bool showOnScreenKeyboard);

    // What the operator left in the field, trimmed. May be empty; the writers
    // treat that as "use the default" rather than as an error.
    QString fileName() const;

    // A refusal from the writer - the name is taken, the stick is gone. Shown
    // under the field, where the name that caused it still is.
    void setError(const QString &text);

    // Accept the name currently in the field, if it is usable.
    void accept();

    // Every key this page acts on, handed to it by the screen that owns it.
    // Returns true if it was used.
    //
    // This page does not hold the keyboard focus and must not: on this platform
    // a key event reaches a widget inside a QStackedWidget only sometimes -
    // letters arrive, Return does not, which was traced with the screen and the
    // page each reporting what they saw. What does work, everywhere in this
    // application, is the screen above the stack keeping the focus and routing
    // keystrokes by hand. So this page is driven the same way as every entry
    // screen: the screen calls this.
    bool handleKey(QKeyEvent *event);

    // The on-screen keyboard's output. It belongs to the screen (one floating
    // panel per screen, ui/osk_panel.h), so the screen hands the characters on
    // exactly as it hands on the physical ones.
    void typeCharacter(char c);
    void backspace();
    void clearName();

    // Keeps the page's own toggle in step with the screen's panel.
    void setKeyboardShown(bool shown);

signals:
    void back();
    void accepted();
    // "show me the keys" - the panel belongs to the screen, so the screen acts
    // on this. Every page that takes typing carries the button; F2 alone is not
    // discoverable.
    void keyboardRequested(bool on);

protected:
    void showEvent(QShowEvent *event) override;
    void hideEvent(QHideEvent *event) override;

private:
    void refresh();

    QLabel *heading_ = nullptr;
    QLabel *subtitle_ = nullptr;
    QLabel *dirLabel_ = nullptr;
    QLabel *error_ = nullptr;
    QLabel *hint_ = nullptr;
    QLabel *nameLabel_ = nullptr;
    QPushButton *acceptBtn_ = nullptr;
    QPushButton *clearBtn_ = nullptr;
    QPushButton *oskToggle_ = nullptr;

    // The name being edited, and the caret blinking at the end of it. Not a
    // secret: a QString is the right place for it, unlike everything the entry
    // screens hold.
    QString name_;
    QTimer *caretTimer_ = nullptr;
    bool caretOn_ = true;
};

} // namespace signeros
