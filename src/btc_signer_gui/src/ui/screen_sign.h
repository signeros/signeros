// SPDX-License-Identifier: MIT
//
// Screen 3 - enter the key and sign.
//
// Memory discipline on this screen is the whole point:
//
//   * The mnemonic, the passphrase and its confirmation live in the shared
//     SecureStrings of ui/secret_buffers.h - fixed capacity, page-locked,
//     wiped. There is exactly one of each in the process.
//   * Nothing ever assembles them into a QString. Keystrokes - from the
//     on-screen keyboard or a physical one - are appended character by
//     character, and the display shows dots plus the word currently being
//     typed.
//   * They are wiped the moment signing finishes, before the result appears,
//     and again whenever this screen is left.
//
// The flow is deliberately three-step: "Check key" derives the master and
// reports its fingerprint and how many inputs it covers; that also verifies
// which outputs are genuinely change coming back to this wallet, which is
// knowable only once a key exists. "Review and sign" then shows the
// confirmation page - the same transaction restated in verified terms, so the
// last thing seen before an irreversible act is what is actually leaving the
// wallet rather than what the file claimed. Only that page signs.
//
// Signing and writing are two steps, in that order: the signature is made, the
// secrets are wiped on the spot, and only then does the save-as page ask what
// the file should be called. So the naming step holds no key material at all,
// and a write that fails - a name already used, a stick pulled out - can be
// retried from that page without the mnemonic having to be entered again.

#pragma once

#include <QString>
#include <QWidget>

#include <cstddef>

#include "ui/osk_panel.h"
#include "ui/save_as.h"

class QFrame;
class QLabel;
class QPushButton;
class QScrollArea;
class QStackedWidget;
class QTimer;
class QVBoxLayout;

namespace signeros {

class AppWindow;
class SecureString;

class SignScreen : public QWidget {
    Q_OBJECT

public:
    explicit SignScreen(AppWindow *app, QWidget *parent = nullptr);
    ~SignScreen() override;

    void onEnter();
    void onLeave();

    // The save-as page, when it is the one showing. AppWindow asks, because
    // Enter has to be answered from its application-wide event filter - see
    // AppWindow::eventFilter for the reason.
    SaveAsPage *activeSaveAsPage() const;

protected:
    void keyPressEvent(QKeyEvent *event) override;
    // Keeps the floating keyboard across the bottom of the screen.
    void resizeEvent(QResizeEvent *event) override;
    // Clicking either entry card puts the keystrokes there. Installed on the
    // two frames rather than handled by a subclass so the cards stay plain
    // theme::card()s.
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    // The passphrase is typed twice. It is the one secret on this machine that
    // nothing can check - any bytes are a legal passphrase, so a slip produces
    // a different, valid, empty wallet rather than an error - and a second
    // entry is the only check that exists for it.
    enum class Field { Mnemonic, Passphrase, Confirm };
    enum class KeySource { Mnemonic, Xprv };

    // Pages of pages_, in the order they are added.
    enum Page { kEntryPage = 0, kConfirmPage = 1, kNamePage = 2, kResultPage = 3 };

    QWidget *buildEntryPage();
    QWidget *buildConfirmPage();
    QWidget *buildResultPage();

    void typeCharacter(char c);
    void backspace();
    void deleteWord();
    void clearAll();

    // The buffer the current field types into. One place decides.
    SecureString &activeBuffer();

    void setField(Field f);
    void setKeySource(KeySource s);
    void setOskVisible(bool visible);
    void refreshPaying();
    void refreshReminder();
    void refreshDisplays();
    void refreshSuggestions();
    void applySuggestion(int index);

    // Which card is lit, what its caption says, and where the caret is drawn.
    void refreshFieldChrome();
    void applyCaret();
    // What the floating keyboard shows above its keys.
    void refreshEcho();

    void checkKey();
    void showConfirm();
    void rebuildConfirm();
    void doSign();
    void doWrite();
    void wipeSecrets();
    void showError(const QString &text);

    // True when the passphrase is in a state that may be derived from: empty,
    // or typed twice identically. Puts the reason on screen otherwise.
    bool passphraseReady();

    AppWindow *app_ = nullptr;

    QStackedWidget *pages_ = nullptr;
    // Floats over the pages rather than sitting in one. See ui/osk_panel.h.
    OskPanel *osk_ = nullptr;

    QLabel *reminder_ = nullptr;
    QLabel *keyStatus_ = nullptr;
    QLabel *error_ = nullptr;

    // The two fields, as two cards that are both on screen at all times. They
    // replaced a single card fed by a pair of "Typing: key / Typing:
    // passphrase" toggle buttons - a tab strip in all but name, which hid the
    // passphrase behind a control you had to already know about, and said
    // nothing about which of the two your next keystroke would land in.
    QFrame *mnemonicBox_ = nullptr;
    QLabel *mnemonicCaption_ = nullptr;
    QLabel *mnemonicHint_ = nullptr;
    QLabel *mnemonicDisplay_ = nullptr;
    QLabel *mnemonicMeta_ = nullptr;

    QFrame *passphraseBox_ = nullptr;
    QLabel *passphraseCaption_ = nullptr;
    QLabel *passphraseHint_ = nullptr;
    QLabel *passphraseDisplay_ = nullptr;

    // The second entry. Exists only while there is a passphrase to confirm, so
    // an operator with no passphrase never sees a field they have no use for.
    QFrame *confirmBox_ = nullptr;
    QLabel *confirmCaption_ = nullptr;
    QLabel *confirmHint_ = nullptr;
    QLabel *confirmDisplay_ = nullptr;

    QPushButton *sourceMnemonicBtn_ = nullptr;
    QPushButton *sourceXprvBtn_ = nullptr;
    QPushButton *checkBtn_ = nullptr;
    QPushButton *signBtn_ = nullptr;
    QPushButton *oskToggle_ = nullptr;

    // What the transaction actually pays, kept on screen while the key is being
    // typed - it now keeps that space permanently, because the keyboard no
    // longer competes for it.
    QWidget *payingBox_ = nullptr;
    QLabel *payingLabel_ = nullptr;
    QLabel *hint_ = nullptr;

    static constexpr int kSuggestionCount = 5;
    QPushButton *suggestions_[kSuggestionCount] = {};

    // The confirmation page. Its contents are rebuilt from the summary every
    // time it is shown: it must never display a figure that predates the key.
    QScrollArea *confirmScroll_ = nullptr;
    QWidget *confirmContent_ = nullptr;
    QVBoxLayout *confirmLayout_ = nullptr;
    QPushButton *confirmSignBtn_ = nullptr;
    // A refusal from sign() used to be reported into the entry page's error
    // label, which is not on the screen the operator is looking at when it
    // happens - so "Sign now" appeared to do nothing at all.
    QLabel *confirmError_ = nullptr;

    // Naming the output, between signing and writing. See ui/save_as.h.
    SaveAsPage *namePage_ = nullptr;

    QLabel *resultHeading_ = nullptr;
    QLabel *resultDetail_ = nullptr;

    // Carried from doSign() to doWrite(), because by the time the file is
    // written the engine has been re-summarised and the key is gone: the inputs
    // this key just signed no longer count as signable, so asking again would
    // report a successful signing as "0 of 2".
    std::size_t signedInputs_ = 0;
    std::size_t signedTotal_ = 0;
    QString signedFingerprint_;

    Field field_ = Field::Mnemonic;
    KeySource source_ = KeySource::Mnemonic;
    bool keyChecked_ = false;

    // The blinking caret. It runs only while the entry page is showing, and it
    // is drawn into the label text rather than painted, so the two halves of
    // each display line are kept apart: `shown` is everything before the caret,
    // `suffix` everything after it (the character count on the passphrase
    // line), and applyCaret() joins them. `placeholder` says the line is a
    // prompt rather than a secret, which is the only case allowed to be rich
    // text.
    //
    // Both `shown` members can hold a fragment of a secret - the word being
    // typed, or a revealed passphrase - exactly as the QLabel they feed
    // already does. They are cleared by wipeSecrets() with the labels.
    QTimer *caretTimer_ = nullptr;
    bool caretOn_ = true;
    QString mnemonicShown_;
    QString mnemonicSuffix_;
    bool mnemonicPlaceholder_ = true;
    QString passphraseShown_;
    QString passphraseSuffix_;
    bool passphrasePlaceholder_ = true;
    QString confirmShown_;
    QString confirmSuffix_;
    bool confirmPlaceholder_ = true;

    // Set from AppConfig::physicalKeyboard on entry, toggled with F2.
    bool oskVisible_ = true;
};

} // namespace signeros
