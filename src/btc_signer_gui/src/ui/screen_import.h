// SPDX-License-Identifier: MIT
//
// screen_import.h - the watch-only export for recovery words the operator
// already has.
//
// Why this exists as a third thing the machine does:
//
//     Signing a PSBT requires a PSBT, and building one requires a watch-only
//     wallet, and building that requires the account xpubs. Before this screen
//     the device could produce those only for a seed it had generated itself,
//     so someone arriving with an existing seed could sign transactions other
//     people's software had built for them and could never build one of their
//     own. That is a chicken-and-egg that made the device far less useful than
//     it looks, and it is closed by re-using the derivation the creation screen
//     already ends with - buildWalletExport() does not care where the mnemonic
//     came from.
//
// What is different from creating a wallet, and what that changes:
//
//     When this machine mints a seed, the export is correct by construction -
//     it derived both halves from the same bytes. Here it is handed a seed it
//     has never seen, and two mistakes are possible that creation cannot make:
//
//       * A mistyped WORD is caught. BIP39's checksum means a wrong word fails
//         validation outright (15 chances in 16 for twelve words, 255 in 256
//         for twenty-four), and psbt_engine refuses before anything is derived.
//
//       * A mistyped PASSPHRASE is not caught, and cannot be. Any bytes are a
//         legal passphrase, so the wrong ones simply produce a different, valid,
//         empty wallet. The operator imports it, sees a zero balance, and either
//         concludes their seed is broken or - far worse - receives coins at
//         addresses their real seed cannot spend from. This machine reads every
//         keyboard as US (Qt's evdev keyboard has a built-in US keymap and no
//         .qmap is shipped), which makes a wrong passphrase a routine outcome
//         rather than a careless one.
//
//     So the review page is not a formality on the way to the write, it is the
//     point of the screen: the master fingerprint and the first address of each
//     account, big, before any file exists, with the instruction to compare
//     them against the wallet the operator already has. That comparison is to
//     this flow what "type every word back" is to wallet creation - the one
//     check available to a device that cannot know the right answer by itself.
//
// The account number is selectable here and fixed at 0 when creating, for the
// same reason: a new wallet is account 0 by definition, and an existing one is
// whatever it already is. Choosing 0 for someone who is on account 1 would hand
// them a file for a wallet they do not own, which is the failure above wearing
// a different hat.
//
// Memory discipline is the signing screen's, unchanged: the words and the
// passphrase live in the shared page-locked SecureStrings (ui/secret_buffers.h),
// are never assembled into a QString, and are wiped when the export is written
// and whenever this screen is left. No private key is written, and none
// survives buildWalletExport().

#pragma once

#include <QWidget>

#include "core/wallet_export.h"
#include "ui/osk_panel.h"
#include "ui/save_as.h"

class QFrame;
class QLabel;
class QPushButton;
class QScrollArea;
class QStackedWidget;
class QVBoxLayout;

namespace signeros {

class AppWindow;
class SecureString;
class SeedView;

class ImportScreen : public QWidget {
    Q_OBJECT

public:
    explicit ImportScreen(AppWindow *app, QWidget *parent = nullptr);
    ~ImportScreen() override;

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
    // A click on a card is how a pointer chooses which field it is typing into.
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    enum Page {
        kEntryPage = 0,
        kReviewPage,
        kNamePage,
        kResultPage,
    };

    // Which secure buffer a keystroke goes into. Mirrors SignScreen::Field -
    // the same three buffers, the same rule that only one of them is being
    // typed into at a time, and the same reason for the third: a passphrase is
    // the one secret here with nothing to check it, so it is typed twice.
    enum class Field { Mnemonic, Passphrase, Confirm };

    static constexpr int kMaxAccount = 9;
    // BIP39's five legal lengths. Unlike wallet creation, this screen cannot
    // work the count out for itself - the seed belongs to somebody else and was
    // made somewhere else - so it is chosen here, and choosing it is what lets
    // the grid show every cell from before the first keystroke.
    static constexpr int kCountChoices = 5;

    QWidget *buildEntryPage();
    QWidget *buildReviewPage();
    QWidget *buildResultPage();

    void goTo(Page page);

    void setField(Field field);
    void setWordCount(int words);
    void cycleWordCount();

    // Cursor movement across the grid. Not named setCursor(): QWidget already
    // has one, and quietly shadowing the call that sets the mouse pointer is a
    // bug that compiles.
    void setWordCursor(int index);
    void moveWordCursor(int delta);

    void typeCharacter(char c);
    void backspace();
    void deleteWord();
    void clearAll();
    SecureString &activeBuffer();
    void refreshEntry();
    void refreshFieldChrome();
    // What the floating keyboard shows above its keys.
    void refreshEcho();
    void setOskVisible(bool visible);
    void refreshSuggestions();
    void applySuggestion(int index);

    // As on the signing screen: an empty passphrase is fine, one typed once
    // and not confirmed is not. Puts the reason on the screen otherwise.
    bool passphraseReady();

    // Derives the export for the words, passphrase and account currently
    // entered. Reports failure on the entry page and stays there.
    bool derive(bool reportOnEntryPage);
    void setAccount(int account);
    void rebuildReview();

    void showNamePage();
    void doWrite();
    void rebuildResult(const std::string &path);

    void wipeSecrets();

    AppWindow *app_ = nullptr;

    QStackedWidget *pages_ = nullptr;
    WalletExport export_;
    int account_ = 0;
    Field field_ = Field::Mnemonic;

    // --- entry
    // The same numbered grid the creation screen verifies into, over the same
    // shared mnemonic buffer. Words are shown in clear here rather than as
    // blocks: creation masks them because the operator is meant to be copying
    // from paper and not from the screen, and here there is no such thing to
    // enforce - they ARE copying from paper, and a transcription they cannot
    // read back is the entire failure this screen exists to prevent.
    SeedView *mnemonicGrid_ = nullptr;
    int wordCount_ = 12;
    int cursor_ = 0;
    bool revealWords_ = true;
    QPushButton *countButtons_[kCountChoices] = {};
    QPushButton *revealWordsBtn_ = nullptr;

    // The three fields, as three cards in the column, all of them on screen at
    // once whenever they apply. The passphrase used to be behind a "Type
    // passphrase" toggle button up in the word-count row - a tab in all but
    // name, which is how a wallet with a passphrase turns into "my words do not
    // work". The words card is the one under the grid; the grid's own
    // highlighted cell is the second half of saying where typing goes.
    QFrame *wordsBox_ = nullptr;
    QLabel *wordsCaption_ = nullptr;
    QLabel *wordsHint_ = nullptr;
    QLabel *wordDisplay_ = nullptr;
    QLabel *entryStatus_ = nullptr;

    QFrame *passphraseBox_ = nullptr;
    QLabel *passphraseCaption_ = nullptr;
    QLabel *passphraseHint_ = nullptr;
    QLabel *passphraseDisplay_ = nullptr;

    QFrame *confirmBox_ = nullptr;
    QLabel *confirmCaption_ = nullptr;
    QLabel *confirmHint_ = nullptr;
    QLabel *confirmDisplay_ = nullptr;

    QLabel *entryError_ = nullptr;
    QLabel *entryHint_ = nullptr;
    QPushButton *deriveBtn_ = nullptr;

    // Floats over the pages rather than sitting in one; see ui/osk_panel.h.
    OskPanel *osk_ = nullptr;
    QPushButton *oskToggle_ = nullptr;

    static constexpr int kSuggestionCount = 5;
    QPushButton *suggestions_[kSuggestionCount] = {};

    // --- review
    QLabel *reviewFingerprint_ = nullptr;
    QPushButton *accountButtons_[kMaxAccount + 1] = {};
    QScrollArea *reviewScroll_ = nullptr;
    QWidget *reviewContent_ = nullptr;
    QVBoxLayout *reviewLayout_ = nullptr;
    QLabel *reviewError_ = nullptr;
    QPushButton *writeBtn_ = nullptr;

    // --- naming the file, between the review and the write. See ui/save_as.h.
    SaveAsPage *namePage_ = nullptr;

    // --- result
    QLabel *resultHeading_ = nullptr;
    QScrollArea *resultScroll_ = nullptr;
    QWidget *resultContent_ = nullptr;
    QVBoxLayout *resultLayout_ = nullptr;
};

} // namespace signeros
