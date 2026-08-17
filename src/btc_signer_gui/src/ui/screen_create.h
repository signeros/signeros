// SPDX-License-Identifier: MIT
//
// screen_create.h - creating a wallet on a machine that keeps nothing.
//
// The promise this screen makes, and the reason every page of it is shaped the
// way it is:
//
//     The seed is shown to you once. It is never written to any medium, by any
//     code path, under any circumstance. The only file that leaves this machine
//     contains public keys.
//
// That promise has an obvious consequence: if the operator's transcription is
// wrong, the wallet is gone the moment this screen closes, and nothing anywhere
// can bring it back. So the words are not merely displayed with a warning -
// every single one of them has to be typed back in before the export is
// offered. That is the only check available to a device that refuses to keep a
// copy, and it is not skippable.
//
// The pages, in order:
//
//   Intro       what is about to happen, and how many words you want
//   Entropy     where the randomness comes from, including yours
//   Seed        the words, once
//   Verify      all of them, typed back
//   Passphrase  optional, and the risk of one, stated
//   Confirm     what will be written and where
//   Result      the file, the fingerprint, and the first address to check
//
// Memory discipline is the same as the signing screen's: the words live in the
// shared, page-locked SecureStrings (ui/secret_buffers.h) and are never
// assembled into a QString - not even to be displayed, which is what ui/seed_view.h
// is for.

#pragma once

#include <QWidget>

#include "core/entropy.h"
#include "core/wallet_export.h"
#include "ui/osk_panel.h"
#include "ui/save_as.h"

class QFrame;
class QLabel;
class QProgressBar;
class QPushButton;
class QScrollArea;
class QStackedWidget;
class QVBoxLayout;

namespace signeros {

class AppWindow;
class SeedView;

// ---------------------------------------------------------------------------
// EntropyPad
//
// The patch of screen the operator scribbles on. Every pointer movement and
// every keystroke it sees is folded into the pool with the time it arrived,
// and it draws what it has collected so the contribution is visible rather than
// asserted.
//
// It is not the security of the seed - the kernel CSPRNG and the CPU's RDSEED
// are (see core/entropy.h). It is here because a physical, human source is
// independent of both of those in a way nothing else on this machine is, and
// because asking for it is what teaches the operator where their money's
// randomness actually came from.
// ---------------------------------------------------------------------------
class EntropyPad : public QWidget {
    Q_OBJECT

public:
    EntropyPad(EntropyPool *pool, QWidget *parent = nullptr);

    void restart();
    int percent() const;

signals:
    // One per sample. The page listens to this to move its meter; there is
    // deliberately no separate "target reached" signal, because the meter has
    // to be recomputed on every sample anyway and a second path to the same
    // state is a second thing that can disagree with the first.
    void collected();

protected:
    void paintEvent(QPaintEvent *event) override;
    void mouseMoveEvent(QMouseEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;

private:
    void addSample(int x, int y, unsigned extra);

    EntropyPool *pool_ = nullptr;

    // The last few positions, drawn as a fading trail. Screen coordinates the
    // operator produced themselves: not secret, and already mixed in.
    static constexpr int kTrail = 64;
    QPointF trail_[kTrail];
    int trailCount_ = 0;
    int trailHead_ = 0;
};

// ---------------------------------------------------------------------------

class CreateScreen : public QWidget {
    Q_OBJECT

public:
    explicit CreateScreen(AppWindow *app, QWidget *parent = nullptr);
    ~CreateScreen() override;

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
    // A click on either passphrase card chooses which one is being typed into.
    bool eventFilter(QObject *watched, QEvent *event) override;

private:
    enum Page {
        kIntroPage = 0,
        kEntropyPage,
        kSeedPage,
        kVerifyPage,
        kPassphrasePage,
        kConfirmPage,
        kNamePage,
        kResultPage,
    };

    QWidget *buildIntroPage();
    QWidget *buildEntropyPage();
    QWidget *buildSeedPage();
    QWidget *buildVerifyPage();
    QWidget *buildPassphrasePage();
    QWidget *buildConfirmPage();
    QWidget *buildResultPage();

    void goTo(Page page);

    void setWordCount(int words);
    void generate();

    // Verification entry, driven by the on-screen keyboard and by
    // keyPressEvent().
    void verifyType(char c);
    // Cursor movement between cells. The cursor is an index into the grid and
    // nothing is destroyed by moving it: the buffer holds one slot per cell
    // from the moment the page opens (SecureString's grid view), so word 7 can
    // be emptied and re-typed without disturbing word 8. `delta` of ±1 steps a
    // cell, ±columns steps a row.
    void verifyMoveCursor(int delta);
    void verifySetCursor(int index);
    void verifyBackspace();
    void verifyDeleteWord();
    void verifyClear();
    void refreshVerify();
    void refreshVerifySuggestions();
    void applyVerifySuggestion(int index);

    void passphraseType(char c);
    void refreshPassphrase();

    // The floating keyboard's output, dispatched to whichever page is up, and
    // the line it shows above its own keys.
    void oskType(char c);
    void oskBackspace();
    void oskDeleteWord();
    void oskClear();
    void setOskVisible(bool visible);
    void refreshEcho();
    // Which of the two passphrase fields is being typed into, and whether the
    // page may be left yet. Same rules as the signing and import screens: shown
    // in clear and typed twice, with an empty one simply accepted.
    void setPassphraseField(bool confirming);
    bool passphraseReady();
    void leavePassphrasePage();

    void rebuildConfirm();
    void showNamePage();
    void doCreate();

    void wipeSecrets();

    AppWindow *app_ = nullptr;

    QStackedWidget *pages_ = nullptr;
    // One floating keyboard for every page of this screen; see ui/osk_panel.h.
    OskPanel *osk_ = nullptr;
    EntropyPool pool_;
    EntropyReport report_;
    WalletExport export_;

    // --- intro
    QPushButton *wordButtons_[5] = {};
    int wordCount_ = 12;

    // --- entropy
    EntropyPad *pad_ = nullptr;
    QProgressBar *entropyBar_ = nullptr;
    QLabel *entropySources_ = nullptr;
    QLabel *entropyHint_ = nullptr;
    QPushButton *generateBtn_ = nullptr;

    // --- seed
    SeedView *seedView_ = nullptr;
    QLabel *seedTitle_ = nullptr;
    QLabel *seedProvenance_ = nullptr;

    // --- verify
    SeedView *verifyMask_ = nullptr;
    QPushButton *verifyOskToggle_ = nullptr;
    QLabel *verifyDisplay_ = nullptr;
    QLabel *verifyStatus_ = nullptr;
    QPushButton *verifyNextBtn_ = nullptr;
    static constexpr int kSuggestionCount = 5;
    QPushButton *verifySuggestions_[kSuggestionCount] = {};
    bool verified_ = false;
    int verifyCursor_ = 0;

    // --- passphrase
    //
    // Two cards, the second appearing as soon as there is something in the
    // first. A passphrase chosen here is one the operator has to be able to
    // reproduce for the rest of the wallet's life from a piece of paper they
    // are about to write it on, and nothing downstream can ever tell them they
    // got it wrong - so it is shown as typed and typed twice.
    QPushButton *passOskToggle_ = nullptr;
    QFrame *passBox_ = nullptr;
    QLabel *passCaption_ = nullptr;
    QLabel *passHint_ = nullptr;
    QLabel *passDisplay_ = nullptr;
    QFrame *passConfirmBox_ = nullptr;
    QLabel *passConfirmCaption_ = nullptr;
    QLabel *passConfirmHint_ = nullptr;
    QLabel *passConfirmDisplay_ = nullptr;
    QLabel *passError_ = nullptr;
    QPushButton *passNextBtn_ = nullptr;
    bool passConfirming_ = false;

    // --- confirm
    QScrollArea *confirmScroll_ = nullptr;
    QWidget *confirmContent_ = nullptr;
    QVBoxLayout *confirmLayout_ = nullptr;
    QLabel *confirmError_ = nullptr;
    QPushButton *createBtn_ = nullptr;

    // --- naming the file, between the confirmation and the write.
    SaveAsPage *namePage_ = nullptr;

    // --- result
    QLabel *resultHeading_ = nullptr;
    QScrollArea *resultScroll_ = nullptr;
    QWidget *resultContent_ = nullptr;
    QVBoxLayout *resultLayout_ = nullptr;
};

} // namespace signeros
