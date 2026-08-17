// SPDX-License-Identifier: MIT

#include "ui/screen_import.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QStackedWidget>
#include <QStringList>
#include <QVBoxLayout>

#include <cstdint>
#include <vector>

#include "core/psbt_engine.h"
#include "core/secure_memory.h"
#include "ui/app_window.h"
#include "ui/secret_buffers.h"
#include "ui/seed_view.h"
#include "ui/theme.h"

namespace signeros {
namespace {

QString qs(const std::string &s)
{
    return QString::fromStdString(s);
}

bool isBip39Char(char c)
{
    return (c >= 'a' && c <= 'z') || c == ' ';
}

// The five lengths BIP39 defines, and the longest word in its English list.
// Nothing longer than that can be a word, so nothing longer is accepted into a
// cell - which also keeps the text inside the box SeedView draws for it.
const int kWordChoices[5] = { 12, 15, 18, 21, 24 };
constexpr std::size_t kMaxWordLength = 8;

// "word 3", or "words 3, 9 and 14" - the cells a mask names. Capped: a grid
// where everything is unrecognisable was typed against the wrong piece of paper
// and does not need enumerating.
QString describeCells(std::uint32_t mask, int limit = 3)
{
    QString out;
    int shown = 0;
    int total = 0;
    for (int i = 0; i < 32; ++i) {
        if ((mask & (1u << i)) != 0)
            ++total;
    }
    for (int i = 0; i < 32 && shown < limit; ++i) {
        if ((mask & (1u << i)) == 0)
            continue;
        if (shown > 0)
            out += (shown == total - 1) ? QStringLiteral(" and ")
                                        : QStringLiteral(", ");
        out += QString::number(i + 1);
        ++shown;
    }
    if (total > shown)
        out += QStringLiteral(" and %1 more").arg(total - shown);
    return out;
}

bool isPrintableAscii(char c)
{
    return c >= 0x20 && c <= 0x7e;
}

// Line breaks every `width` characters, for public strings that are one long
// token - an xpub, an address. revealedSecret() does the same job for the two
// strings that are secret and must not be copied more than once on the way to
// the screen; this is the plain version for everything else.
QString chunked(const QString &s, int width)
{
    QString out;
    out.reserve(s.size() + s.size() / width + 2);
    for (int i = 0; i < s.size(); ++i) {
        if (i > 0 && i % width == 0)
            out += QLatin1Char('\n');
        out += s.at(i);
    }
    return out;
}

} // namespace

// ---------------------------------------------------------------------------

ImportScreen::ImportScreen(AppWindow *app, QWidget *parent)
    : QWidget(parent), app_(app)
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);

    pages_ = new QStackedWidget(this);
    pages_->addWidget(buildEntryPage());    // kEntryPage
    pages_->addWidget(buildReviewPage());   // kReviewPage

    // kNamePage - see ui/save_as.h.
    namePage_ = new SaveAsPage(this);
    connect(namePage_, &SaveAsPage::back, this, [this]() { goTo(kReviewPage); });
    connect(namePage_, &SaveAsPage::keyboardRequested, this,
            [this](bool on) { setOskVisible(on); });
    connect(namePage_, &SaveAsPage::accepted, this, &ImportScreen::doWrite);
    pages_->addWidget(namePage_);

    pages_->addWidget(buildResultPage());   // kResultPage
    v->addWidget(pages_);

    // One floating keyboard for the whole screen; see ui/osk_panel.h.
    osk_ = new OskPanel(this);
    osk_->setMode(OnScreenKeyboard::Mode::Bip39);
    connect(osk_, &OskPanel::characterTyped, this, &ImportScreen::typeCharacter);
    connect(osk_, &OskPanel::backspacePressed, this, &ImportScreen::backspace);
    connect(osk_, &OskPanel::deleteWordPressed, this, &ImportScreen::deleteWord);
    connect(osk_, &OskPanel::clearAllPressed, this, &ImportScreen::clearAll);
    connect(osk_, &OskPanel::hideRequested, this, [this]() { setOskVisible(false); });
    connect(osk_, &OskPanel::suggestionChosen, this, &ImportScreen::applySuggestion);

    setFocusPolicy(Qt::StrongFocus);
}

ImportScreen::~ImportScreen()
{
    // Belt and braces. The buffers are shared statics wiped by wipeSecrets(),
    // but a teardown path that skipped it must not leave a mnemonic in memory.
    wipeSecrets();
}

// ---------------------------------------------------------------------------

QWidget *ImportScreen::buildEntryPage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(12), theme::px(24), theme::px(16));
    outer->setSpacing(theme::px(8));

    outer->addWidget(theme::heading(
        QStringLiteral("Enter the recovery words you already have"), page));
    outer->addWidget(theme::dim(
        QStringLiteral("This derives the extended PUBLIC keys for those words and "
                       "writes them to the USB stick, so a coordinator can watch "
                       "the wallet and build transactions for it. Nothing private "
                       "is derived to any file, and the words are wiped from "
                       "memory when you leave this screen."),
        page));

    // --- how many words, and which buffer is being typed into --------------
    //
    // Everything on this row is narrowed below theme's 140px button minimum on
    // purpose. Eight full-width buttons do not fit across a 1024px panel, and a
    // row that does not fit does not wrap - it widens the window past a screen
    // with no window manager to scroll it back, taking the buttons at the
    // bottom of every other page with it.
    auto *fieldRow = new QHBoxLayout;
    fieldRow->setSpacing(theme::px(8));

    QLabel *countLabel = theme::dim(QStringLiteral("words"), page);
    countLabel->setFont(theme::uiFont(14));
    fieldRow->addWidget(countLabel);

    for (int i = 0; i < kCountChoices; ++i) {
        const int words = kWordChoices[i];
        countButtons_[i] = theme::secondaryButton(QStringLiteral("%1").arg(words), page);
        countButtons_[i]->setCheckable(true);
        countButtons_[i]->setChecked(words == wordCount_);
        countButtons_[i]->setMinimumWidth(theme::px(52));
        connect(countButtons_[i], &QPushButton::clicked, this,
                [this, words]() { setWordCount(words); });
        fieldRow->addWidget(countButtons_[i]);
    }
    fieldRow->addStretch(1);

    // Not a secret, but it is somebody's whole seed sitting in clear on a
    // screen in whatever room this is. One click puts it back behind blocks
    // without losing a character of it.
    revealWordsBtn_ = theme::secondaryButton(QStringLiteral("Hide"), page);
    revealWordsBtn_->setCheckable(true);
    revealWordsBtn_->setMinimumWidth(theme::px(88));
    connect(revealWordsBtn_, &QPushButton::clicked, this, [this]() {
        revealWords_ = !revealWords_;
        refreshEntry();
    });
    fieldRow->addWidget(revealWordsBtn_);
    outer->addLayout(fieldRow);

    // --- the grid ----------------------------------------------------------
    mnemonicGrid_ = new SeedView(page);
    mnemonicGrid_->setSource(&mnemonicBuffer());
    mnemonicGrid_->setInteractive(true);
    // Shorter than SeedView's own minimum. This page carries more above and
    // below the grid than the verification page does - a word count row, a
    // passphrase line, suggestions - and on a 600px panel with the on-screen
    // keyboard up the difference is what keeps the buttons on the screen.
    mnemonicGrid_->setMinimumHeight(theme::px(150));
    connect(mnemonicGrid_, &SeedView::cellClicked, this, [this](int index) {
        // Clicking a cell also means "I am typing words again", so a click
        // does not silently feed the passphrase buffer.
        if (field_ != Field::Mnemonic)
            setField(Field::Mnemonic);
        setWordCursor(index);
    });
    outer->addWidget(mnemonicGrid_, 4);

    // --- the three fields, as three cards ---------------------------------
    //
    // The words, the passphrase and the passphrase again, all visible whenever
    // they apply, the active one carrying an accent border. This replaced a
    // "Type words / Type passphrase" pair of toggle buttons up in the row above
    // - a tab strip in all but name, which hid the passphrase behind a control
    // you had to already know about and said nothing about where the next
    // keystroke would land. Same shape as the signing screen, deliberately: it
    // is the same operator typing the same two secrets.
    auto card = [this, page, outer](QFrame **box, QLabel **caption, QLabel **hint) {
        *box = theme::card(page);
        auto *bv = new QVBoxLayout(*box);
        bv->setContentsMargins(theme::px(14), theme::px(8), theme::px(14),
                               theme::px(10));
        bv->setSpacing(theme::px(4));

        auto *row = new QHBoxLayout;
        row->setSpacing(theme::px(10));
        *caption = new QLabel(*box);
        (*caption)->setFont(theme::uiFont(13, true));
        row->addWidget(*caption);
        row->addStretch(1);
        *hint = new QLabel(*box);
        (*hint)->setFont(theme::uiFont(13, true));
        row->addWidget(*hint);
        bv->addLayout(row);

        outer->addWidget(*box);
        return bv;
    };

    QVBoxLayout *wb = card(&wordsBox_, &wordsCaption_, &wordsHint_);
    wordDisplay_ = new QLabel(wordsBox_);
    wordDisplay_->setFont(theme::monoFont(18, true));
    wordDisplay_->setWordWrap(true);
    wb->addWidget(wordDisplay_);

    entryStatus_ = new QLabel(wordsBox_);
    entryStatus_->setFont(theme::uiFont(14));
    entryStatus_->setWordWrap(true);
    entryStatus_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    wb->addWidget(entryStatus_);

    QVBoxLayout *pb = card(&passphraseBox_, &passphraseCaption_, &passphraseHint_);
    passphraseDisplay_ = new QLabel(passphraseBox_);
    passphraseDisplay_->setFont(theme::monoFont(17, true));
    passphraseDisplay_->setWordWrap(true);
    // Same rule as the signing screen: a passphrase on screen has no spaces to
    // wrap at and does not get a vote on how wide this page is. See
    // revealedSecret().
    passphraseDisplay_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    pb->addWidget(passphraseDisplay_);

    auto *passphraseWarning = theme::dim(
        QStringLiteral("Warning: Any passphrase produces a valid wallet. A typo will not give an error, "
                       "it will generate a completely different, empty wallet."),
        passphraseBox_);
    passphraseWarning->setFont(theme::uiFont(12));
    passphraseWarning->setWordWrap(true);
    passphraseWarning->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    pb->addWidget(passphraseWarning);

    QVBoxLayout *cb = card(&confirmBox_, &confirmCaption_, &confirmHint_);
    confirmDisplay_ = new QLabel(confirmBox_);
    confirmDisplay_->setFont(theme::monoFont(17, true));
    confirmDisplay_->setWordWrap(true);
    confirmDisplay_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
    cb->addWidget(confirmDisplay_);
    confirmBox_->hide();

    // A click anywhere on a card puts the typing there. The labels inside are
    // transparent to the mouse so the press lands on the frame being watched
    // rather than on whichever line of text was under the finger.
    for (QFrame *box : {wordsBox_, passphraseBox_, confirmBox_}) {
        box->installEventFilter(this);
        for (QLabel *l : box->findChildren<QLabel *>())
            l->setAttribute(Qt::WA_TransparentForMouseEvents, true);
    }

#ifdef SIGNEROS_WORD_SUGGESTIONS
    auto *sugRow = new QHBoxLayout;
    sugRow->setSpacing(theme::px(8));
    for (int i = 0; i < kSuggestionCount; ++i) {
        suggestions_[i] = theme::secondaryButton(QString(), page);
        suggestions_[i]->setFont(theme::monoFont(17, true));
        suggestions_[i]->setMinimumWidth(theme::px(80));
        suggestions_[i]->hide();
        connect(suggestions_[i], &QPushButton::clicked, this,
                [this, i]() { applySuggestion(i); });
        sugRow->addWidget(suggestions_[i], 1);
    }
    outer->addLayout(sugRow);
#endif

    entryError_ = new QLabel(page);
    entryError_->setFont(theme::uiFont(15, true));
    entryError_->setWordWrap(true);
    entryError_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
    entryError_->hide();
    outer->addWidget(entryError_);

    entryHint_ = new QLabel(page);
    entryHint_->setFont(theme::uiFont(13));
    entryHint_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    entryHint_->setAlignment(Qt::AlignRight);
    outer->addWidget(entryHint_);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));

    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), page);
    connect(back, &QPushButton::clicked, app_, &AppWindow::showHome);
    buttons->addWidget(back);

    QPushButton *clear = theme::secondaryButton(QStringLiteral("Clear"), page);
    connect(clear, &QPushButton::clicked, this, &ImportScreen::clearAll);
    buttons->addWidget(clear);

    // Every page that takes typing carries this, not just the ones that guessed
    // the machine has no keyboard: F2 is invisible to somebody who has never
    // read the hint line, and a touchscreen laptop reports a keyboard it may
    // not have in front of it.
    oskToggle_ = theme::secondaryButton(QStringLiteral("On-screen keys (F2)"), page);
    oskToggle_->setCheckable(true);
    connect(oskToggle_, &QPushButton::clicked, this,
            [this](bool on) { setOskVisible(on); });
    buttons->addWidget(oskToggle_);

    buttons->addStretch(1);

    deriveBtn_ = theme::primaryButton(QStringLiteral("Derive the keys"), page);
    connect(deriveBtn_, &QPushButton::clicked, this, [this]() {
        if (passphraseReady() && derive(true))
            goTo(kReviewPage);
    });
    buttons->addWidget(deriveBtn_);
    outer->addLayout(buttons);

    // Nothing here may hold the keyboard focus: a physical keystroke has to
    // reach keyPressEvent() and go into the secure buffer, and Space would
    // otherwise re-activate whichever button was clicked last. Which is also
    // why F3 exists - with every button unfocusable, switching to the
    // passphrase would otherwise be reachable only with a pointer.
    for (QPushButton *b : page->findChildren<QPushButton *>())
        b->setFocusPolicy(Qt::NoFocus);

    return page;
}

// ---------------------------------------------------------------------------

QWidget *ImportScreen::buildReviewPage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(14), theme::px(24), theme::px(16));
    outer->setSpacing(theme::px(8));

    outer->addWidget(theme::heading(
        QStringLiteral("Check this against your existing wallet"), page));

    // The one paragraph on this screen that has to be read. A wrong passphrase
    // cannot be detected by this machine - only by the operator, and only here.
    QFrame *warnCard = theme::card(page);
    warnCard->setObjectName(QStringLiteral("cardWarn"));
    auto *wc = new QVBoxLayout(warnCard);
    wc->setContentsMargins(theme::px(16), theme::px(12), theme::px(16), theme::px(12));
    wc->setSpacing(theme::px(6));

    auto *wt = new QLabel(QStringLiteral("BEFORE YOU USE THIS FILE"), warnCard);
    wt->setFont(theme::uiFont(13, true));
    wt->setStyleSheet(QStringLiteral("color: %1;").arg(theme::warn()));
    wc->addWidget(wt);

    wc->addWidget(theme::body(
        QStringLiteral(
            "The fingerprint and first address below must match what your "
            "existing wallet shows. If they do not, this is a different wallet "
            "and the file would be wrong.\n\n"
            "A wrong word cannot get this far - BIP39's checksum rejects it. A "
            "wrong PASSPHRASE can: any characters are legal, so the wrong ones "
            "silently produce a valid, empty wallet. This machine also reads "
            "every keyboard as US, so a passphrase typed on a QWERTZ or "
            "Turkish-Q layout is captured as different characters - which is "
            "why the previous page shows it in clear and asks for it twice."),
        warnCard));
    outer->addWidget(warnCard);

    reviewFingerprint_ = new QLabel(page);
    reviewFingerprint_->setFont(theme::monoFont(26, true));
    reviewFingerprint_->setWordWrap(true);
    outer->addWidget(reviewFingerprint_);

    // --- account ----------------------------------------------------------
    //
    // Ten buttons and a label across one row. Every one of them is narrowed
    // below theme's 140px button minimum on purpose, the same way the word
    // count row on the entry page is: ten full-width buttons are wider than a
    // 1280px screen, and a row that does not fit does not wrap - the layout
    // hands out its minimums anyway and the buttons on the right ride over the
    // ones on their left and off the edge of the panel.
    //
    // 44px scaled is still a fingertip: the height comes from theme's own
    // minimum and is untouched, and these hold one digit each.
    auto *accountRow = new QHBoxLayout;
    accountRow->setSpacing(theme::px(6));
    auto *accountLabel = new QLabel(QStringLiteral("Account"), page);
    accountLabel->setFont(theme::uiFont(15, true));
    accountRow->addWidget(accountLabel, 0);
    for (int i = 0; i <= kMaxAccount; ++i) {
        accountButtons_[i] = theme::secondaryButton(QStringLiteral("%1").arg(i), page);
        accountButtons_[i]->setCheckable(true);
        accountButtons_[i]->setChecked(i == account_);
        accountButtons_[i]->setMinimumWidth(theme::px(44));
        connect(accountButtons_[i], &QPushButton::clicked, this,
                [this, i]() { setAccount(i); });
        accountRow->addWidget(accountButtons_[i], 1);
    }
    outer->addLayout(accountRow);

    outer->addWidget(theme::dim(
        QStringLiteral("Almost every wallet is account 0. Change this only if "
                       "you know yours is not - the keys below change with it, "
                       "and an export for the wrong account is an export for a "
                       "wallet you do not own."),
        page));

    reviewScroll_ = new QScrollArea(page);
    reviewScroll_->setWidgetResizable(true);
    reviewScroll_->setFrameShape(QFrame::NoFrame);
    reviewScroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // Same reason as the signing screen: a QScrollArea's default
    // WheelFocus makes it the one focusable widget on a page whose buttons are
    // all NoFocus, so it takes the focus when the page appears and the screen's
    // keyPressEvent stops seeing the first keystroke.
    reviewScroll_->setFocusPolicy(Qt::NoFocus);
    reviewContent_ = new QWidget(reviewScroll_);
    reviewLayout_ = new QVBoxLayout(reviewContent_);
    reviewLayout_->setContentsMargins(0, 0, theme::px(8), 0);
    reviewLayout_->setSpacing(theme::px(8));
    reviewScroll_->setWidget(reviewContent_);
    reviewScroll_->setAlignment(Qt::AlignHCenter | Qt::AlignTop);
    reviewContent_->setMaximumWidth(theme::px(1040));
    outer->addWidget(reviewScroll_, 1);

    reviewError_ = new QLabel(page);
    reviewError_->setFont(theme::uiFont(15, true));
    reviewError_->setWordWrap(true);
    reviewError_->hide();
    outer->addWidget(reviewError_);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));
    QPushButton *back = theme::secondaryButton(
        QStringLiteral("Back - change the words"), page);
    connect(back, &QPushButton::clicked, this, [this]() { goTo(kEntryPage); });
    buttons->addWidget(back);
    buttons->addStretch(1);

    writeBtn_ = theme::primaryButton(QStringLiteral("Write the watch-only file"), page);
    connect(writeBtn_, &QPushButton::clicked, this, &ImportScreen::showNamePage);
    buttons->addWidget(writeBtn_);
    outer->addLayout(buttons);

    // The stick is very often pushed in while this page is already up, so the
    // mount poll enables the button rather than making the operator go back.
    connect(app_, &AppWindow::dataStatusChanged, this, [this](bool) {
        if (pages_->currentIndex() == kReviewPage)
            rebuildReview();
    });

    for (QPushButton *b : page->findChildren<QPushButton *>())
        b->setFocusPolicy(Qt::NoFocus);

    return page;
}

// ---------------------------------------------------------------------------

QWidget *ImportScreen::buildResultPage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(16), theme::px(24), theme::px(18));
    outer->setSpacing(theme::px(10));

    resultHeading_ = new QLabel(page);
    resultHeading_->setFont(theme::uiFont(26, true));
    resultHeading_->setWordWrap(true);
    outer->addWidget(resultHeading_);

    resultScroll_ = new QScrollArea(page);
    resultScroll_->setWidgetResizable(true);
    resultScroll_->setFrameShape(QFrame::NoFrame);
    resultScroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // Same reason as the signing screen: a QScrollArea's default
    // WheelFocus makes it the one focusable widget on a page whose buttons are
    // all NoFocus, so it takes the focus when the page appears and the screen's
    // keyPressEvent stops seeing the first keystroke.
    resultScroll_->setFocusPolicy(Qt::NoFocus);
    resultContent_ = new QWidget(resultScroll_);
    resultLayout_ = new QVBoxLayout(resultContent_);
    resultLayout_->setContentsMargins(0, 0, theme::px(8), 0);
    resultLayout_->setSpacing(theme::px(8));
    resultScroll_->setWidget(resultContent_);
    resultScroll_->setAlignment(Qt::AlignHCenter | Qt::AlignTop);
    resultContent_->setMaximumWidth(theme::px(1040));
    outer->addWidget(resultScroll_, 1);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));
    buttons->addStretch(1);

    QPushButton *home = theme::secondaryButton(QStringLiteral("Back to the start"), page);
    connect(home, &QPushButton::clicked, app_, &AppWindow::showHome);
    buttons->addWidget(home);

    QPushButton *off = theme::primaryButton(QStringLiteral("Secure shutdown"), page);
    connect(off, &QPushButton::clicked, app_, &AppWindow::showShutdown);
    buttons->addWidget(off);
    buttons->addStretch(1);

    outer->addLayout(buttons);

    for (QPushButton *b : page->findChildren<QPushButton *>())
        b->setFocusPolicy(Qt::NoFocus);

    return page;
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

void ImportScreen::onEnter()
{
    wipeSecrets();
    export_ = WalletExport();
    account_ = 0;
    revealWords_ = true;
    cursor_ = 0;
    // Lays the empty cells out before a key is pressed. This is what makes the
    // cursor an index rather than the end of the buffer: cell 7 exists and can
    // be typed into whether or not cells 1-6 hold anything.
    setWordCount(wordCount_);
    setAccount(0);
    setField(Field::Mnemonic);
    goTo(kEntryPage);
}

SaveAsPage *ImportScreen::activeSaveAsPage() const
{
    return pages_->currentIndex() == kNamePage ? namePage_ : nullptr;
}

void ImportScreen::onLeave()
{
    wipeSecrets();
}

void ImportScreen::setOskVisible(bool visible)
{
    osk_->setPanelVisible(visible);
    oskToggle_->setChecked(visible);
    namePage_->setKeyboardShown(visible);
    entryHint_->setVisible(!visible);
    refreshEcho();
}

void ImportScreen::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    if (osk_ != nullptr && osk_->panelVisible())
        osk_->reposition();
}

void ImportScreen::goTo(Page page)
{
    pages_->setCurrentIndex(page);

    switch (page) {
    case kEntryPage:
        // On a machine with a real keyboard the on-screen one is only in the
        // way, and the space it frees goes to the entry. F2 brings it back.
        osk_->setMode(field_ == Field::Mnemonic ? OnScreenKeyboard::Mode::Bip39
                                                : OnScreenKeyboard::Mode::FullText);
        setOskVisible(!app_->config().physicalKeyboard);
        refreshEntry();
        break;

    case kReviewPage:
        setOskVisible(false);
        rebuildReview();
        reviewScroll_->verticalScrollBar()->setValue(0);
        break;

    default:
        break;
    }

    setFocus();
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

void ImportScreen::setField(Field field)
{
    // There is nothing to confirm until there is a passphrase.
    if (field == Field::Confirm && passphraseBuffer().empty())
        field = Field::Passphrase;

    field_ = field;
    osk_->setMode(field == Field::Mnemonic ? OnScreenKeyboard::Mode::Bip39
                                           : OnScreenKeyboard::Mode::FullText);
    refreshEntry();
}

// Which buffer the next keystroke lands in. One place decides, as on the
// signing screen.
SecureString &ImportScreen::activeBuffer()
{
    switch (field_) {
    case Field::Passphrase: return passphraseBuffer();
    case Field::Confirm:    return passphraseConfirmBuffer();
    default:                return mnemonicBuffer();
    }
}

// An empty passphrase is accepted as it stands - most wallets have none. What
// is not accepted is one typed once and not confirmed, which is the slip
// nothing downstream can catch.
bool ImportScreen::passphraseReady()
{
    if (passphraseBuffer().empty())
        return true;

    if (!passphraseConfirmed()) {
        setField(Field::Confirm);
        entryError_->setText(
            QStringLiteral("The passphrase and its repeat are not the same. "
                           "Both are shown in clear above - compare them, and "
                           "correct whichever one is wrong."));
        entryError_->show();
        return false;
    }
    return true;
}

void ImportScreen::setWordCount(int words)
{
    if (!isValidWordCount(static_cast<std::size_t>(words)))
        return;
    wordCount_ = words;
    for (int i = 0; i < kCountChoices; ++i) {
        if (countButtons_[i] != nullptr)
            countButtons_[i]->setChecked(kWordChoices[i] == words);
    }

    // Growing adds empty cells; shrinking wipes whatever was in the cells past
    // the new end. Both are what the operator asked for by naming a length -
    // and the status line under the grid says how many cells are filled, so a
    // count set wrongly does not go unnoticed.
    mnemonicBuffer().setSlotCount(static_cast<std::size_t>(words));
    if (mnemonicGrid_ != nullptr)
        mnemonicGrid_->setCellCount(static_cast<std::size_t>(words));
    if (cursor_ >= words)
        cursor_ = words - 1;
    refreshEntry();
}

void ImportScreen::cycleWordCount()
{
    for (int i = 0; i < kCountChoices; ++i) {
        if (kWordChoices[i] == wordCount_) {
            setWordCount(kWordChoices[(i + 1) % kCountChoices]);
            return;
        }
    }
    setWordCount(kWordChoices[0]);
}

void ImportScreen::setWordCursor(int index)
{
    // Clamped rather than wrapped: an arrow press at the end of the grid that
    // silently jumped to word 1 would have the next keystroke overwrite it.
    if (index < 0)
        index = 0;
    if (index > wordCount_ - 1)
        index = wordCount_ - 1;
    if (index == cursor_)
        return;
    cursor_ = index;
    refreshEntry();
}

void ImportScreen::moveWordCursor(int delta)
{
    setWordCursor(cursor_ + delta);
}

void ImportScreen::typeCharacter(char c)
{
    if (pages_->currentIndex() == kNamePage) {
        namePage_->typeCharacter(c);
        refreshEcho();
        return;
    }

    if (field_ != Field::Mnemonic) {
        if (!isPrintableAscii(c))
            return;
        if (!activeBuffer().append(c)) {
            entryError_->setText(
                QStringLiteral("That is as much text as this field holds (%1 "
                               "characters).")
                    .arg(SecureString::capacity() - 1));
            entryError_->show();
            return;
        }
        entryError_->hide();
        refreshEntry();
        return;
    }

    if (!isBip39Char(c))
        return;

    // In a grid a space is not a character, it is "this cell is done" - the
    // same thing Enter and the right arrow mean. The separators already exist,
    // one per cell, from the moment the count was chosen.
    if (c == ' ') {
        moveWordCursor(1);
        return;
    }

    SecureString &key = mnemonicBuffer();
    if (key.slotLength(static_cast<std::size_t>(cursor_)) >= kMaxWordLength)
        return;
    if (!key.appendToSlot(static_cast<std::size_t>(cursor_), c))
        return;
    entryError_->hide();
    refreshEntry();
}

void ImportScreen::backspace()
{
    if (pages_->currentIndex() == kNamePage) {
        namePage_->backspace();
        refreshEcho();
        return;
    }

    if (field_ != Field::Mnemonic) {
        activeBuffer().backspace();
        refreshEntry();
        return;
    }

    SecureString &key = mnemonicBuffer();
    const std::size_t cell = static_cast<std::size_t>(cursor_);
    // Backspace in an already empty cell steps back into the previous one, so
    // holding it down walks back through the entry the way it does in every
    // other text field anyone has used.
    if (key.slotLength(cell) == 0) {
        if (cursor_ > 0)
            setWordCursor(cursor_ - 1);
        return;
    }
    key.backspaceInSlot(cell);
    refreshEntry();
}

void ImportScreen::deleteWord()
{
    if (pages_->currentIndex() == kNamePage) {
        namePage_->clearName();
        refreshEcho();
        return;
    }

    if (field_ != Field::Mnemonic) {
        activeBuffer().backspaceWord();
        refreshEntry();
        return;
    }
    mnemonicBuffer().clearSlot(static_cast<std::size_t>(cursor_));
    refreshEntry();
}

void ImportScreen::clearAll()
{
    if (pages_->currentIndex() == kNamePage) {
        namePage_->clearName();
        refreshEcho();
        return;
    }

    if (field_ != Field::Mnemonic) {
        activeBuffer().clear();
    } else {
        // clear() takes the slots with the text, so they are laid out again
        // straight away: the grid must not lose its cells just because it lost
        // its words.
        mnemonicBuffer().clear();
        mnemonicBuffer().setSlotCount(static_cast<std::size_t>(wordCount_));
        cursor_ = 0;
    }
    entryError_->hide();
    refreshEntry();
}

void ImportScreen::refreshEntry()
{
    const SecureString &key = mnemonicBuffer();
    const bool typingWords = (field_ == Field::Mnemonic);

    // Every word stays readable. The creation screen masks its grid because the
    // operator is meant to be copying from paper rather than from the display;
    // here the paper IS the source, and a transcription that cannot be read
    // back is the mistake this screen exists to catch. "Hide words" is there
    // for the room rather than for the flow.
    mnemonicGrid_->setMasked(!revealWords_);
    mnemonicGrid_->setCellCount(static_cast<std::size_t>(wordCount_));
    // No cursor while the passphrase is being typed: a caret blinking in a cell
    // that is not receiving the keystrokes is a lie about where they are going.
    mnemonicGrid_->setActiveWord(typingWords ? cursor_ : -1);

    // Which cells hold something that is not a BIP39 word at all. This is the
    // answer bip39Validate() cannot give - it can only say the whole thing is
    // wrong - and without it a single mistyped letter means reading twenty-four
    // words back off the paper to find it.
    const std::uint32_t unknown =
        bip39UnknownSlots(key, typingWords ? cursor_ : -1);
    mnemonicGrid_->setErrorWords(unknown);
    mnemonicGrid_->update();

    revealWordsBtn_->setText(revealWords_ ? QStringLiteral("Hide")
                                          : QStringLiteral("Show"));
    revealWordsBtn_->setChecked(!revealWords_);

    // The cell the cursor is in, in clear, with its number. The number is the
    // answer to "where am I" that a highlight among twenty-four outlined cells
    // does not give on its own.
    char current[kMaxWordLength + 2] = {};
    const std::size_t currentLen =
        key.copySlot(static_cast<std::size_t>(cursor_), current, sizeof(current));
    wordDisplay_->setStyleSheet(
        QStringLiteral("color: %1;")
            .arg(typingWords ? theme::text() : theme::textDim()));
    wordDisplay_->setText(
        QStringLiteral("word %1 of %2:   %3")
            .arg(cursor_ + 1)
            .arg(wordCount_)
            .arg(currentLen > 0
                     ? QString::fromLatin1(current, static_cast<int>(currentLen))
                     : QStringLiteral("_")));
    secureWipe(current, sizeof(current));

    const std::size_t filled = key.wordCount();
    const bool complete = (filled == static_cast<std::size_t>(wordCount_));

    if (unknown != 0) {
        const bool several = (unknown & (unknown - 1)) != 0;
        entryStatus_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
        entryStatus_->setText(
            (several ? QStringLiteral("Words %1 are not in the BIP39 wordlist. "
                                      "Click a cell, or use the arrow keys, to "
                                      "re-type it.")
                     : QStringLiteral("Word %1 is not in the BIP39 wordlist. "
                                      "Click that cell, or use the arrow keys, "
                                      "and re-type it."))
                .arg(describeCells(unknown)));
    } else if (complete) {
        entryStatus_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::ok()));
        entryStatus_->setText(
            QStringLiteral("All %1 words are in the wordlist. The checksum is "
                           "checked when you derive.").arg(wordCount_));
    } else {
        entryStatus_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
        entryStatus_->setText(
            QStringLiteral("%1 of %2 words entered.").arg(filled).arg(wordCount_));
    }

    // Deriving needs every cell filled: a gap in the middle is not a shorter
    // mnemonic, it is an unfinished one, and passing it to BIP39 would produce
    // "that is not a valid mnemonic" for a reason the operator can already see.
    deriveBtn_->setEnabled(complete && unknown == 0);

    // --- the passphrase, in clear, and again ------------------------------
    //
    // Shown as typed rather than as blocks, for the reason at the top of this
    // file: a wrong passphrase is undetectable by this machine and produces a
    // valid, empty wallet, and the commonest cause is a keyboard this build
    // reads as US when it is not. Blocks hide exactly the thing the operator
    // has to check. Typed twice as well, which catches the other half - a slip
    // that a second entry disagrees with.
    const SecureString &pass = passphraseBuffer();
    const std::size_t plen = pass.size();
    if (plen == 0) {
        passphraseDisplay_->setStyleSheet(
            QStringLiteral("color: %1;").arg(theme::textDim()));
        passphraseDisplay_->setText(
            field_ == Field::Passphrase
                ? QStringLiteral("type it now, or leave this empty")
                : QStringLiteral("none - the wallet is the words alone"));
    } else {
        passphraseDisplay_->setStyleSheet(
            QStringLiteral("color: %1;").arg(theme::warn()));
        passphraseDisplay_->setText(
            revealedSecret(pass) +
            QStringLiteral("\n(%1 characters)").arg(plen));
    }

    const SecureString &again = passphraseConfirmBuffer();
    const std::size_t clen = again.size();
    if (plen > 0) {
        if (clen == 0) {
            confirmDisplay_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::textDim()));
            confirmDisplay_->setText(QStringLiteral("type the same passphrase again"));
        } else {
            confirmDisplay_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::warn()));
            confirmDisplay_->setText(
                revealedSecret(again) +
                QStringLiteral("\n(%1 characters)").arg(clen));
        }
        confirmBox_->show();
    } else {
        // Nothing left to confirm: the second buffer goes with the first rather
        // than sitting in memory describing a passphrase that no longer exists.
        if (clen > 0)
            passphraseConfirmBuffer().clear();
        confirmBox_->hide();
        if (field_ == Field::Confirm)
            field_ = Field::Passphrase;
    }

    entryHint_->setText(
        field_ == Field::Mnemonic
            ? QStringLiteral("Arrows or a click: move between words   ·   Space: "
                             "next word   ·   Enter: next word, then the "
                             "passphrase   ·   F3: switch field   ·   F4: word "
                             "count   ·   F2: on-screen keyboard   ·   Escape: back")
            : QStringLiteral("Enter: on to the next field, then derive   ·   F3: "
                             "switch field   ·   F2: on-screen keyboard   ·   "
                             "Escape: back"));

    refreshFieldChrome();
    refreshEcho();
    refreshSuggestions();
}

// Which card is lit and what its caption says. The grid's own highlighted cell
// is the other half of this while the words are being typed; refreshEntry()
// clears that highlight when they are not, so the two cannot both claim to be
// where the keystrokes go.
void ImportScreen::refreshFieldChrome()
{
    theme::setCardFocused(wordsBox_, field_ == Field::Mnemonic);
    theme::setCardFocused(passphraseBox_, field_ == Field::Passphrase);
    theme::setCardFocused(confirmBox_, field_ == Field::Confirm);

    wordsCaption_->setText(QStringLiteral("RECOVERY WORDS"));
    passphraseCaption_->setText(QStringLiteral("PASSPHRASE  (optional)"));

    auto captionColour = [](QLabel *l, bool active) {
        l->setStyleSheet(QStringLiteral("color: %1;")
                             .arg(active ? theme::accent() : theme::textDim()));
    };
    captionColour(wordsCaption_, field_ == Field::Mnemonic);
    captionColour(passphraseCaption_, field_ == Field::Passphrase);

    if (!passphraseBuffer().empty()) {
        if (passphraseConfirmed()) {
            confirmCaption_->setText(QStringLiteral("PASSPHRASE AGAIN  -  MATCHES"));
            confirmCaption_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::ok()));
        } else if (!passphraseConfirmBuffer().empty()) {
            confirmCaption_->setText(
                QStringLiteral("PASSPHRASE AGAIN  -  NOT THE SAME YET"));
            confirmCaption_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::danger()));
        } else {
            confirmCaption_->setText(QStringLiteral("PASSPHRASE AGAIN"));
            captionColour(confirmCaption_, field_ == Field::Confirm);
        }
    }

    const QString here = QStringLiteral("TYPING HERE");
    const QString away = osk_->panelVisible() ? QStringLiteral("tap here to type")
                                              : QStringLiteral("click here, or F3");
    auto hint = [&](QLabel *l, bool active) {
        l->setText(active ? here : away);
        l->setStyleSheet(QStringLiteral("color: %1;")
                             .arg(active ? theme::accent() : theme::textDim()));
    };
    hint(wordsHint_, field_ == Field::Mnemonic);
    hint(passphraseHint_, field_ == Field::Passphrase);
    hint(confirmHint_, field_ == Field::Confirm);
}

// The panel covers the bottom of the page, so it repeats the field being typed
// into on the line above its keys.
void ImportScreen::refreshEcho()
{
    if (osk_ == nullptr)
        return;

    if (pages_->currentIndex() == kNamePage) {
        osk_->setEcho(QStringLiteral("FILE NAME"), namePage_->fileName(), nullptr);
        return;
    }

    if (field_ == Field::Mnemonic) {
        char current[kMaxWordLength + 2] = {};
        const std::size_t len = mnemonicBuffer().copySlot(
            static_cast<std::size_t>(cursor_), current, sizeof(current));
        osk_->setEcho(QStringLiteral("WORD %1 of %2").arg(cursor_ + 1).arg(wordCount_),
                      len > 0 ? QString::fromLatin1(current, static_cast<int>(len))
                              : QString(),
                      nullptr);
        secureWipe(current, sizeof(current));
        return;
    }

    const bool confirming = (field_ == Field::Confirm);
    const SecureString &pass = confirming ? passphraseConfirmBuffer() : passphraseBuffer();
    osk_->setEcho(confirming ? QStringLiteral("PASSPHRASE AGAIN")
                             : QStringLiteral("PASSPHRASE"),
                  pass.empty() ? QString() : revealedSecret(pass),
                  confirming && passphraseConfirmed() ? theme::ok() : theme::warn());
}

bool ImportScreen::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress) {
        if (watched == wordsBox_) {
            setField(Field::Mnemonic);
            setFocus();
            return true;
        }
        if (watched == passphraseBox_) {
            setField(Field::Passphrase);
            setFocus();
            return true;
        }
        if (watched == confirmBox_) {
            setField(Field::Confirm);
            setFocus();
            return true;
        }
    }
    return QWidget::eventFilter(watched, event);
}

void ImportScreen::refreshSuggestions()
{
#ifdef SIGNEROS_WORD_SUGGESTIONS
    for (int i = 0; i < kSuggestionCount; ++i) {
        if (suggestions_[i] == nullptr)
            continue;
        suggestions_[i]->setText(QString());
        suggestions_[i]->hide();
    }

    QStringList panelLabels;

    // Only for the words. A passphrase is not in any dictionary, and offering
    // it one would be both useless and a hint about what is being typed.
    if (field_ == Field::Mnemonic) {
        char prefix[kMaxWordLength + 2] = {};
        const std::size_t len = mnemonicBuffer().copySlot(
            static_cast<std::size_t>(cursor_), prefix, sizeof(prefix));
        if (len > 0) {
            std::vector<std::string> words;
            bip39Suggestions(prefix, kSuggestionCount, &words);
            secureWipe(prefix, sizeof(prefix));

            const std::size_t limit = static_cast<std::size_t>(kSuggestionCount);
            for (std::size_t i = 0; i < words.size() && i < limit; ++i) {
                const QString word = qs(words[i]);
                const QString label = app_->config().physicalKeyboard
                                          ? QStringLiteral("%1  %2").arg(i + 1).arg(word)
                                          : word;
                suggestions_[i]->setProperty("word", word);
                suggestions_[i]->setText(label);
                panelLabels << label;
            }
        }
    }

    // Whichever row the operator can reach: the page's own is underneath the
    // floating keyboard while that is up, so the panel takes the words over.
    if (osk_ != nullptr && osk_->panelVisible()) {
        osk_->setSuggestions(panelLabels);
    } else {
        if (osk_ != nullptr)
            osk_->setSuggestions(QStringList());
        for (int i = 0; i < panelLabels.size(); ++i)
            suggestions_[i]->show();
    }
#endif
}

void ImportScreen::applySuggestion(int index)
{
#ifdef SIGNEROS_WORD_SUGGESTIONS
    if (index < 0 || index >= kSuggestionCount || suggestions_[index] == nullptr)
        return;
    QByteArray word = suggestions_[index]->property("word").toString().toLatin1();
    if (word.isEmpty())
        return;

    SecureString &key = mnemonicBuffer();
    key.setSlot(static_cast<std::size_t>(cursor_), word.constData(),
                static_cast<std::size_t>(word.size()));

    // The word is in the secure buffer now; scrub the copy Qt made for the
    // button label on its way there.
    secureWipe(word.data(), static_cast<std::size_t>(word.size()));

    // Accepting a suggestion finishes the cell, so it hands over to the next
    // one - which is what appending the separator used to do here.
    if (cursor_ + 1 < wordCount_)
        setWordCursor(cursor_ + 1);
    else
        refreshEntry();
#else
    (void)index;
#endif
}

// ---------------------------------------------------------------------------
// Derivation
// ---------------------------------------------------------------------------

bool ImportScreen::derive(bool reportOnEntryPage)
{
    SecureString &key = mnemonicBuffer();

    // Every cell filled, checked before normalising rather than after: an
    // unfinished grid holds adjacent separators, and collapsing those would
    // turn "word 7 is empty" into a shorter mnemonic that BIP39 then rejects
    // for a reason with nothing to do with what actually happened.
    const std::size_t empty = key.firstEmptySlot();
    if (empty < static_cast<std::size_t>(wordCount_)) {
        if (reportOnEntryPage) {
            entryError_->setText(
                key.wordCount() == 0
                    ? QStringLiteral("Nothing entered yet.")
                    : QStringLiteral("Word %1 is empty.").arg(empty + 1));
            entryError_->show();
            setWordCursor(static_cast<int>(empty));
        }
        return false;
    }

    // BIP39 wants exactly single-space separation. A complete grid already has
    // it; this is the belt to that braces.
    key.normaliseWhitespace();

    std::string err;
    if (!buildWalletExport(key, passphraseBuffer(), app_->config().network,
                           static_cast<std::uint32_t>(account_), &export_, &err)) {
        // The commonest cause by far is a word that is not in the wordlist or a
        // checksum that does not add up, and buildWalletExport says which.
        if (reportOnEntryPage) {
            entryError_->setText(qs(err));
            entryError_->show();
        } else {
            reviewError_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::danger()));
            reviewError_->setText(qs(err));
            reviewError_->show();
        }
        return false;
    }

    entryError_->hide();
    return true;
}

void ImportScreen::setAccount(int account)
{
    if (account < 0 || account > kMaxAccount)
        return;
    account_ = account;
    for (int i = 0; i <= kMaxAccount; ++i) {
        if (accountButtons_[i] != nullptr)
            accountButtons_[i]->setChecked(i == account_);
    }
    // Only re-derive once there is something to re-derive from; setAccount is
    // also called to initialise the buttons before any words exist.
    if (pages_ != nullptr && pages_->currentIndex() == kReviewPage) {
        if (derive(false))
            rebuildReview();
    }
}

void ImportScreen::rebuildReview()
{
    while (QLayoutItem *item = reviewLayout_->takeAt(0)) {
        if (QWidget *w = item->widget())
            w->deleteLater();
        delete item;
    }
    reviewError_->hide();

    reviewFingerprint_->setText(
        QStringLiteral("<span style='color:%1'>master fingerprint</span>  "
                       "<span style='color:%2'>%3</span>")
            .arg(QString::fromLatin1(theme::textDim()),
                 QString::fromLatin1(theme::accent()),
                 qs(export_.fingerprint)));

    QFrame *box = theme::card(reviewContent_);
    auto *v = new QVBoxLayout(box);
    v->setContentsMargins(theme::px(14), theme::px(12), theme::px(14), theme::px(12));
    v->setSpacing(theme::px(6));

    auto row = [&](const QString &key, const QString &value, const char *colour) {
        auto *l = new QLabel(box);
        l->setWordWrap(true);
        l->setFont(theme::monoFont(15));
        l->setText(QStringLiteral("<span style='color:%1'>%2</span>  "
                                  "<span style='color:%3'>%4</span>")
                       .arg(QString::fromLatin1(theme::textDim()), key.toHtmlEscaped(),
                            QString::fromLatin1(colour), value.toHtmlEscaped()));
        return l;
    };

    auto *title = new QLabel(QStringLiteral("THE WALLET THESE WORDS DESCRIBE"), box);
    title->setFont(theme::uiFont(13, true));
    title->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
    v->addWidget(title);

    v->addWidget(row(QStringLiteral("recovery words "),
                     QStringLiteral("%1, entered here").arg(mnemonicBuffer().wordCount()),
                     theme::text()));
    v->addWidget(row(QStringLiteral("passphrase     "),
                     passphraseBuffer().empty()
                         ? QStringLiteral("none")
                         : QStringLiteral("%1 characters")
                               .arg(passphraseBuffer().size()),
                     passphraseBuffer().empty() ? theme::text() : theme::warn()));
    v->addWidget(row(QStringLiteral("network        "),
                     QString::fromLatin1(networkName(app_->config().network)),
                     app_->config().network == Network::Mainnet ? theme::accent()
                                                                : theme::warn()));
    v->addWidget(row(QStringLiteral("account        "),
                     QStringLiteral("%1").arg(account_), theme::text()));
    v->addWidget(row(QStringLiteral("will be written"),
                     app_->config().dataDir, theme::text()));
    reviewLayout_->addWidget(box);

    reviewLayout_->addWidget(theme::sectionHeader(
        QStringLiteral("Compare the first address with your wallet"), reviewContent_));

    for (const AccountExport &a : export_.accounts) {
        QFrame *ab = theme::card(reviewContent_);
        auto *av = new QVBoxLayout(ab);
        av->setContentsMargins(theme::px(14), theme::px(10), theme::px(14), theme::px(10));
        av->setSpacing(theme::px(4));

        auto *t = new QLabel(QStringLiteral("%1  -  %2").arg(qs(a.standard), qs(a.label)), ab);
        t->setFont(theme::uiFont(14, true));
        t->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
        av->addWidget(t);

        auto *p = new QLabel(QStringLiteral("%1   first address:").arg(qs(a.path)), ab);
        p->setFont(theme::monoFont(13));
        p->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
        av->addWidget(p);

        auto *addr = new QLabel(qs(a.firstAddress), ab);
        addr->setFont(theme::monoFont(a.firstAddress.size() > 50 ? 14 : 16, true));
        addr->setWordWrap(true);
        addr->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        av->addWidget(addr);

        // The widest single token anywhere in this application: an xpub is 111
        // characters with nothing to wrap at. Broken into lines and forbidden
        // from voting on the page width, for the reason revealedSecret()
        // documents - it is public data, but the layout does not care.
        auto *xpub = new QLabel(chunked(qs(a.xpub), 56), ab);
        xpub->setFont(theme::monoFont(12));
        xpub->setWordWrap(true);
        xpub->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        xpub->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
        av->addWidget(xpub);

        reviewLayout_->addWidget(ab);
    }

    // One line, not a card each. This page answers exactly one question - did
    // the right words and the right passphrase go in - and the four addresses
    // above answer it. The cosigner keys cannot: a multisig key has no address
    // to compare against anything. So they are mentioned rather than shown,
    // and the file itself explains them.
    if (!export_.cosigners.empty()) {
        QString paths;
        for (const CosignerKey &c : export_.cosigners) {
            if (!paths.isEmpty())
                paths += QStringLiteral(" and ");
            paths += qs(c.path);
        }
        reviewLayout_->addWidget(theme::dim(
            QStringLiteral("The file will also carry this seed's multisig "
                           "cosigner keys (%1). They matter only if this seed "
                           "is one of several in a multisig wallet; a "
                           "single-signature import ignores them.")
                .arg(paths),
            reviewContent_));
    }

    reviewLayout_->addStretch(1);

    const bool mounted = app_->dataMounted();
    writeBtn_->setEnabled(mounted);
    if (!mounted) {
        reviewError_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::warn()));
        reviewError_->setText(
            QStringLiteral("Insert the USB stick now - partition 2, labelled %1. "
                           "It is picked up automatically, and nothing you have "
                           "typed is lost.")
                .arg(app_->config().dataLabel));
        reviewError_->show();
    }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

// Between the review and the write: what the file should be called.
//
// The words are still in memory here, because unlike the signing screen this
// flow can still go back and change them - the export is derived from them and
// re-derived if the account changes. They go the moment the file exists.
void ImportScreen::showNamePage()
{
    const std::string dir = app_->config().dataDir.toStdString();
    namePage_->begin(
        QStringLiteral("Name the watch-only file"),
        QStringLiteral("master %1  -  account %2  -  %3")
            .arg(qs(export_.fingerprint))
            .arg(account_)
            .arg(QString::fromLatin1(networkName(app_->config().network))),
        qs(proposedWalletExportName(export_, dir)),
        app_->config().dataDir,
        QStringLiteral("Write the file"),
        !app_->config().physicalKeyboard);
    pages_->setCurrentIndex(kNamePage);
    osk_->setMode(OnScreenKeyboard::Mode::FullText);
    osk_->setSuggestions(QStringList());
    refreshEcho();
    setOskVisible(!app_->config().physicalKeyboard);
    setFocus();
}

void ImportScreen::doWrite()
{
    reviewError_->hide();

    std::string path;
    std::string err;
    if (!writeWalletExport(export_, app_->config().dataDir.toStdString(),
                           namePage_->fileName().toStdString(), &path, &err)) {
        namePage_->setError(
            QStringLiteral("%1\n\nNothing has been written. Change the name, or "
                           "put the stick back, and write again.").arg(qs(err)));
        return;
    }

    // The words go now, before the result is drawn. Nothing about the outcome
    // needs them any more, and the next screen says so.
    wipeSecrets();
    rebuildResult(path);
    pages_->setCurrentIndex(kResultPage);
    setFocus();
}

void ImportScreen::rebuildResult(const std::string &path)
{
    while (QLayoutItem *item = resultLayout_->takeAt(0)) {
        if (QWidget *w = item->widget())
            w->deleteLater();
        delete item;
    }

    resultHeading_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::ok()));
    resultHeading_->setText(QStringLiteral("Watch-only keys written"));

    QFrame *box = theme::card(resultContent_);
    auto *v = new QVBoxLayout(box);
    v->setContentsMargins(theme::px(14), theme::px(12), theme::px(14), theme::px(12));
    v->setSpacing(theme::px(6));

    auto mono = [&](const QString &text, int size, const char *colour) {
        auto *l = new QLabel(text, box);
        l->setFont(theme::monoFont(size));
        l->setWordWrap(true);
        if (colour != nullptr)
            l->setStyleSheet(QStringLiteral("color: %1;").arg(QString::fromLatin1(colour)));
        return l;
    };

    v->addWidget(mono(QStringLiteral("written to   %1")
                          .arg(QString::fromStdString(
                              path.substr(path.find_last_of('/') + 1))),
                      16, theme::text()));
    v->addWidget(mono(QStringLiteral("fingerprint  %1").arg(qs(export_.fingerprint)),
                      16, theme::accent()));
    v->addWidget(mono(QStringLiteral("account      %1").arg(account_), 16, theme::text()));
    v->addWidget(theme::dim(
        QStringLiteral("Your recovery words and passphrase have been wiped from "
                       "this machine's memory. The file holds extended public "
                       "keys and descriptors only - import it into Sparrow or "
                       "Bitcoin Core to watch the wallet and build "
                       "transactions.\n\n"
                       "Shut down before removing the stick - the shutdown "
                       "flushes the partition and scrubs free memory."),
        box));
    resultLayout_->addWidget(box);

    resultLayout_->addWidget(theme::sectionHeader(
        QStringLiteral("Check the first address after you import"), resultContent_));

    for (const AccountExport &a : export_.accounts) {
        QFrame *ab = theme::card(resultContent_);
        auto *av = new QVBoxLayout(ab);
        av->setContentsMargins(theme::px(14), theme::px(10), theme::px(14), theme::px(10));
        av->setSpacing(theme::px(4));

        auto *t = new QLabel(QStringLiteral("%1  -  %2").arg(qs(a.standard), qs(a.label)), ab);
        t->setFont(theme::uiFont(14, true));
        t->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
        av->addWidget(t);

        auto *p = new QLabel(QStringLiteral("%1   first address:").arg(qs(a.path)), ab);
        p->setFont(theme::monoFont(13));
        p->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
        av->addWidget(p);

        auto *addr = new QLabel(qs(a.firstAddress), ab);
        addr->setFont(theme::monoFont(a.firstAddress.size() > 50 ? 14 : 16, true));
        addr->setWordWrap(true);
        addr->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        av->addWidget(addr);

        resultLayout_->addWidget(ab);
    }

    if (!export_.cosigners.empty())
        resultLayout_->addWidget(theme::dim(
            QStringLiteral("The file also carries this seed's BIP48 multisig "
                           "cosigner keys, for the case where this wallet is "
                           "one signer of several. The file says which line to "
                           "give a coordinator; a single-signature import "
                           "ignores them."),
            resultContent_));

    resultLayout_->addStretch(1);
    resultScroll_->verticalScrollBar()->setValue(0);
}

// ---------------------------------------------------------------------------

void ImportScreen::wipeSecrets()
{
    wipeAllSecrets();
    // The slots go with the text they described, so the next visit starts from
    // cell 1 of an empty grid rather than wherever this one was abandoned.
    cursor_ = 0;

    if (mnemonicGrid_ != nullptr) {
        mnemonicGrid_->setErrorWords(0);
        mnemonicGrid_->setActiveWord(-1);
        mnemonicGrid_->update();
    }
    if (wordDisplay_ != nullptr)
        wordDisplay_->clear();
    if (entryStatus_ != nullptr)
        entryStatus_->clear();
    if (passphraseDisplay_ != nullptr)
        passphraseDisplay_->clear();
    if (confirmDisplay_ != nullptr)
        confirmDisplay_->clear();

    // Dictionary words left in button labels are public wordlist entries rather
    // than the secret, but they are fragments of it and do not get to outlive
    // the keystroke that produced them.
    for (int i = 0; i < kSuggestionCount; ++i) {
        if (suggestions_[i] != nullptr) {
            suggestions_[i]->setText(QString());
            suggestions_[i]->hide();
        }
    }
}

// ---------------------------------------------------------------------------

void ImportScreen::keyPressEvent(QKeyEvent *event)
{
    const int k = event->key();
    const int page = pages_->currentIndex();

    if (page == kReviewPage) {
        // No text is entered on this page, so the digits and the arrows are
        // free for the one thing it has to offer: which account these keys
        // belong to.
        if (k >= Qt::Key_0 && k <= Qt::Key_9) {
            setAccount(k - Qt::Key_0);
            return;
        }
        if (k == Qt::Key_Left) {
            setAccount(account_ - 1);
            return;
        }
        if (k == Qt::Key_Right) {
            setAccount(account_ + 1);
            return;
        }
        if (k == Qt::Key_Return || k == Qt::Key_Enter) {
            // On to the save-as step, not straight to the write: the button
            // beside it does the same, and the two must not disagree about
            // whether the operator gets to name the file.
            if (writeBtn_->isEnabled())
                showNamePage();
            return;
        }
        QWidget::keyPressEvent(event);
        return;
    }

    if (page == kNamePage) {
        // The save-as page is typed into through this screen, like every other
        // field here: this screen holds the focus and hands the keystrokes on.
        if (k == Qt::Key_F2) {
            setOskVisible(!osk_->panelVisible());
            return;
        }
        if (namePage_->handleKey(event))
            return;
        QWidget::keyPressEvent(event);
        return;
    }

    if (page != kEntryPage) {
        QWidget::keyPressEvent(event);
        return;
    }

    if (k == Qt::Key_F2) {
        setOskVisible(!osk_->panelVisible());
        return;
    }
    // Every button on this page is unfocusable so that Space reaches the secure
    // buffer, which would otherwise leave "switch to the passphrase" reachable
    // only with a pointer - and a wallet with a passphrase then unusable on a
    // machine driven by the keyboard. The word count is on the same critical
    // path for the same reason: somebody with 24 words cannot be made to reach
    // for a mouse to say so.
    // Cycles rather than toggles now that a confirmed passphrase is a third
    // field. setField() skips the confirmation while there is nothing to
    // confirm, so the cycle cannot land on a card that is not on screen.
    if (k == Qt::Key_F3) {
        switch (field_) {
        case Field::Mnemonic:   setField(Field::Passphrase); break;
        case Field::Passphrase: setField(passphraseBuffer().empty()
                                             ? Field::Mnemonic
                                             : Field::Confirm); break;
        case Field::Confirm:    setField(Field::Mnemonic); break;
        }
        return;
    }
    if (k == Qt::Key_F4) {
        cycleWordCount();
        return;
    }

    // Grid navigation. Confined to the words: in the passphrase these would be
    // moving a cursor that is not there, and the field has no cells to move
    // between.
    if (field_ == Field::Mnemonic) {
        if (k == Qt::Key_Right) {
            moveWordCursor(1);
            return;
        }
        if (k == Qt::Key_Left) {
            moveWordCursor(-1);
            return;
        }
        // A row is whatever SeedView is currently drawing as one, asked rather
        // than assumed, so the two cannot disagree about where "down" is.
        if (k == Qt::Key_Down) {
            moveWordCursor(mnemonicGrid_->columns());
            return;
        }
        if (k == Qt::Key_Up) {
            moveWordCursor(-mnemonicGrid_->columns());
            return;
        }
        if (k == Qt::Key_Home) {
            setWordCursor(0);
            return;
        }
        if (k == Qt::Key_End) {
            setWordCursor(wordCount_ - 1);
            return;
        }
    }

#ifdef SIGNEROS_WORD_SUGGESTIONS
    // 1-5 and Tab accept a suggested word. Confined to the words, where a digit
    // cannot be part of what is being typed - the BIP39 wordlist is letters
    // only. A passphrase takes any character, so there the digits below type.
    if (field_ == Field::Mnemonic) {
        int pick = -1;
        if (k >= Qt::Key_1 && k <= Qt::Key_1 + kSuggestionCount - 1)
            pick = k - Qt::Key_1;
        else if (k == Qt::Key_Tab)
            pick = 0;
        if (pick >= 0 && suggestions_[pick] != nullptr &&
            suggestions_[pick]->isVisible()) {
            applySuggestion(pick);
            return;
        }
        if (k == Qt::Key_Tab)
            return;   // never let Tab move focus off this screen
    }
#endif

    if (k == Qt::Key_Backspace) {
        backspace();
        return;
    }
    if (k == Qt::Key_Space) {
        typeCharacter(' ');
        return;
    }
    if (k == Qt::Key_Return || k == Qt::Key_Enter) {
        // Enter walks the screen forwards: words, then passphrase, then derive.
        // Within the words it ends a cell like Space does, and only leaves the
        // grid once every cell is filled - so it cannot carry anyone past a
        // half-typed mnemonic. The passphrase is the field people forget
        // exists, and stepping through it is what makes them decide about it
        // rather than skip it.
        if (field_ == Field::Mnemonic) {
            if (deriveBtn_->isEnabled())
                setField(Field::Passphrase);
            else
                moveWordCursor(1);
            return;
        }
        // From the passphrase, Enter steps into the confirmation rather than
        // deriving: an unconfirmed passphrase is not usable, and walking the
        // operator into the field that says so beats refusing at the button.
        if (field_ == Field::Passphrase && !passphraseBuffer().empty() &&
            !passphraseConfirmed()) {
            setField(Field::Confirm);
            return;
        }
        if (deriveBtn_->isEnabled() && passphraseReady() && derive(true))
            goTo(kReviewPage);
        return;
    }

    // Mapped from key codes rather than QKeyEvent::text(), so the character
    // never lands in a QString on its way into the secure buffer.
    const bool shifted = (event->modifiers() & Qt::ShiftModifier) != 0;
    if (k >= Qt::Key_A && k <= Qt::Key_Z) {
        const char base = static_cast<char>('a' + (k - Qt::Key_A));
        typeCharacter(shifted ? static_cast<char>(base - 32) : base);
        return;
    }
    if (k >= Qt::Key_0 && k <= Qt::Key_9) {
        typeCharacter(static_cast<char>('0' + (k - Qt::Key_0)));
        return;
    }

    QWidget::keyPressEvent(event);
}

} // namespace signeros
