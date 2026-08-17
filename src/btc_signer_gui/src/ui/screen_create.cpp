// SPDX-License-Identifier: MIT

#include "ui/screen_create.h"

#include <QColor>
#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QMouseEvent>
#include <QPainter>
#include <QProgressBar>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QStackedWidget>
#include <QStringList>
#include <QVBoxLayout>

#include <cstdint>
#include <cstring>

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

QColor colourOf(const char *hex, int alpha = 255)
{
    QColor c(QString::fromLatin1(hex));
    c.setAlpha(alpha);
    return c;
}

bool isBip39Char(char c)
{
    return (c >= 'a' && c <= 'z') || c == ' ';
}

bool isPrintableAscii(char c)
{
    return c >= 0x20 && c <= 0x7e;
}

const int kWordChoices[5] = { 12, 15, 18, 21, 24 };

// The longest word in the BIP39 English list. Nothing longer can be a word, so
// nothing longer is accepted into a cell - which also keeps a cell's text
// inside the box SeedView draws for it.
constexpr std::size_t kMaxWordLength = 8;

// How the re-typed grid compares with the generated one, cell by cell.
//
// Cell by cell rather than as one byte-prefix, which is what this used to be:
// once the operator can stand in any cell, "the first place the two strings
// diverge" stops being the same thing as "the word that is wrong". Word 3 and
// word 9 can both be wrong at once, and a comparison that can only name the
// first of them sends somebody back to their paper twice.
struct GridMatch {
    std::uint32_t wrong = 0;      // bit i: cell i holds something that is not the word
    std::size_t correct = 0;      // cells holding exactly the right word
    std::size_t filled = 0;       // cells holding anything at all
    bool complete = false;
};

GridMatch compareGrid(const SecureString &typed, const SecureString &reference,
                      int cursor)
{
    GridMatch m;
    const std::size_t cellCount = reference.slotCount();
    const char *t = typed.c_str();
    const char *r = reference.c_str();

    for (std::size_t i = 0; i < cellCount && i < 32; ++i) {
        std::size_t ts = 0, tl = 0, rs = 0, rl = 0;
        if (!typed.slotSpan(i, &ts, &tl) || !reference.slotSpan(i, &rs, &rl))
            continue;
        if (tl == 0)
            continue;             // nothing typed here yet: not wrong, just empty
        ++m.filled;

        if (tl == rl && std::memcmp(t + ts, r + rs, tl) == 0) {
            ++m.correct;
            continue;
        }

        // The cell the cursor is standing in is half typed rather than wrong,
        // for as long as what is in it is still the start of the word it is
        // meant to be. Every other cell is finished and is judged outright, so
        // a mistake found by moving back to word 3 is reported the moment the
        // cursor lands there.
        const bool inProgress = (cursor >= 0 &&
                                 static_cast<std::size_t>(cursor) == i &&
                                 tl < rl &&
                                 std::memcmp(t + ts, r + rs, tl) == 0);
        if (!inProgress)
            m.wrong |= (1u << i);
    }

    m.complete = (cellCount > 0 && m.correct == cellCount);
    return m;
}

// "word 3", or "words 3, 9 and 14" - the cells a mask names, for the status
// line. Capped, because a grid where everything is wrong is a grid that was
// typed against the wrong piece of paper and does not need enumerating.
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

} // namespace

// ---------------------------------------------------------------------------
// EntropyPad
// ---------------------------------------------------------------------------

EntropyPad::EntropyPad(EntropyPool *pool, QWidget *parent)
    : QWidget(parent), pool_(pool)
{
    setMouseTracking(true);
    // Never takes focus: keystrokes are entropy too, and they have to reach
    // CreateScreen::keyPressEvent to be mixed in.
    setFocusPolicy(Qt::NoFocus);
    setMinimumHeight(theme::px(220));
}

void EntropyPad::restart()
{
    trailCount_ = 0;
    trailHead_ = 0;
    update();
}

int EntropyPad::percent() const
{
    if (pool_ == nullptr)
        return 0;
    const std::size_t got = pool_->userSamples();
    const std::size_t want = EntropyPool::kUserSampleTarget;
    return static_cast<int>(qMin<std::size_t>(got * 100 / want, 100));
}

void EntropyPad::addSample(int x, int y, unsigned extra)
{
    if (pool_ == nullptr)
        return;

    pool_->mixUserEvent(x, y, extra);

    trail_[trailHead_] = QPointF(x, y);
    trailHead_ = (trailHead_ + 1) % kTrail;
    if (trailCount_ < kTrail)
        ++trailCount_;

    emit collected();
    update();
}

void EntropyPad::mouseMoveEvent(QMouseEvent *event)
{
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    const QPoint pos = event->position().toPoint();
#else
    const QPoint pos = event->pos();
#endif
    addSample(pos.x(), pos.y(), static_cast<unsigned>(event->buttons()));
}

void EntropyPad::mousePressEvent(QMouseEvent *event)
{
    // A touchscreen with no pointer still produces press events on every tap,
    // so tapping around the pad works where moving a mouse is not possible.
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    const QPoint pos = event->position().toPoint();
#else
    const QPoint pos = event->pos();
#endif
    addSample(pos.x(), pos.y(), 0xC0DEu);
}

void EntropyPad::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    const QRectF r = rect().adjusted(1, 1, -1, -1);
    const int pct = percent();

    p.setPen(QPen(colourOf(pct >= 100 ? theme::ok() : theme::accent(), 200), 2.0));
    p.setBrush(colourOf(theme::panel()));
    p.drawRoundedRect(r, theme::px(8), theme::px(8));
    p.setBrush(Qt::NoBrush);

    // The trail. Older points fade; it is the operator's own movement played
    // back to them, which is what makes "your contribution" concrete instead of
    // a claim in a paragraph.
    for (int k = 0; k < trailCount_; ++k) {
        const int idx = (trailHead_ - 1 - k + kTrail * 2) % kTrail;
        const double age = static_cast<double>(k) / kTrail;
        const int alpha = static_cast<int>(210 * (1.0 - age));
        const double radius = theme::px(9) * (1.0 - age * 0.75) + 1.0;
        p.setPen(Qt::NoPen);
        p.setBrush(colourOf(theme::accent(), alpha));
        p.drawEllipse(trail_[idx], radius, radius);
    }
    p.setBrush(Qt::NoBrush);

    if (trailCount_ == 0) {
        QFont f = theme::uiFont(18);
        p.setFont(f);
        p.setPen(colourOf(theme::textDim()));
        p.drawText(rect(), Qt::AlignCenter,
                   QStringLiteral("Move the mouse around in here\n"
                                  "(or tap, or just type - anything counts)"));
    }
}

// ---------------------------------------------------------------------------
// CreateScreen
// ---------------------------------------------------------------------------

CreateScreen::CreateScreen(AppWindow *app, QWidget *parent)
    : QWidget(parent), app_(app)
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);

    pages_ = new QStackedWidget(this);
    pages_->addWidget(buildIntroPage());       // kIntroPage
    pages_->addWidget(buildEntropyPage());     // kEntropyPage
    pages_->addWidget(buildSeedPage());        // kSeedPage
    pages_->addWidget(buildVerifyPage());      // kVerifyPage
    pages_->addWidget(buildPassphrasePage());  // kPassphrasePage
    pages_->addWidget(buildConfirmPage());     // kConfirmPage

    // kNamePage - see ui/save_as.h. The export is derived by the time this is
    // shown; all it decides is what the file on the stick is called.
    namePage_ = new SaveAsPage(this);
    connect(namePage_, &SaveAsPage::back, this, [this]() { goTo(kConfirmPage); });
    connect(namePage_, &SaveAsPage::keyboardRequested, this,
            [this](bool on) { setOskVisible(on); });
    connect(namePage_, &SaveAsPage::accepted, this, &CreateScreen::doCreate);
    pages_->addWidget(namePage_);

    pages_->addWidget(buildResultPage());      // kResultPage
    v->addWidget(pages_);

    // One floating keyboard for the whole screen, over whichever page is up;
    // see ui/osk_panel.h. It used to be two - one built into the verification
    // page and one into the passphrase page - and both of them squeezed the
    // page they were part of.
    osk_ = new OskPanel(this);
    connect(osk_, &OskPanel::characterTyped, this, &CreateScreen::oskType);
    connect(osk_, &OskPanel::backspacePressed, this, &CreateScreen::oskBackspace);
    connect(osk_, &OskPanel::deleteWordPressed, this, &CreateScreen::oskDeleteWord);
    connect(osk_, &OskPanel::clearAllPressed, this, &CreateScreen::oskClear);
    connect(osk_, &OskPanel::hideRequested, this, [this]() { setOskVisible(false); });
    connect(osk_, &OskPanel::suggestionChosen, this, &CreateScreen::applyVerifySuggestion);

    setFocusPolicy(Qt::StrongFocus);
}

CreateScreen::~CreateScreen()
{
    // Belt and braces. The buffers are shared statics wiped by wipeSecrets(),
    // but a teardown path that skipped it must not leave a seed in memory.
    wipeSecrets();
}

// ---------------------------------------------------------------------------

QWidget *CreateScreen::buildIntroPage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(16), theme::px(24), theme::px(18));
    outer->setSpacing(theme::px(10));

    auto *column = new QWidget(page);
    auto *v = new QVBoxLayout(column);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(theme::px(10));

    v->addWidget(theme::heading(QStringLiteral("Create a new wallet"), column));

    // --- the promise, and its price ---------------------------------------
    QFrame *promise = theme::card(column);
    promise->setObjectName(QStringLiteral("cardWarn"));
    auto *pb = new QVBoxLayout(promise);
    pb->setContentsMargins(theme::px(16), theme::px(14), theme::px(16), theme::px(14));
    pb->setSpacing(theme::px(6));

    auto *ptitle = new QLabel(QStringLiteral("READ THIS FIRST"), promise);
    ptitle->setFont(theme::uiFont(13, true));
    ptitle->setStyleSheet(QStringLiteral("color: %1;").arg(theme::warn()));
    pb->addWidget(ptitle);

    pb->addWidget(theme::body(
        QStringLiteral(
            "This machine will generate a seed and show you the recovery words "
            "once.\n\n"
            "The words are never written to the USB stick, to this machine, or "
            "to anywhere else. There is no backup, no copy and no recovery "
            "service. When this screen closes they are erased from memory and "
            "the only copy left in existence is the one you wrote down on "
            "paper.\n\n"
            "Anyone who reads those words owns everything the wallet will ever "
            "hold. Anyone who cannot read them - including you, if you lose the "
            "paper - has lost it permanently.\n\n"
            "The only file that will be written is a watch-only export: "
            "extended public keys and output descriptors. Import it into "
            "Sparrow or Bitcoin Core to see your balance and build "
            "transactions. It cannot spend anything."),
        promise));
    v->addWidget(promise);

    // --- word count -------------------------------------------------------
    v->addWidget(theme::sectionHeader(QStringLiteral("How many words"), column));

    auto *counts = new QHBoxLayout;
    counts->setSpacing(theme::px(10));
    for (int i = 0; i < 5; ++i) {
        const int words = kWordChoices[i];
        wordButtons_[i] = theme::secondaryButton(
            QStringLiteral("%1 words").arg(words), column);
        wordButtons_[i]->setCheckable(true);
        wordButtons_[i]->setChecked(words == wordCount_);
        connect(wordButtons_[i], &QPushButton::clicked, this,
                [this, words]() { setWordCount(words); });
        counts->addWidget(wordButtons_[i], 1);
    }
    v->addLayout(counts);

    v->addWidget(theme::dim(
        QStringLiteral(
            "12 words carry 128 bits of entropy, 24 carry 256. Both are far "
            "beyond anything that can be searched: nobody has ever broken a "
            "correctly generated 12-word seed, and nobody is going to. 24 words "
            "are the convention for large, long-lived holdings and are what "
            "most hardware wallets default to; 12 are meaningfully easier to "
            "write down accurately, and a transcription error is a real risk "
            "where brute force is not."),
        column));

    v->addStretch(1);
    outer->addWidget(theme::centeredColumn(column, theme::px(900), page), 1);

    // --- actions ----------------------------------------------------------
    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));

    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), page);
    connect(back, &QPushButton::clicked, app_, &AppWindow::showHome);
    buttons->addWidget(back);
    buttons->addStretch(1);

    QPushButton *next = theme::primaryButton(
        QStringLiteral("I understand - continue"), page);
    connect(next, &QPushButton::clicked, this, [this]() { goTo(kEntropyPage); });
    buttons->addWidget(next);

    outer->addLayout(buttons);
    return page;
}

void CreateScreen::setWordCount(int words)
{
    wordCount_ = words;
    for (int i = 0; i < 5; ++i)
        wordButtons_[i]->setChecked(kWordChoices[i] == words);
}

// ---------------------------------------------------------------------------

QWidget *CreateScreen::buildEntropyPage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(16), theme::px(24), theme::px(18));
    outer->setSpacing(theme::px(10));

    auto *column = new QWidget(page);
    auto *v = new QVBoxLayout(column);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(theme::px(8));

    v->addWidget(theme::heading(QStringLiteral("Where your seed comes from"), column));
    v->addWidget(theme::dim(
        QStringLiteral(
            "A seed is only as unguessable as the randomness it was made from. "
            "This device does not trust any single source: it mixes the kernel's "
            "random pool, the CPU's own hardware generator read directly with "
            "RDSEED, timing jitter, and your movement below - all through "
            "HMAC-SHA512. One unpredictable source among them is enough, so all "
            "of them would have to be compromised at once for the result to be "
            "guessable."),
        column));

    entropySources_ = new QLabel(column);
    entropySources_->setFont(theme::monoFont(14));
    entropySources_->setWordWrap(true);
    v->addWidget(entropySources_);

    pad_ = new EntropyPad(&pool_, column);
    v->addWidget(pad_, 1);

    entropyBar_ = new QProgressBar(column);
    entropyBar_->setRange(0, 100);
    entropyBar_->setValue(0);
    entropyBar_->setTextVisible(false);
    entropyBar_->setFixedHeight(theme::px(14));
    v->addWidget(entropyBar_);

    entropyHint_ = new QLabel(column);
    entropyHint_->setFont(theme::uiFont(15, true));
    entropyHint_->setWordWrap(true);
    v->addWidget(entropyHint_);

    connect(pad_, &EntropyPad::collected, this, [this]() {
        entropyBar_->setValue(pad_->percent());
        const bool ready = pool_.userTargetReached();
        generateBtn_->setEnabled(ready);
        entropyHint_->setStyleSheet(
            QStringLiteral("color: %1;").arg(ready ? theme::ok() : theme::textDim()));
        entropyHint_->setText(
            ready ? QStringLiteral("Enough. %1 movements collected - press "
                                   "Generate when you are ready.")
                        .arg(pool_.userSamples())
                  : QStringLiteral("%1 of %2 movements collected.")
                        .arg(pool_.userSamples())
                        .arg(EntropyPool::kUserSampleTarget));
    });

    outer->addWidget(theme::centeredColumn(column, theme::px(900), page), 1);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));
    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), page);
    connect(back, &QPushButton::clicked, this, [this]() { goTo(kIntroPage); });
    buttons->addWidget(back);
    buttons->addStretch(1);

    generateBtn_ = theme::primaryButton(QStringLiteral("Generate my seed"), page);
    generateBtn_->setEnabled(false);
    connect(generateBtn_, &QPushButton::clicked, this, &CreateScreen::generate);
    buttons->addWidget(generateBtn_);
    outer->addLayout(buttons);

    return page;
}

// ---------------------------------------------------------------------------

QWidget *CreateScreen::buildSeedPage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(14), theme::px(24), theme::px(18));
    outer->setSpacing(theme::px(8));

    auto *column = new QWidget(page);
    auto *v = new QVBoxLayout(column);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(theme::px(8));

    seedTitle_ = theme::heading(QStringLiteral("Write these words down, in order"), column);
    v->addWidget(seedTitle_);

    QLabel *warn = theme::body(
        QStringLiteral("On paper, not on a phone and not in a photograph. This is "
                       "the only time they will ever be shown, and nothing on this "
                       "machine has kept a copy. You will be asked to type every "
                       "one of them back on the next screen."),
        column);
    warn->setStyleSheet(QStringLiteral("color: %1;").arg(theme::warn()));
    v->addWidget(warn);

    seedView_ = new SeedView(column);
    v->addWidget(seedView_, 1);

    // Where these particular words came from, stated rather than implied. An
    // operator who is about to trust a number with their savings is entitled to
    // see which sources actually contributed to it on this machine, on this
    // boot - not just to read that several were consulted.
    seedProvenance_ = theme::dim(QString(), column);
    seedProvenance_->setFont(theme::monoFont(13));
    v->addWidget(seedProvenance_);

    outer->addWidget(theme::centeredColumn(column, theme::px(980), page), 1);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));

    QPushButton *cancel = theme::dangerButton(QStringLiteral("Discard and start over"), page);
    connect(cancel, &QPushButton::clicked, this, [this]() {
        // Nothing was written anywhere, so discarding is genuinely free - and
        // that is worth being able to do, because "I was not ready to write
        // them down" is the commonest reason a backup ends up wrong.
        wipeSecrets();
        goTo(kIntroPage);
    });
    buttons->addWidget(cancel);
    buttons->addStretch(1);

    QPushButton *next = theme::primaryButton(
        QStringLiteral("I have written them down"), page);
    connect(next, &QPushButton::clicked, this, [this]() { goTo(kVerifyPage); });
    buttons->addWidget(next);

    outer->addLayout(buttons);
    return page;
}

// ---------------------------------------------------------------------------

QWidget *CreateScreen::buildVerifyPage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(12), theme::px(24), theme::px(16));
    outer->setSpacing(theme::px(6));

    outer->addWidget(theme::heading(QStringLiteral("Now type every word back"), page));
    outer->addWidget(theme::dim(
        QStringLiteral("All of them, in order. Space, Enter or the right arrow "
                       "finishes a word and moves to the next cell; the arrow "
                       "keys move between cells and clicking a cell goes "
                       "straight to it, so a word you got wrong can be fixed "
                       "where it is without re-typing everything after it. This "
                       "is the only way to find out that what you wrote down is "
                       "what this machine generated - and after this screen "
                       "there is nothing left to check it against."),
        page));

    // The grid fills in as the words are typed. It is drawn straight from the
    // secure buffer, so the re-typed mnemonic never becomes a QString either.
    verifyMask_ = new SeedView(page);
    verifyMask_->setSource(&verificationBuffer());
    verifyMask_->setInteractive(true);
    connect(verifyMask_, &SeedView::cellClicked, this, &CreateScreen::verifySetCursor);
    outer->addWidget(verifyMask_, 3);

    verifyDisplay_ = new QLabel(page);
    verifyDisplay_->setFont(theme::monoFont(18, true));
    verifyDisplay_->setWordWrap(true);
    outer->addWidget(verifyDisplay_);

    verifyStatus_ = new QLabel(page);
    verifyStatus_->setFont(theme::uiFont(15, true));
    verifyStatus_->setWordWrap(true);
    outer->addWidget(verifyStatus_);

#ifdef SIGNEROS_WORD_SUGGESTIONS
    auto *sugRow = new QHBoxLayout;
    sugRow->setSpacing(theme::px(8));
    for (int i = 0; i < kSuggestionCount; ++i) {
        verifySuggestions_[i] = theme::secondaryButton(QString(), page);
        verifySuggestions_[i]->setFont(theme::monoFont(17, true));
        verifySuggestions_[i]->setMinimumWidth(theme::px(80));
        verifySuggestions_[i]->hide();
        connect(verifySuggestions_[i], &QPushButton::clicked, this,
                [this, i]() { applyVerifySuggestion(i); });
        sugRow->addWidget(verifySuggestions_[i], 1);
    }
    outer->addLayout(sugRow);
#endif


    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));

    QPushButton *showAgain = theme::secondaryButton(
        QStringLiteral("Show the words again"), page);
    connect(showAgain, &QPushButton::clicked, this, [this]() {
        // Deliberately allowed. The alternative - "you had your chance" - turns
        // an unreadable digit in someone's handwriting into a lost wallet, and
        // the words are still in this machine's memory either way until the
        // flow ends.
        //
        // What has been typed is kept. This used to clear it, which was
        // harmless when the only way to fix word 3 was to re-type everything
        // from word 3 anyway; now that a cell can be corrected in place,
        // throwing away eleven correct words because somebody wanted to check
        // the twelfth is just a punishment for looking.
        goTo(kSeedPage);
    });
    buttons->addWidget(showAgain);

    QPushButton *clear = theme::secondaryButton(QStringLiteral("Clear"), page);
    connect(clear, &QPushButton::clicked, this, &CreateScreen::verifyClear);
    buttons->addWidget(clear);

    verifyOskToggle_ = theme::secondaryButton(QStringLiteral("On-screen keys (F2)"), page);
    verifyOskToggle_->setCheckable(true);
    connect(verifyOskToggle_, &QPushButton::clicked, this,
            [this](bool on) { setOskVisible(on); });
    buttons->addWidget(verifyOskToggle_);

    buttons->addStretch(1);

    verifyNextBtn_ = theme::primaryButton(QStringLiteral("Continue"), page);
    verifyNextBtn_->setEnabled(false);
    connect(verifyNextBtn_, &QPushButton::clicked, this,
            [this]() { goTo(kPassphrasePage); });
    buttons->addWidget(verifyNextBtn_);

    outer->addLayout(buttons);

    // Nothing here may hold the keyboard focus: a physical keystroke has to
    // reach keyPressEvent() and go into the secure buffer, and Space would
    // otherwise re-activate whichever button was clicked last.
    for (QPushButton *b : page->findChildren<QPushButton *>())
        b->setFocusPolicy(Qt::NoFocus);

    return page;
}

// ---------------------------------------------------------------------------

QWidget *CreateScreen::buildPassphrasePage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(12), theme::px(24), theme::px(16));
    outer->setSpacing(theme::px(8));

    outer->addWidget(theme::heading(
        QStringLiteral("Add a passphrase? (optional)"), page));

    QLabel *explain = theme::body(
        QStringLiteral(
            "A BIP39 passphrase is a 25th word of your own choosing. The same "
            "recovery words with a different passphrase are a completely "
            "different wallet, with different addresses and a different "
            "balance.\n\n"
            "It protects you against someone who finds your written words. It "
            "also destroys the wallet if you forget it: there is no way to "
            "recover or reset it, and this machine will not store it any more "
            "than it stores the seed. Write it down with the same care, and "
            "keep it somewhere else.\n\n"
            "Leave it empty if you are not certain you want one."),
        page);
    outer->addWidget(explain);

    // Two cards, the same shape as the signing and import screens: shown in
    // clear as it is typed, and typed again underneath. Nothing downstream can
    // ever tell the operator they mistyped this - a different passphrase is
    // simply a different wallet - so the second entry and the plain characters
    // are the only checks that exist.
    auto card = [this, page, outer](QFrame **box, QLabel **caption, QLabel **hint,
                                    QLabel **display) {
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

        *display = new QLabel(*box);
        (*display)->setFont(theme::monoFont(17, true));
        (*display)->setWordWrap(true);
        // Whatever is in here, it does not get a vote on how wide this page is.
        // See revealedSecret() for what went wrong when it did.
        (*display)->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        bv->addWidget(*display);

        outer->addWidget(*box);
        (*box)->installEventFilter(this);
        for (QLabel *l : (*box)->findChildren<QLabel *>())
            l->setAttribute(Qt::WA_TransparentForMouseEvents, true);
    };

    card(&passBox_, &passCaption_, &passHint_, &passDisplay_);
    card(&passConfirmBox_, &passConfirmCaption_, &passConfirmHint_,
         &passConfirmDisplay_);
    passConfirmBox_->hide();

    passError_ = new QLabel(page);
    passError_->setFont(theme::uiFont(15, true));
    passError_->setWordWrap(true);
    passError_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
    passError_->hide();
    outer->addWidget(passError_);


    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));
    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), page);
    connect(back, &QPushButton::clicked, this, [this]() { goTo(kVerifyPage); });
    buttons->addWidget(back);

    passOskToggle_ = theme::secondaryButton(QStringLiteral("On-screen keys (F2)"), page);
    passOskToggle_->setCheckable(true);
    connect(passOskToggle_, &QPushButton::clicked, this,
            [this](bool on) { setOskVisible(on); });
    buttons->addWidget(passOskToggle_);
    buttons->addStretch(1);

    passNextBtn_ = theme::primaryButton(QStringLiteral("Continue"), page);
    connect(passNextBtn_, &QPushButton::clicked, this,
            &CreateScreen::leavePassphrasePage);
    buttons->addWidget(passNextBtn_);
    outer->addLayout(buttons);

    for (QPushButton *b : page->findChildren<QPushButton *>())
        b->setFocusPolicy(Qt::NoFocus);

    return page;
}

// ---------------------------------------------------------------------------

QWidget *CreateScreen::buildConfirmPage()
{
    auto *page = new QWidget(this);
    auto *outer = new QVBoxLayout(page);
    outer->setContentsMargins(theme::px(24), theme::px(16), theme::px(24), theme::px(18));
    outer->setSpacing(theme::px(10));

    outer->addWidget(theme::heading(
        QStringLiteral("What will be written to the USB stick"), page));

    confirmScroll_ = new QScrollArea(page);
    confirmScroll_->setWidgetResizable(true);
    confirmScroll_->setFrameShape(QFrame::NoFrame);
    confirmScroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // Same reason as the signing screen: a QScrollArea's default
    // WheelFocus makes it the one focusable widget on a page whose buttons are
    // all NoFocus, so it takes the focus when the page appears and the screen's
    // keyPressEvent stops seeing the first keystroke.
    confirmScroll_->setFocusPolicy(Qt::NoFocus);
    confirmContent_ = new QWidget(confirmScroll_);
    confirmLayout_ = new QVBoxLayout(confirmContent_);
    confirmLayout_->setContentsMargins(0, 0, theme::px(8), 0);
    confirmLayout_->setSpacing(theme::px(8));
    confirmScroll_->setWidget(confirmContent_);
    confirmScroll_->setAlignment(Qt::AlignHCenter | Qt::AlignTop);
    confirmContent_->setMaximumWidth(theme::px(1040));
    outer->addWidget(confirmScroll_, 1);

    confirmError_ = new QLabel(page);
    confirmError_->setFont(theme::uiFont(15, true));
    confirmError_->setWordWrap(true);
    confirmError_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
    confirmError_->hide();
    outer->addWidget(confirmError_);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(theme::px(12));
    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), page);
    connect(back, &QPushButton::clicked, this, [this]() { goTo(kPassphrasePage); });
    buttons->addWidget(back);
    buttons->addStretch(1);

    createBtn_ = theme::primaryButton(
        QStringLiteral("Write the watch-only file"), page);
    connect(createBtn_, &QPushButton::clicked, this, &CreateScreen::showNamePage);
    buttons->addWidget(createBtn_);
    outer->addLayout(buttons);

    // The stick is very often pushed in while this page is already up - it is
    // the first moment the operator is told they need it. Rebuilding on the
    // mount poll is what turns that into "the button lights up" rather than
    // "press Back and come in again".
    connect(app_, &AppWindow::dataStatusChanged, this, [this](bool) {
        if (pages_->currentIndex() == kConfirmPage)
            rebuildConfirm();
    });

    return page;
}

QWidget *CreateScreen::buildResultPage()
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
    return page;
}

// ---------------------------------------------------------------------------
// Navigation
// ---------------------------------------------------------------------------

void CreateScreen::onEnter()
{
    wipeSecrets();
    pool_.reset();
    export_ = WalletExport();
    verified_ = false;
    passConfirming_ = false;
    if (passError_ != nullptr)
        passError_->hide();
    setWordCount(wordCount_);
    goTo(kIntroPage);
}

SaveAsPage *CreateScreen::activeSaveAsPage() const
{
    return pages_->currentIndex() == kNamePage ? namePage_ : nullptr;
}

void CreateScreen::onLeave()
{
    wipeSecrets();
    pool_.reset();
}

// The floating keyboard belongs to the screen, so its output goes wherever the
// page that is up would have sent a physical keystroke.
void CreateScreen::oskType(char c)
{
    switch (pages_->currentIndex()) {
    case kVerifyPage:     verifyType(c); break;
    case kPassphrasePage: passphraseType(c); break;
    case kNamePage:       namePage_->typeCharacter(c); refreshEcho(); break;
    default: break;
    }
}

void CreateScreen::oskBackspace()
{
    switch (pages_->currentIndex()) {
    case kVerifyPage:
        verifyBackspace();
        break;
    case kPassphrasePage:
        (passConfirming_ ? passphraseConfirmBuffer() : passphraseBuffer()).backspace();
        refreshPassphrase();
        break;
    case kNamePage:
        namePage_->backspace();
        refreshEcho();
        break;
    default:
        break;
    }
}

void CreateScreen::oskDeleteWord()
{
    switch (pages_->currentIndex()) {
    case kVerifyPage:
        verifyDeleteWord();
        break;
    case kPassphrasePage:
        (passConfirming_ ? passphraseConfirmBuffer() : passphraseBuffer()).backspaceWord();
        refreshPassphrase();
        break;
    case kNamePage:
        namePage_->clearName();
        refreshEcho();
        break;
    default:
        break;
    }
}

void CreateScreen::oskClear()
{
    switch (pages_->currentIndex()) {
    case kVerifyPage:
        verifyClear();
        break;
    case kPassphrasePage:
        (passConfirming_ ? passphraseConfirmBuffer() : passphraseBuffer()).clear();
        refreshPassphrase();
        break;
    case kNamePage:
        namePage_->clearName();
        refreshEcho();
        break;
    default:
        break;
    }
}

void CreateScreen::setOskVisible(bool visible)
{
    osk_->setPanelVisible(visible);
    if (verifyOskToggle_ != nullptr)
        verifyOskToggle_->setChecked(visible);
    if (passOskToggle_ != nullptr)
        passOskToggle_->setChecked(visible);
    if (namePage_ != nullptr)
        namePage_->setKeyboardShown(visible);
    refreshEcho();
}

// The panel covers the bottom of the page, so it repeats the field being typed
// into on the line above its keys.
void CreateScreen::refreshEcho()
{
    if (osk_ == nullptr)
        return;

    switch (pages_->currentIndex()) {
    case kVerifyPage: {
        char current[16] = {};
        const std::size_t len = verificationBuffer().copySlot(
            static_cast<std::size_t>(verifyCursor_), current, sizeof(current));
        osk_->setEcho(QStringLiteral("WORD %1 of %2")
                          .arg(verifyCursor_ + 1)
                          .arg(mnemonicBuffer().wordCount()),
                      len > 0 ? QString::fromLatin1(current, static_cast<int>(len))
                              : QString(),
                      nullptr);
        secureWipe(current, sizeof(current));
        break;
    }
    case kPassphrasePage: {
        const SecureString &p = passConfirming_ ? passphraseConfirmBuffer()
                                                : passphraseBuffer();
        osk_->setEcho(passConfirming_ ? QStringLiteral("PASSPHRASE AGAIN")
                                      : QStringLiteral("PASSPHRASE"),
                      p.empty() ? QString() : revealedSecret(p),
                      passConfirming_ && passphraseConfirmed() ? theme::ok()
                                                               : theme::warn());
        break;
    }
    case kNamePage:
        osk_->setEcho(QStringLiteral("FILE NAME"), namePage_->fileName(), nullptr);
        break;
    default:
        break;
    }
}

void CreateScreen::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    if (osk_ != nullptr && osk_->panelVisible())
        osk_->reposition();
}

void CreateScreen::goTo(Page page)
{
    pages_->setCurrentIndex(page);

    switch (page) {
    case kEntropyPage:
        pad_->restart();
        entropyBar_->setValue(pad_->percent());
        generateBtn_->setEnabled(pool_.userTargetReached());
        entropyHint_->setStyleSheet(
            QStringLiteral("color: %1;").arg(theme::textDim()));
        entropyHint_->setText(
            QStringLiteral("%1 of %2 movements collected.")
                .arg(pool_.userSamples())
                .arg(EntropyPool::kUserSampleTarget));
        entropySources_->setText(
            QStringLiteral("kernel pool <span style='color:%1'>%2</span>   ·   "
                           "CPU RDSEED <span style='color:%3'>%4</span>   ·   "
                           "CPU RDRAND <span style='color:%5'>%6</span>")
                .arg(QString::fromLatin1(kernelEntropyReady() ? theme::ok() : theme::warn()),
                     kernelEntropyReady() ? QStringLiteral("ready")
                                          : QStringLiteral("still filling"),
                     QString::fromLatin1(cpuHasRdseed() ? theme::ok() : theme::textDim()),
                     cpuHasRdseed() ? QStringLiteral("available")
                                    : QStringLiteral("not on this CPU"),
                     QString::fromLatin1(cpuHasRdrand() ? theme::ok() : theme::textDim()),
                     cpuHasRdrand() ? QStringLiteral("available")
                                    : QStringLiteral("not on this CPU")));
        break;

    case kSeedPage:
        seedView_->setSource(&mnemonicBuffer());
        seedView_->setMasked(false);
        seedTitle_->setText(
            QStringLiteral("Write these %1 words down, in order")
                .arg(mnemonicBuffer().wordCount()));
        seedProvenance_->setText(
            QStringLiteral("entropy: %1").arg(qs(report_.describe())));
        break;

    case kVerifyPage:
        // The words come off the screen the moment verification starts. Leaving
        // them up would let the operator copy from the display instead of from
        // the paper they are supposed to be checking, which would make this
        // page prove nothing at all.
        seedView_->setMasked(true);
        verifyMask_->setCellCount(mnemonicBuffer().wordCount());
        // One slot per cell, before a single key is pressed. This is what makes
        // the cursor an index rather than the end of the buffer: cell 7 exists
        // and can be typed into whether or not cells 1-6 hold anything.
        // Re-entering the page (from "Show the words again") keeps what is
        // already there - setSlotCount is a no-op when the count is unchanged.
        verificationBuffer().setSlotCount(mnemonicBuffer().wordCount());
        // On a machine with a real keyboard the on-screen one is only in the
        // way, and the space it frees goes to the word grid. F2 brings it back.
        osk_->setMode(OnScreenKeyboard::Mode::Bip39);
        setOskVisible(!app_->config().physicalKeyboard);
        refreshVerify();
        break;

    case kPassphrasePage:
        // No dictionary for a passphrase - and offering one would be a hint
        // about what is being typed.
        osk_->setSuggestions(QStringList());
        osk_->setMode(OnScreenKeyboard::Mode::FullText);
        setOskVisible(!app_->config().physicalKeyboard);
        refreshPassphrase();
        break;

    case kConfirmPage:
        setOskVisible(false);
        rebuildConfirm();
        confirmScroll_->verticalScrollBar()->setValue(0);
        break;

    default:
        break;
    }

    setFocus();
}

// ---------------------------------------------------------------------------
// Generation
// ---------------------------------------------------------------------------

void CreateScreen::generate()
{
    const std::size_t need = entropyBytesForWords(static_cast<std::size_t>(wordCount_));
    if (need == 0) {
        entropyHint_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
        entropyHint_->setText(QStringLiteral("Unsupported word count."));
        return;
    }

    SecureBuffer<32> entropy;
    std::string err;
    if (!pool_.finalise(entropy.data(), need, &report_, &err)) {
        // The only path that refuses outright. There is no override, because
        // the alternative is minting a key that might be guessable and telling
        // the operator it is fine.
        entropyHint_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
        entropyHint_->setText(qs(err));
        return;
    }

    mnemonicBuffer().clear();
    if (!mnemonicFromEntropy(entropy.data(), need, &mnemonicBuffer(), &err)) {
        entropyHint_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
        entropyHint_->setText(qs(err));
        return;
    }
    // entropy is wiped by its destructor here; the seed exists only as words in
    // the locked mnemonic buffer.

    verificationBuffer().clear();
    verified_ = false;
    goTo(kSeedPage);
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

void CreateScreen::verifyType(char c)
{
    if (!isBip39Char(c))
        return;

    // Space is not a character in a grid, it is the "this cell is done" key -
    // the same thing Enter and the right arrow mean. The separators already
    // exist, one per cell, from the moment the page opened.
    if (c == ' ') {
        verifyMoveCursor(1);
        return;
    }

    SecureString &typed = verificationBuffer();
    if (typed.slotLength(static_cast<std::size_t>(verifyCursor_)) >= kMaxWordLength)
        return;
    if (!typed.appendToSlot(static_cast<std::size_t>(verifyCursor_), c))
        return;
    refreshVerify();
}

void CreateScreen::verifyMoveCursor(int delta)
{
    verifySetCursor(verifyCursor_ + delta);
}

void CreateScreen::verifySetCursor(int index)
{
    const int cells = static_cast<int>(mnemonicBuffer().wordCount());
    if (cells <= 0)
        return;
    // Clamped rather than wrapped. Wrapping from word 12 to word 1 on a stray
    // arrow press moves the cursor the entire width of the grid, and the person
    // typing does not notice until they have overwritten the first word.
    if (index < 0)
        index = 0;
    if (index > cells - 1)
        index = cells - 1;
    if (index == verifyCursor_)
        return;
    verifyCursor_ = index;
    refreshVerify();
}

void CreateScreen::verifyBackspace()
{
    SecureString &typed = verificationBuffer();
    const std::size_t cell = static_cast<std::size_t>(verifyCursor_);

    // Backspace in an already empty cell steps back into the previous one
    // rather than doing nothing, so holding it down walks back through the
    // entry the way it does in every other text field anyone has used.
    if (typed.slotLength(cell) == 0) {
        if (verifyCursor_ > 0)
            verifySetCursor(verifyCursor_ - 1);
        return;
    }
    typed.backspaceInSlot(cell);
    refreshVerify();
}

void CreateScreen::verifyDeleteWord()
{
    verificationBuffer().clearSlot(static_cast<std::size_t>(verifyCursor_));
    refreshVerify();
}

void CreateScreen::verifyClear()
{
    SecureString &typed = verificationBuffer();
    typed.clear();
    typed.setSlotCount(mnemonicBuffer().wordCount());
    verifyCursor_ = 0;
    refreshVerify();
}

void CreateScreen::refreshVerify()
{
    refreshEcho();
    const SecureString &typed = verificationBuffer();
    const SecureString &reference = mnemonicBuffer();
    const std::size_t total = reference.wordCount();

    if (verifyCursor_ >= static_cast<int>(total))
        verifyCursor_ = (total == 0) ? 0 : static_cast<int>(total) - 1;

    const GridMatch m = compareGrid(typed, reference, verifyCursor_);

    verified_ = m.complete;
    verifyNextBtn_->setEnabled(verified_);

    verifyMask_->setErrorWords(m.wrong);
    // The cursor stays visible while a word is wrong - that cell is where the
    // correction has to be typed, so hiding it there is the one moment it is
    // most needed. It goes only once there is nothing left to type.
    verifyMask_->setActiveWord(m.complete ? -1 : verifyCursor_);
    verifyMask_->update();

    // Which cell we are in, and the word in it, in clear. The number is the
    // answer to "where am I" that a highlight on its own does not give when
    // twelve outlined cells look alike - and it matters more now that the
    // cursor can be anywhere rather than only at the end.
    char current[kMaxWordLength + 2] = {};
    const std::size_t currentLen =
        typed.copySlot(static_cast<std::size_t>(verifyCursor_), current, sizeof(current));
    const bool cursorWrong =
        (verifyCursor_ < 32) && ((m.wrong & (1u << verifyCursor_)) != 0);
    verifyDisplay_->setStyleSheet(
        QStringLiteral("color: %1;")
            .arg(cursorWrong ? theme::danger() : theme::text()));
    verifyDisplay_->setText(
        QStringLiteral("word %1 of %2:   %3")
            .arg(verifyCursor_ + 1)
            .arg(total)
            .arg(currentLen > 0
                     ? QString::fromLatin1(current, static_cast<int>(currentLen))
                     : QStringLiteral("_")));
    secureWipe(current, sizeof(current));

    if (m.wrong != 0) {
        const bool several = (m.wrong & (m.wrong - 1)) != 0;
        verifyStatus_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
        verifyStatus_->setText(
            (several ? QStringLiteral("Words %1 do not match what was generated. "
                                      "Click a cell, or use the arrow keys, to "
                                      "re-type it.")
                     : QStringLiteral("Word %1 does not match what was generated. "
                                      "Click that cell, or use the arrow keys, "
                                      "and re-type it."))
                .arg(describeCells(m.wrong)));
    } else if (m.complete) {
        verifyStatus_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::ok()));
        verifyStatus_->setText(
            QStringLiteral("All %1 words match. Your backup is correct.").arg(total));
    } else {
        verifyStatus_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
        verifyStatus_->setText(
            QStringLiteral("%1 of %2 words entered and correct so far.")
                .arg(m.correct)
                .arg(total));
    }

    refreshVerifySuggestions();
}

void CreateScreen::refreshVerifySuggestions()
{
#ifdef SIGNEROS_WORD_SUGGESTIONS
    for (int i = 0; i < kSuggestionCount; ++i) {
        if (verifySuggestions_[i] == nullptr)
            continue;
        verifySuggestions_[i]->setText(QString());
        verifySuggestions_[i]->hide();
    }

    QStringList panelLabels;

    char prefix[kMaxWordLength + 2] = {};
    const std::size_t len = verificationBuffer().copySlot(
        static_cast<std::size_t>(verifyCursor_), prefix, sizeof(prefix));
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
            verifySuggestions_[i]->setProperty("word", word);
            verifySuggestions_[i]->setText(label);
            panelLabels << label;
        }
    }

    // Whichever row the operator can reach: the page's own is underneath the
    // floating keyboard while that is up, so the panel takes the words over.
    if (osk_ != nullptr && osk_->panelVisible() &&
        pages_->currentIndex() == kVerifyPage) {
        osk_->setSuggestions(panelLabels);
    } else {
        if (osk_ != nullptr)
            osk_->setSuggestions(QStringList());
        for (int i = 0; i < panelLabels.size(); ++i)
            verifySuggestions_[i]->show();
    }
#endif
}

void CreateScreen::applyVerifySuggestion(int index)
{
#ifdef SIGNEROS_WORD_SUGGESTIONS
    if (index < 0 || index >= kSuggestionCount || verifySuggestions_[index] == nullptr)
        return;
    QByteArray word = verifySuggestions_[index]->property("word").toString().toLatin1();
    if (word.isEmpty())
        return;

    SecureString &typed = verificationBuffer();
    typed.setSlot(static_cast<std::size_t>(verifyCursor_), word.constData(),
                  static_cast<std::size_t>(word.size()));

    // The word is in the secure buffer now; scrub the copy Qt made for the
    // button label on its way there.
    secureWipe(word.data(), static_cast<std::size_t>(word.size()));

    // Accepting a suggestion finishes the cell, so it hands over to the next
    // one - which is what the separator used to do here.
    if (verifyCursor_ + 1 < static_cast<int>(mnemonicBuffer().wordCount()))
        verifySetCursor(verifyCursor_ + 1);
    else
        refreshVerify();
#else
    (void)index;
#endif
}

// ---------------------------------------------------------------------------
// Passphrase
// ---------------------------------------------------------------------------

void CreateScreen::passphraseType(char c)
{
    if (!isPrintableAscii(c))
        return;
    (passConfirming_ ? passphraseConfirmBuffer() : passphraseBuffer()).append(c);
    refreshPassphrase();
}

void CreateScreen::setPassphraseField(bool confirming)
{
    passConfirming_ = confirming && !passphraseBuffer().empty();
    refreshPassphrase();
}

void CreateScreen::refreshPassphrase()
{
    const SecureString &pass = passphraseBuffer();
    const std::size_t n = pass.size();
    const SecureString &again = passphraseConfirmBuffer();
    const std::size_t m = again.size();

    if (n == 0) {
        passDisplay_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
        passDisplay_->setText(
            QStringLiteral("no passphrase - the wallet is the words alone"));
        if (m > 0)
            passphraseConfirmBuffer().clear();
        passConfirming_ = false;
        passConfirmBox_->hide();
    } else {
        passDisplay_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::warn()));
        passDisplay_->setText(revealedSecret(pass) +
                              QStringLiteral("\n(%1 characters)").arg(n));

        if (m == 0) {
            passConfirmDisplay_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::textDim()));
            passConfirmDisplay_->setText(
                QStringLiteral("type the same passphrase again"));
        } else {
            passConfirmDisplay_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::warn()));
            passConfirmDisplay_->setText(revealedSecret(again) +
                                         QStringLiteral("\n(%1 characters)").arg(m));
        }
        passConfirmBox_->show();
    }

    // --- which card is lit, and what the second one has to say -------------
    theme::setCardFocused(passBox_, !passConfirming_);
    theme::setCardFocused(passConfirmBox_, passConfirming_);

    passCaption_->setText(QStringLiteral("PASSPHRASE  (optional)"));
    passCaption_->setStyleSheet(
        QStringLiteral("color: %1;")
            .arg(passConfirming_ ? theme::textDim() : theme::accent()));

    if (n > 0) {
        if (passphraseConfirmed()) {
            passConfirmCaption_->setText(
                QStringLiteral("PASSPHRASE AGAIN  -  MATCHES"));
            passConfirmCaption_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::ok()));
        } else if (m > 0) {
            passConfirmCaption_->setText(
                QStringLiteral("PASSPHRASE AGAIN  -  NOT THE SAME YET"));
            passConfirmCaption_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::danger()));
        } else {
            passConfirmCaption_->setText(QStringLiteral("PASSPHRASE AGAIN"));
            passConfirmCaption_->setStyleSheet(
                QStringLiteral("color: %1;")
                    .arg(passConfirming_ ? theme::accent() : theme::textDim()));
        }
    }

    const QString here = QStringLiteral("TYPING HERE");
    const QString away = osk_->panelVisible()
                             ? QStringLiteral("tap here to type")
                             : QStringLiteral("click here, or F3");
    auto hint = [&](QLabel *l, bool active) {
        l->setText(active ? here : away);
        l->setStyleSheet(QStringLiteral("color: %1;")
                             .arg(active ? theme::accent() : theme::textDim()));
    };
    hint(passHint_, !passConfirming_);
    hint(passConfirmHint_, passConfirming_);

    refreshEcho();
}

// Whether the passphrase page may be left.
//
// Leaving it EMPTY is a decision this page has already argued about at length
// above, so it is simply taken. What is not taken is a passphrase typed once
// and not confirmed: a wallet minted from a mistyped passphrase is a wallet
// whose owner cannot reproduce it, and nothing later can tell them so.
bool CreateScreen::passphraseReady()
{
    if (passphraseBuffer().empty())
        return true;

    if (!passphraseConfirmed()) {
        setPassphraseField(true);
        passError_->setText(
            QStringLiteral("The two entries are not the same. Both are shown "
                           "in clear above - compare them, and correct "
                           "whichever one is wrong."));
        passError_->show();
        return false;
    }
    passError_->hide();
    return true;
}

void CreateScreen::leavePassphrasePage()
{
    if (passphraseReady())
        goTo(kConfirmPage);
}

bool CreateScreen::eventFilter(QObject *watched, QEvent *event)
{
    if (event->type() == QEvent::MouseButtonPress) {
        if (watched == passBox_) {
            setPassphraseField(false);
            setFocus();
            return true;
        }
        if (watched == passConfirmBox_) {
            setPassphraseField(true);
            setFocus();
            return true;
        }
    }
    return QWidget::eventFilter(watched, event);
}

// ---------------------------------------------------------------------------
// Confirmation and writing
// ---------------------------------------------------------------------------

void CreateScreen::rebuildConfirm()
{
    while (QLayoutItem *item = confirmLayout_->takeAt(0)) {
        if (QWidget *w = item->widget())
            w->deleteLater();
        delete item;
    }
    confirmError_->hide();

    auto row = [&](QWidget *parent, const QString &key, const QString &value,
                   const char *colour) {
        auto *l = new QLabel(parent);
        l->setWordWrap(true);
        l->setFont(theme::monoFont(15));
        l->setText(QStringLiteral("<span style='color:%1'>%2</span>  "
                                  "<span style='color:%3'>%4</span>")
                       .arg(QString::fromLatin1(theme::textDim()), key.toHtmlEscaped(),
                            QString::fromLatin1(colour), value.toHtmlEscaped()));
        return l;
    };

    QFrame *box = theme::card(confirmContent_);
    auto *v = new QVBoxLayout(box);
    v->setContentsMargins(theme::px(14), theme::px(12), theme::px(14), theme::px(12));
    v->setSpacing(theme::px(6));

    auto *title = new QLabel(QStringLiteral("THE WALLET YOU ARE ABOUT TO CREATE"), box);
    title->setFont(theme::uiFont(13, true));
    title->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
    v->addWidget(title);

    v->addWidget(row(box, QStringLiteral("recovery words "),
                     QStringLiteral("%1, written down and verified")
                         .arg(mnemonicBuffer().wordCount()),
                     theme::ok()));
    v->addWidget(row(box, QStringLiteral("passphrase     "),
                     passphraseBuffer().empty()
                         ? QStringLiteral("none")
                         : QStringLiteral("%1 characters - see below")
                               .arg(passphraseBuffer().size()),
                     passphraseBuffer().empty() ? theme::text() : theme::warn()));
    v->addWidget(row(box, QStringLiteral("network        "),
                     QString::fromLatin1(networkName(app_->config().network)),
                     app_->config().network == Network::Mainnet ? theme::accent()
                                                                : theme::warn()));
    v->addWidget(row(box, QStringLiteral("account        "), QStringLiteral("0"),
                     theme::text()));
    v->addWidget(row(box, QStringLiteral("written to     "),
                     app_->config().dataDir, theme::text()));
    confirmLayout_->addWidget(box);

    // The passphrase, in clear, once. It is the one secret the operator has to
    // write down that they have not been shown plainly yet, and a passphrase
    // remembered incorrectly is exactly as lost as a seed written down
    // incorrectly.
    if (!passphraseBuffer().empty()) {
        QFrame *pbox = theme::card(confirmContent_);
        pbox->setObjectName(QStringLiteral("cardWarn"));
        auto *pv = new QVBoxLayout(pbox);
        pv->setContentsMargins(theme::px(14), theme::px(12), theme::px(14), theme::px(12));
        pv->setSpacing(theme::px(6));

        auto *pt = new QLabel(QStringLiteral("WRITE THIS DOWN TOO"), pbox);
        pt->setFont(theme::uiFont(13, true));
        pt->setStyleSheet(QStringLiteral("color: %1;").arg(theme::warn()));
        pv->addWidget(pt);

        auto *pval = new QLabel(revealedSecret(passphraseBuffer()), pbox);
        pval->setFont(theme::monoFont(20, true));
        pval->setWordWrap(true);
        pval->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        pv->addWidget(pval);

        pv->addWidget(theme::dim(
            QStringLiteral("Exactly these characters, including capitals and "
                           "spaces. A long passphrase is shown over several "
                           "lines - the line breaks are this screen wrapping "
                           "it, not part of it. Without it the recovery words "
                           "open a different, empty wallet."),
            pbox));
        confirmLayout_->addWidget(pbox);
    }

    confirmLayout_->addWidget(theme::sectionHeader(
        QStringLiteral("What the file will contain"), confirmContent_));

    QFrame *what = theme::card(confirmContent_);
    auto *wv = new QVBoxLayout(what);
    wv->setContentsMargins(theme::px(14), theme::px(12), theme::px(14), theme::px(12));
    wv->setSpacing(theme::px(4));
    wv->addWidget(theme::body(
        QStringLiteral(
            "One text file holding output descriptors and extended PUBLIC keys "
            "for four address types (BIP84 native segwit, BIP86 taproot, BIP49 "
            "nested segwit, BIP44 legacy), account 0.\n\n"
            "No private key, no seed and no passphrase is written - not to this "
            "file, not to any other, not now and not on shutdown."),
        what));
    confirmLayout_->addWidget(what);

    confirmLayout_->addStretch(1);

    // The stick may not be in yet. Rather than failing at the write, say so
    // here and let the mount poll enable the button when it appears.
    const bool mounted = app_->dataMounted();
    createBtn_->setEnabled(mounted);
    if (!mounted) {
        confirmError_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::warn()));
        confirmError_->setText(
            QStringLiteral("Insert the USB stick now - partition 2, labelled %1. "
                           "It is picked up automatically. Your words are still "
                           "in memory and nothing has been lost.")
                .arg(app_->config().dataLabel));
        confirmError_->show();
    }
}

// Derives the export, then asks what the file should be called. The words are
// still in memory here - the derivation needs them, and the operator can still
// go back - and they go the moment the file exists.
void CreateScreen::showNamePage()
{
    confirmError_->hide();

    std::string err;
    if (!buildWalletExport(mnemonicBuffer(), passphraseBuffer(),
                           app_->config().network, 0, &export_, &err)) {
        confirmError_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
        confirmError_->setText(qs(err));
        confirmError_->show();
        return;
    }

    const std::string dir = app_->config().dataDir.toStdString();
    namePage_->begin(
        QStringLiteral("Name the watch-only file"),
        QStringLiteral("master %1  -  account 0  -  %2")
            .arg(qs(export_.fingerprint),
                 QString::fromLatin1(networkName(app_->config().network))),
        qs(proposedWalletExportName(export_, dir)),
        app_->config().dataDir,
        QStringLiteral("Write the file"),
        !app_->config().physicalKeyboard);
    pages_->setCurrentIndex(kNamePage);
    osk_->setMode(OnScreenKeyboard::Mode::FullText);
    refreshEcho();
    setOskVisible(!app_->config().physicalKeyboard);
    setFocus();
}

void CreateScreen::doCreate()
{
    std::string err;
    std::string path;
    if (!writeWalletExport(export_, app_->config().dataDir.toStdString(),
                           namePage_->fileName().toStdString(), &path, &err)) {
        namePage_->setError(
            QStringLiteral("%1\n\nNothing has been written. Your recovery words "
                           "are still in memory - change the name, or fix the "
                           "stick, and write again.").arg(qs(err)));
        return;
    }

    // The seed goes now, before the result is drawn. Nothing about the outcome
    // needs it any more, and the next screen is about to tell the operator that
    // it is gone.
    wipeSecrets();

    // --- the result -------------------------------------------------------
    while (QLayoutItem *item = resultLayout_->takeAt(0)) {
        if (QWidget *w = item->widget())
            w->deleteLater();
        delete item;
    }

    resultHeading_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::ok()));
    resultHeading_->setText(QStringLiteral("Wallet created"));

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
    v->addWidget(theme::dim(
        QStringLiteral("Your recovery words have been wiped from this machine's "
                       "memory. The paper you wrote them on is now the only copy "
                       "in existence.\n\n"
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

        auto *t = new QLabel(QStringLiteral("%1  -  %2")
                                 .arg(qs(a.standard), qs(a.label)), ab);
        t->setFont(theme::uiFont(14, true));
        t->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
        av->addWidget(t);

        auto *path_ = new QLabel(QStringLiteral("%1   first address:").arg(qs(a.path)), ab);
        path_->setFont(theme::monoFont(13));
        path_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
        av->addWidget(path_);

        auto *addr = new QLabel(qs(a.firstAddress), ab);
        addr->setFont(theme::monoFont(a.firstAddress.size() > 50 ? 14 : 16, true));
        addr->setWordWrap(true);
        av->addWidget(addr);

        resultLayout_->addWidget(ab);
    }

    // Mentioned, not shown: a multisig cosigner key has no address, so it has
    // nothing to contribute to the check this section is for. The file it was
    // just written to explains what it is and what to do with it.
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
    pages_->setCurrentIndex(kResultPage);
}

// ---------------------------------------------------------------------------

void CreateScreen::wipeSecrets()
{
    passConfirming_ = false;

    wipeAllSecrets();
    verified_ = false;
    // The cells go with the text they described, so the next entry starts from
    // cell 1 of an empty grid rather than wherever the last one was abandoned.
    verifyCursor_ = 0;

    if (verifyNextBtn_ != nullptr)
        verifyNextBtn_->setEnabled(false);
    if (verifyDisplay_ != nullptr)
        verifyDisplay_->clear();
    if (passDisplay_ != nullptr)
        passDisplay_->clear();
    if (passConfirmDisplay_ != nullptr)
        passConfirmDisplay_->clear();
    if (seedView_ != nullptr)
        seedView_->update();
    if (verifyMask_ != nullptr) {
        verifyMask_->setErrorWords(0);
        verifyMask_->setActiveWord(-1);
        verifyMask_->update();
    }

    // Dictionary words left in button labels are public wordlist entries rather
    // than the secret, but they are fragments of it and do not get to outlive
    // the keystroke that produced them.
    for (int i = 0; i < kSuggestionCount; ++i) {
        if (verifySuggestions_[i] != nullptr) {
            verifySuggestions_[i]->setText(QString());
            verifySuggestions_[i]->hide();
        }
    }
}

// ---------------------------------------------------------------------------

void CreateScreen::keyPressEvent(QKeyEvent *event)
{
    const int k = event->key();
    const int page = pages_->currentIndex();

    // The save-as page is typed into through this screen, like every other
    // field here: this screen holds the focus and hands the keystrokes on.
    if (page == kNamePage) {
        if (k == Qt::Key_F2) {
            setOskVisible(!osk_->panelVisible());
            return;
        }
        if (namePage_->handleKey(event))
            return;
        QWidget::keyPressEvent(event);
        return;
    }

    // On the entropy page every keystroke is another sample: a machine with no
    // pointer at all can still fill the pool.
    if (page == kEntropyPage) {
        if (k == Qt::Key_Return || k == Qt::Key_Enter) {
            if (generateBtn_->isEnabled())
                generate();
            return;
        }
        // The key code, its modifiers and the moment it arrived. Deliberately
        // not QKeyEvent::text(): what is wanted here is the timing and the
        // fact of the press, and there is no reason to put the character into
        // a QString to get it.
        pool_.mixUserEvent(k, static_cast<int>(event->modifiers()), 0x4B45u);
        pad_->update();
        entropyBar_->setValue(pad_->percent());
        generateBtn_->setEnabled(pool_.userTargetReached());
        entropyHint_->setText(QStringLiteral("%1 of %2 movements collected.")
                                  .arg(pool_.userSamples())
                                  .arg(EntropyPool::kUserSampleTarget));
        return;
    }

    // The on-screen keyboard is off by default where a real one exists; F2 is
    // how a touchscreen laptop, or an operator who does not trust the keyboard
    // layout for a passphrase, gets it back.
    if (k == Qt::Key_F2 &&
        (page == kVerifyPage || page == kPassphrasePage || page == kNamePage)) {
        setOskVisible(!osk_->panelVisible());
        return;
    }

    if (page == kVerifyPage) {
#ifdef SIGNEROS_WORD_SUGGESTIONS
        int pick = -1;
        if (k >= Qt::Key_1 && k <= Qt::Key_1 + kSuggestionCount - 1)
            pick = k - Qt::Key_1;
        else if (k == Qt::Key_Tab)
            pick = 0;
        if (pick >= 0 && verifySuggestions_[pick] != nullptr &&
            verifySuggestions_[pick]->isVisible()) {
            applyVerifySuggestion(pick);
            return;
        }
        if (k == Qt::Key_Tab)
            return;   // never let Tab move focus off this screen
#endif
        if (k == Qt::Key_Backspace) {
            verifyBackspace();
            return;
        }
        if (k == Qt::Key_Space) {
            verifyType(' ');
            return;
        }
        if (k == Qt::Key_Return || k == Qt::Key_Enter) {
            // Enter is the first key everybody presses after a word, and doing
            // nothing with it reads as a frozen screen. It ends the word like
            // Space does, and only means "continue" once every word matches -
            // so it can never carry someone past a half-typed entry.
            if (verified_)
                goTo(kPassphrasePage);
            else
                verifyMoveCursor(1);
            return;
        }
        if (k == Qt::Key_Right) {
            verifyMoveCursor(1);
            return;
        }
        if (k == Qt::Key_Left) {
            verifyMoveCursor(-1);
            return;
        }
        // The grid is two-dimensional and so is the cursor now. A row is
        // whatever SeedView is currently drawing as one, asked rather than
        // assumed, so the two cannot disagree about where "down" is.
        if (k == Qt::Key_Down) {
            verifyMoveCursor(verifyMask_->columns());
            return;
        }
        if (k == Qt::Key_Up) {
            verifyMoveCursor(-verifyMask_->columns());
            return;
        }
        if (k == Qt::Key_Home) {
            verifySetCursor(0);
            return;
        }
        if (k == Qt::Key_End) {
            verifySetCursor(static_cast<int>(mnemonicBuffer().wordCount()) - 1);
            return;
        }
        if (k >= Qt::Key_A && k <= Qt::Key_Z) {
            verifyType(static_cast<char>('a' + (k - Qt::Key_A)));
            return;
        }
        QWidget::keyPressEvent(event);
        return;
    }

    if (page == kPassphrasePage) {
        if (k == Qt::Key_Backspace) {
            (passConfirming_ ? passphraseConfirmBuffer() : passphraseBuffer())
                .backspace();
            refreshPassphrase();
            return;
        }
        if (k == Qt::Key_F3) {
            setPassphraseField(!passConfirming_);
            return;
        }
        if (k == Qt::Key_Return || k == Qt::Key_Enter) {
            // Enter walks forward through the page the way it does everywhere
            // else here: into the second entry first, and only then onwards.
            if (!passConfirming_ && !passphraseBuffer().empty() &&
                !passphraseConfirmed()) {
                setPassphraseField(true);
                return;
            }
            leavePassphrasePage();
            return;
        }
        // Mapped from key codes rather than QKeyEvent::text(), so the character
        // never lands in a QString on its way into the secure buffer.
        const bool shifted = (event->modifiers() & Qt::ShiftModifier) != 0;
        if (k >= Qt::Key_A && k <= Qt::Key_Z) {
            const char base = static_cast<char>('a' + (k - Qt::Key_A));
            passphraseType(shifted ? static_cast<char>(base - 32) : base);
            return;
        }
        if (k >= Qt::Key_0 && k <= Qt::Key_9) {
            passphraseType(static_cast<char>('0' + (k - Qt::Key_0)));
            return;
        }
        if (k == Qt::Key_Space) {
            passphraseType(' ');
            return;
        }
        QWidget::keyPressEvent(event);
        return;
    }

    QWidget::keyPressEvent(event);
}

} // namespace signeros
