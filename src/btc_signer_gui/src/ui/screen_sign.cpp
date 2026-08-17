// SPDX-License-Identifier: MIT

#include "ui/screen_sign.h"

#include <QByteArray>
#include <QStringList>
#include <QEvent>
#include <QFrame>
#include <QHBoxLayout>
#include <QKeyEvent>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QStackedWidget>
#include <QTimer>
#include <QVBoxLayout>

#include <cstring>

#include "core/psbt_engine.h"
#include "core/secure_memory.h"
#include "ui/app_window.h"
#include "ui/secret_buffers.h"
#include "ui/theme.h"

namespace signeros {
namespace {

// The mnemonic and passphrase buffers this screen types into live in
// ui/secret_buffers.h, shared with the wallet creation screen. They used to be
// file-scope statics here, with a comment claiming there was exactly one of
// each in the address space; when a second screen needed a mnemonic buffer too,
// keeping that claim true meant moving them somewhere both could reach rather
// than writing the comment twice. See secret_buffers.h.

QString qs(const std::string &s)
{
    return QString::fromStdString(s);
}

bool isBip39Char(char c)
{
    return (c >= 'a' && c <= 'z') || c == ' ';
}

bool isBase58Char(char c)
{
    if (c == '0' || c == 'O' || c == 'I' || c == 'l')
        return false;
    return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
}

bool isPrintableAscii(char c)
{
    return c >= 0x20 && c <= 0x7e;
}

} // namespace

// ---------------------------------------------------------------------------

SignScreen::SignScreen(AppWindow *app, QWidget *parent) : QWidget(parent), app_(app)
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(0, 0, 0, 0);

    pages_ = new QStackedWidget(this);
    pages_->addWidget(buildEntryPage());     // kEntryPage
    pages_->addWidget(buildConfirmPage());   // kConfirmPage

    // kNamePage. The signature already exists and the secrets are already gone
    // by the time this is shown; all it decides is what the file is called.
    namePage_ = new SaveAsPage(this);
    connect(namePage_, &SaveAsPage::back, this, [this]() {
        // Back from here cannot mean "unsign": it means "do not write it after
        // all", and that is the end of this transaction.
        app_->showScan();
    });
    connect(namePage_, &SaveAsPage::keyboardRequested, this,
            [this](bool on) { setOskVisible(on); });
    connect(namePage_, &SaveAsPage::accepted, this, &SignScreen::doWrite);
    pages_->addWidget(namePage_);

    pages_->addWidget(buildResultPage());    // kResultPage
    v->addWidget(pages_);

    // The on-screen keyboard floats over whichever page is showing rather than
    // living in one of them; see ui/osk_panel.h for why. One per screen: this
    // screen already decides where a physical keystroke goes, and the panel is
    // just another source of the same keystrokes.
    osk_ = new OskPanel(this);
    connect(osk_, &OskPanel::characterTyped, this, &SignScreen::typeCharacter);
    connect(osk_, &OskPanel::backspacePressed, this, &SignScreen::backspace);
    connect(osk_, &OskPanel::deleteWordPressed, this, &SignScreen::deleteWord);
    connect(osk_, &OskPanel::clearAllPressed, this, &SignScreen::clearAll);
    connect(osk_, &OskPanel::hideRequested, this, [this]() { setOskVisible(false); });
    connect(osk_, &OskPanel::suggestionChosen, this, &SignScreen::applySuggestion);

    // The caret exists to say "your keystrokes land here", so it runs exactly
    // when that is true. Tied to the page rather than started and stopped by
    // each caller, so no path off the entry page can leave it blinking behind
    // the confirmation screen.
    connect(pages_, &QStackedWidget::currentChanged, this, [this](int index) {
        if (index == kEntryPage) {
            caretOn_ = true;
            caretTimer_->start();
            applyCaret();
        } else {
            caretTimer_->stop();
        }
    });
}

SignScreen::~SignScreen()
{
    // Belt and braces: the buffers are static and wiped by wipeSecrets(), but a
    // teardown path that skipped it must not leave a mnemonic in memory.
    wipeSecrets();
}

QWidget *SignScreen::buildEntryPage()
{
    auto *page = new QWidget(this);
    auto *v = new QVBoxLayout(page);
    v->setContentsMargins(24, 14, 24, 16);
    v->setSpacing(8);

    v->addWidget(theme::heading(QStringLiteral("Enter your key to sign"), page));

    // A one-line restatement of what is being authorised. The operator has just
    // read the detail on the previous screen; this is here so that the thing
    // they are typing a seed into never stops naming the transaction.
    reminder_ = new QLabel(page);
    reminder_->setFont(theme::monoFont(15));
    reminder_->setWordWrap(true);
    reminder_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
    v->addWidget(reminder_);

    v->addWidget(theme::hLine(page));

    // --- key source -----------------------------------------------------
    auto *sourceRow = new QHBoxLayout;
    sourceRow->setSpacing(10);
    sourceMnemonicBtn_ = theme::secondaryButton(QStringLiteral("BIP39 mnemonic"), page);
    sourceMnemonicBtn_->setCheckable(true);
    sourceMnemonicBtn_->setChecked(true);
    connect(sourceMnemonicBtn_, &QPushButton::clicked, this,
            [this]() { setKeySource(KeySource::Mnemonic); });
    sourceRow->addWidget(sourceMnemonicBtn_);

    sourceXprvBtn_ = theme::secondaryButton(QStringLiteral("Extended private key"), page);
    sourceXprvBtn_->setCheckable(true);
    connect(sourceXprvBtn_, &QPushButton::clicked, this,
            [this]() { setKeySource(KeySource::Xprv); });
    sourceRow->addWidget(sourceXprvBtn_);
    sourceRow->addStretch(1);

    v->addLayout(sourceRow);

    // --- the two fields, both on screen at once --------------------------
    //
    // This used to be one card, and which of the two secrets your keystrokes
    // went into was decided by a pair of "Typing: key / Typing: passphrase"
    // toggle buttons up in the row above - a tab strip in all but name. Two
    // things were wrong with it, both reported from real use:
    //
    //   * the passphrase was somewhere you had to know to go and look, so a
    //     wallet that has one looks like a wallet whose seed does not work;
    //   * nothing about the card said it was a text field at all. The screen
    //     keeps the keyboard focus itself and routes characters into a
    //     SecureString (see buildEntryPage's focus rule below), so Qt draws no
    //     focus ring and no caret, and an operator whose typing was already
    //     going to the right place had no way to know that.
    //
    // So: two cards, both visible whenever they apply, the active one carrying
    // an accent border, an accent caption and a blinking caret, and either one
    // reachable by clicking it. F3 still switches from the keyboard.
    mnemonicBox_ = theme::card(page);
    auto *eb = new QVBoxLayout(mnemonicBox_);
    eb->setContentsMargins(14, 10, 14, 12);
    eb->setSpacing(4);

    auto *mnemonicCap = new QHBoxLayout;
    mnemonicCap->setSpacing(10);
    mnemonicCaption_ = new QLabel(mnemonicBox_);
    mnemonicCaption_->setFont(theme::uiFont(13, true));
    mnemonicCap->addWidget(mnemonicCaption_);
    mnemonicCap->addStretch(1);
    mnemonicHint_ = new QLabel(mnemonicBox_);
    mnemonicHint_->setFont(theme::uiFont(13, true));
    mnemonicCap->addWidget(mnemonicHint_);
    eb->addLayout(mnemonicCap);

    mnemonicDisplay_ = new QLabel(mnemonicBox_);
    mnemonicDisplay_->setFont(theme::monoFont(20, true));
    mnemonicDisplay_->setWordWrap(true);
    mnemonicDisplay_->setMinimumHeight(theme::px(56));
    mnemonicDisplay_->setAlignment(Qt::AlignLeft | Qt::AlignTop);
    eb->addWidget(mnemonicDisplay_);

    mnemonicMeta_ = new QLabel(mnemonicBox_);
    mnemonicMeta_->setFont(theme::uiFont(14));
    mnemonicMeta_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    eb->addWidget(mnemonicMeta_);

    v->addWidget(mnemonicBox_);

    // --- passphrase, in clear, and again ---------------------------------
    //
    // Two decisions here that a signer has to justify.
    //
    // FIRST, the passphrase is shown as it is typed rather than as blocks. A
    // machine that hides what it captured is worse than one that shows it: this
    // one reads every keyboard as US (Qt's evdev keyboard has a built-in US
    // keymap and no .qmap is shipped), so a passphrase typed on a QWERTZ or
    // Turkish-Q keyboard is captured as different characters. Nothing validates
    // a passphrase - any bytes are legal - so the only symptom is "this key
    // signs none of the inputs", which reads as "my seed is wrong" and is a
    // dead end on a box with no shell. It used to be behind a "Show" toggle
    // that had to be found; the toggle is gone and the characters are simply
    // there. The room this machine is in is the operator's problem, and it is
    // the problem they can actually solve.
    //
    // SECOND, it is typed twice. That used to be argued against here, on the
    // grounds that double entry catches a slip while the failure that actually
    // happens is a keyboard layout - and you would type the same wrong
    // characters both times. The argument was right about layouts and wrong to
    // conclude anything from it: showing the characters is what catches a
    // layout, and the two checks catch different things. A passphrase is the
    // one secret on this machine with no checksum behind it, so it gets both.
    //
    // The bounded concession is unchanged: rendering a secret puts it in a
    // QString, which is heap memory this process does not wipe - the same is
    // already true of the mnemonic word shown while it is being typed, and
    // shutdown scrubs free memory before the machine powers off.
    auto buildSecretCard = [page, v](QFrame **box, QLabel **caption,
                                     QLabel **hint, QLabel **display) {
        *box = theme::card(page);
        auto *pv = new QVBoxLayout(*box);
        pv->setContentsMargins(14, 10, 14, 12);
        pv->setSpacing(4);

        auto *row = new QHBoxLayout;
        row->setSpacing(10);
        *caption = new QLabel(*box);
        (*caption)->setFont(theme::uiFont(13, true));
        row->addWidget(*caption);
        row->addStretch(1);
        *hint = new QLabel(*box);
        (*hint)->setFont(theme::uiFont(13, true));
        row->addWidget(*hint);
        pv->addLayout(row);

        *display = new QLabel(*box);
        (*display)->setFont(theme::monoFont(18, true));
        (*display)->setWordWrap(true);
        // A passphrase on screen does not get a vote on how wide this page is:
        // it has no spaces to wrap at, and a long one would raise the minimum
        // width of every page this screen holds. See revealedSecret().
        (*display)->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        pv->addWidget(*display);

        v->addWidget(*box);
    };

    buildSecretCard(&passphraseBox_, &passphraseCaption_, &passphraseHint_,
                    &passphraseDisplay_);
    auto *signPassWarning = theme::dim(
        QStringLiteral("Warning: Any passphrase produces a valid wallet. A typo will not give an error, "
                       "it will generate a completely different, empty wallet."),
        passphraseBox_);
    signPassWarning->setFont(theme::uiFont(12));
    signPassWarning->setWordWrap(true);
    signPassWarning->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    passphraseBox_->layout()->addWidget(signPassWarning);

    buildSecretCard(&confirmBox_, &confirmCaption_, &confirmHint_, &confirmDisplay_);
    confirmBox_->hide();

    // Clicking a card is how a pointer chooses a field. The labels inside are
    // made transparent to the mouse so that the press lands on the frame the
    // filter is watching, rather than on whichever line of text happened to be
    // under the finger.
    for (QFrame *box : {mnemonicBox_, passphraseBox_, confirmBox_}) {
        box->installEventFilter(this);
        const QList<QLabel *> inner = box->findChildren<QLabel *>();
        for (QLabel *l : inner)
            l->setAttribute(Qt::WA_TransparentForMouseEvents, true);
    }

    // The caret blinks only while this page is showing; the connection in the
    // constructor starts and stops it with the page.
    caretTimer_ = new QTimer(this);
    caretTimer_->setInterval(530);
    connect(caretTimer_, &QTimer::timeout, this, [this]() {
        caretOn_ = !caretOn_;
        applyCaret();
    });

    // --- BIP39 word suggestions -----------------------------------------
#ifdef SIGNEROS_WORD_SUGGESTIONS
    auto *sugRow = new QHBoxLayout;
    sugRow->setSpacing(8);
    for (int i = 0; i < kSuggestionCount; ++i) {
        suggestions_[i] = theme::secondaryButton(QString(), page);
        suggestions_[i]->setFont(theme::monoFont(17, true));
        suggestions_[i]->setMinimumWidth(80);
        suggestions_[i]->setFocusPolicy(Qt::NoFocus);
        suggestions_[i]->hide();
        connect(suggestions_[i], &QPushButton::clicked, this,
                [this, i]() { applySuggestion(i); });
        sugRow->addWidget(suggestions_[i], 1);
    }
    v->addLayout(sugRow);
#endif

    keyStatus_ = new QLabel(page);
    keyStatus_->setFont(theme::uiFont(15, true));
    keyStatus_->setWordWrap(true);
    v->addWidget(keyStatus_);

    error_ = new QLabel(page);
    error_->setFont(theme::uiFont(15, true));
    error_->setWordWrap(true);
    error_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
    error_->hide();
    v->addWidget(error_);

    // --- what this transaction pays -------------------------------------
    //
    // The same facts the inspect screen showed, kept in front of the operator
    // while they type the seed. This screen used to summarise the whole
    // transaction in one line and give the rest of the display to a keyboard,
    // which put the moment of maximum consequence - entering the key, pressing
    // Sign - at the maximum distance from the destination address. On a machine
    // with a real keyboard that space is free, and this is what it is for.
    payingBox_ = theme::card(page);
    auto *pb = new QVBoxLayout(payingBox_);
    pb->setContentsMargins(14, 10, 14, 10);
    pb->setSpacing(4);

    QLabel *payingTitle = new QLabel(QStringLiteral("PAYING"), payingBox_);
    payingTitle->setFont(theme::uiFont(13, true));
    payingTitle->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
    pb->addWidget(payingTitle);

    payingLabel_ = new QLabel(payingBox_);
    payingLabel_->setFont(theme::monoFont(15));
    payingLabel_->setWordWrap(true);
    payingLabel_->setTextInteractionFlags(Qt::NoTextInteraction);
    pb->addWidget(payingLabel_);
    // The card grows to fill the space the keyboard is not using; its contents
    // stay at the top rather than being spread down the whole height.
    pb->addStretch(1);

    // payingBox_ is added to swapArea below, not to this layout.

    // The payment summary gets the space the keyboard used to compete for: the
    // keyboard is a layer over the page now, not a row in it (ui/osk_panel.h).
    v->addWidget(payingBox_, 1);

    // --- actions ---------------------------------------------------------
    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(12);

    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), page);
    connect(back, &QPushButton::clicked, this, [this]() {
        wipeSecrets();
        app_->showInspect();
    });
    buttons->addWidget(back);

    oskToggle_ = theme::secondaryButton(QStringLiteral("On-screen keys (F2)"), page);
    oskToggle_->setCheckable(true);
    connect(oskToggle_, &QPushButton::clicked, this,
            [this](bool on) { setOskVisible(on); });
    buttons->addWidget(oskToggle_);

    buttons->addStretch(1);

    checkBtn_ = theme::secondaryButton(QStringLiteral("Check key"), page);
    connect(checkBtn_, &QPushButton::clicked, this, &SignScreen::checkKey);
    buttons->addWidget(checkBtn_);

    // Not "Sign": nothing on this page signs. It leads to the confirmation
    // page, which is the only place the transaction can be authorised.
    signBtn_ = theme::primaryButton(QStringLiteral("Review and sign"), page);
    signBtn_->setEnabled(false);
    connect(signBtn_, &QPushButton::clicked, this, &SignScreen::showConfirm);
    buttons->addWidget(signBtn_);

    hint_ = new QLabel(page);
    hint_->setFont(theme::uiFont(13));
    hint_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
    hint_->setAlignment(Qt::AlignRight);
    v->addWidget(hint_);

    v->addLayout(buttons);

    // Nothing on this page may hold the keyboard focus.
    //
    // If a button did, a physical keystroke would go to it instead of into the
    // secure buffer - and Space activates a focused QPushButton, so typing a
    // word separator would re-trigger whichever button was clicked last. With
    // every button set to NoFocus, SignScreen keeps the focus itself and
    // keyPressEvent() is the single path for typed input. Keyboard-only
    // operation still works: type, Enter checks the key, Enter again signs,
    // Escape goes back.
    const QList<QPushButton *> pageButtons = page->findChildren<QPushButton *>();
    for (QPushButton *b : pageButtons)
        b->setFocusPolicy(Qt::NoFocus);
    setFocusPolicy(Qt::StrongFocus);

    return page;
}

QWidget *SignScreen::buildConfirmPage()
{
    auto *page = new QWidget(this);
    auto *v = new QVBoxLayout(page);
    v->setContentsMargins(24, 16, 24, 20);
    v->setSpacing(10);

    v->addWidget(theme::heading(QStringLiteral("Confirm what you are about to sign"), page));

    confirmScroll_ = new QScrollArea(page);
    confirmScroll_->setWidgetResizable(true);
    confirmScroll_->setFrameShape(QFrame::NoFrame);
    confirmScroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    // A QScrollArea takes WheelFocus by default, which made it the only
    // focusable widget on this page and therefore the one Qt handed the focus
    // to when the page appeared - after showConfirm() had asked for it. The
    // symptom was that the first Enter here did nothing and the second signed.
    // Every button on this page is already NoFocus; this closes the last gap,
    // so the screen keeps the focus and keyPressEvent stays the only path.
    confirmScroll_->setFocusPolicy(Qt::NoFocus);

    confirmContent_ = new QWidget(confirmScroll_);
    confirmLayout_ = new QVBoxLayout(confirmContent_);
    confirmLayout_->setContentsMargins(0, 0, 0, 0);
    confirmLayout_->setSpacing(10);
    confirmScroll_->setWidget(confirmContent_);
    confirmScroll_->setAlignment(Qt::AlignHCenter | Qt::AlignTop);
    confirmContent_->setMaximumWidth(theme::px(1040));
    v->addWidget(confirmScroll_, 1);

    // A refusal from sign() has to be legible on the page the operator is
    // standing on. It used to be written into the entry page's error label,
    // which is not this page - so a blocked signature looked like a button that
    // did nothing.
    confirmError_ = new QLabel(page);
    confirmError_->setFont(theme::uiFont(15, true));
    confirmError_->setWordWrap(true);
    confirmError_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
    confirmError_->hide();
    v->addWidget(confirmError_);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(12);

    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), page);
    connect(back, &QPushButton::clicked, this, [this]() {
        pages_->setCurrentIndex(kEntryPage);
        setFocus();
    });
    buttons->addWidget(back);
    buttons->addStretch(1);

    confirmSignBtn_ = theme::primaryButton(QStringLiteral("Sign now"), page);
    connect(confirmSignBtn_, &QPushButton::clicked, this, &SignScreen::doSign);
    buttons->addWidget(confirmSignBtn_);

    v->addLayout(buttons);

    // Same rule as the entry page: no widget here may hold the focus, so this
    // screen's keyPressEvent stays the only path for a keystroke.
    const QList<QPushButton *> pageButtons = page->findChildren<QPushButton *>();
    for (QPushButton *b : pageButtons)
        b->setFocusPolicy(Qt::NoFocus);

    return page;
}

// Rebuilt from the summary on every entry: this page exists to state verified
// facts, and a stale widget is not a verified fact.
void SignScreen::rebuildConfirm()
{
    while (QLayoutItem *item = confirmLayout_->takeAt(0)) {
        if (QWidget *w = item->widget())
            w->deleteLater();
        delete item;
    }

    const TxSummary &s = app_->engine().summary();

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

    auto amount = [](std::uint64_t sat) {
        return QStringLiteral("%1 BTC   (%2 sat)")
            .arg(qs(formatBtc(sat)), qs(formatSat(sat)));
    };

    // --- the headline: what actually leaves this wallet -------------------
    {
        QFrame *box = theme::card(confirmContent_);
        auto *v = new QVBoxLayout(box);
        v->setContentsMargins(14, 12, 14, 12);
        v->setSpacing(6);

        auto *title = new QLabel(QStringLiteral("LEAVING YOUR WALLET"), box);
        title->setFont(theme::uiFont(13, true));
        title->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
        v->addWidget(title);

        auto *big = new QLabel(amount(s.leavingSat), box);
        big->setFont(theme::monoFont(22, true));
        big->setWordWrap(true);
        big->setStyleSheet(QStringLiteral("color: %1;").arg(theme::accent()));
        v->addWidget(big);

        v->addWidget(row(box, QStringLiteral("of which miner fee"),
                         s.feeKnown ? amount(s.feeSat)
                                    : QStringLiteral("CANNOT BE DETERMINED"),
                         s.feeKnown ? theme::text() : theme::danger()));
        v->addWidget(row(box, QStringLiteral("verified change back"),
                         amount(s.verifiedChangeSat), theme::ok()));
        v->addWidget(row(box, QStringLiteral("signing key"),
                         QStringLiteral("master %1  -  signs %2 of %3 input(s)")
                             .arg(qs(app_->engine().masterFingerprint()))
                             .arg(s.signableInputs)
                             .arg(s.inputs.size()),
                         theme::text()));
        confirmLayout_->addWidget(box);
    }

    // --- every output, in verified terms ----------------------------------
    confirmLayout_->addWidget(
        theme::sectionHeader(QStringLiteral("Where the money goes"), confirmContent_));

    for (std::size_t i = 0; i < s.outputs.size(); ++i) {
        const OutputInfo &o = s.outputs[i];

        QFrame *box = theme::card(confirmContent_);
        if (o.ownership == OutputOwnership::Mismatch)
            box->setObjectName(QStringLiteral("cardDanger"));

        auto *v = new QVBoxLayout(box);
        v->setContentsMargins(14, 10, 14, 10);
        v->setSpacing(4);

        QString label;
        const char *colour = theme::accent();
        if (o.isOpReturn) {
            label = QStringLiteral("DATA (OP_RETURN, unspendable)");
            colour = theme::textDim();
        } else {
            switch (o.ownership) {
            case OutputOwnership::Verified:
                label = QStringLiteral("COMES BACK TO YOU  -  verified change");
                colour = theme::ok();
                break;
            case OutputOwnership::Unverifiable:
                label = QStringLiteral("CLAIMS TO BE YOURS  -  could not be proved");
                colour = theme::warn();
                break;
            case OutputOwnership::Mismatch:
                label = QStringLiteral("FORGED CHANGE LABEL  -  not your address");
                colour = theme::danger();
                break;
            default:
                label = QStringLiteral("LEAVES YOUR WALLET  -  payment out");
                break;
            }
        }

        auto *t = new QLabel(QStringLiteral("Output %1  -  %2").arg(i + 1).arg(label), box);
        t->setFont(theme::uiFont(14, true));
        t->setStyleSheet(QStringLiteral("color: %1;").arg(colour));
        v->addWidget(t);

        auto *addr = new QLabel(qs(o.address), box);
        addr->setFont(theme::monoFont(o.address.size() > 60 ? 14 : 16, true));
        addr->setWordWrap(true);
        v->addWidget(addr);

        v->addWidget(row(box, QStringLiteral("amount"), amount(o.amountSat), theme::text()));
        if (o.ownership == OutputOwnership::Verified && !o.derivation.empty())
            v->addWidget(row(box, QStringLiteral("path  "), qs(o.derivation), theme::ok()));

        confirmLayout_->addWidget(box);
    }

    // --- anything the engine wants said before an irreversible act --------
    bool anyNote = false;
    for (const Finding &f : s.findings) {
        if (f.severity == Severity::Info)
            continue;
        if (!anyNote) {
            confirmLayout_->addWidget(theme::sectionHeader(
                QStringLiteral("Before you sign"), confirmContent_));
            anyNote = true;
        }

        QFrame *box = theme::card(confirmContent_);
        if (f.severity == Severity::Danger)
            box->setObjectName(QStringLiteral("cardDanger"));

        auto *v = new QVBoxLayout(box);
        v->setContentsMargins(14, 10, 14, 10);
        auto *text = new QLabel(qs(f.text), box);
        text->setFont(theme::uiFont(14));
        text->setWordWrap(true);
        text->setStyleSheet(QStringLiteral("color: %1;")
                                .arg(f.severity == Severity::Danger ? theme::danger()
                                                                    : theme::warn()));
        v->addWidget(text);
        confirmLayout_->addWidget(box);
    }

    confirmLayout_->addStretch(1);

    // The engine refuses on its own too; disabling the button means the refusal
    // is visible before the operator commits to it rather than after.
    confirmSignBtn_->setEnabled(s.safeToSign && s.signableInputs > 0);
}

void SignScreen::showConfirm()
{
    if (!keyChecked_) {
        showError(QStringLiteral("Check the key first."));
        return;
    }

    confirmError_->hide();
    rebuildConfirm();
    pages_->setCurrentIndex(kConfirmPage);
    confirmScroll_->verticalScrollBar()->setValue(0);
    setFocus();
}

QWidget *SignScreen::buildResultPage()
{
    auto *page = new QWidget(this);
    auto *v = new QVBoxLayout(page);
    v->setContentsMargins(40, 40, 40, 40);
    v->setSpacing(16);

    v->addStretch(1);

    resultHeading_ = new QLabel(page);
    resultHeading_->setFont(theme::uiFont(30, true));
    resultHeading_->setWordWrap(true);
    resultHeading_->setAlignment(Qt::AlignCenter);
    v->addWidget(resultHeading_);

    resultDetail_ = new QLabel(page);
    resultDetail_->setFont(theme::monoFont(16));
    resultDetail_->setWordWrap(true);
    resultDetail_->setAlignment(Qt::AlignCenter);
    v->addWidget(resultDetail_);

    v->addStretch(1);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(12);
    buttons->addStretch(1);

    QPushButton *another = theme::secondaryButton(QStringLiteral("Sign another"), page);
    connect(another, &QPushButton::clicked, app_, &AppWindow::showScan);
    buttons->addWidget(another);

    QPushButton *off = theme::primaryButton(QStringLiteral("Secure shutdown"), page);
    connect(off, &QPushButton::clicked, app_, &AppWindow::showShutdown);
    buttons->addWidget(off);

    buttons->addStretch(1);
    v->addLayout(buttons);

    return page;
}

// ---------------------------------------------------------------------------

void SignScreen::resizeEvent(QResizeEvent *event)
{
    QWidget::resizeEvent(event);
    if (osk_ != nullptr && osk_->panelVisible())
        osk_->reposition();
}

void SignScreen::onEnter()
{
    pages_->setCurrentIndex(kEntryPage);
    keyChecked_ = false;
    signBtn_->setEnabled(false);
    keyStatus_->clear();
    error_->hide();
    confirmError_->hide();
    setField(Field::Mnemonic);
    setKeySource(KeySource::Mnemonic);

    refreshReminder();

    // A real keyboard means the on-screen one is not needed and its space goes
    // to the transaction. F2 brings it back for a touchscreen laptop, and for
    // entering a passphrase without trusting the keyboard's layout.
    setOskVisible(!app_->config().physicalKeyboard);
    hint_->setText(app_->config().physicalKeyboard
        ? QStringLiteral("type the words  ·  1-5 or Tab picks a suggestion  ·  "
                         "F3 or a click on another box switches field  ·  "
                         "Enter checks the key, then reviews  ·  F2 on-screen keys  ·  "
                         "Esc back")
        : QStringLiteral("Esc back  ·  F12 shutdown"));

    refreshPaying();
    refreshDisplays();

    caretOn_ = true;
    caretTimer_->start();
    applyCaret();

    setFocus();
}

SaveAsPage *SignScreen::activeSaveAsPage() const
{
    return pages_->currentIndex() == kNamePage ? namePage_ : nullptr;
}

void SignScreen::onLeave()
{
    caretTimer_->stop();
    wipeSecrets();
}

void SignScreen::wipeSecrets()
{
    wipeAllSecrets();
    app_->engine().clearKey();
    keyChecked_ = false;

    // Clear any dictionary word left in a widget's QString too. Those are
    // public wordlist entries rather than the secret itself, but they are
    // fragments of it, so they do not get to linger on screen or in Qt's heap
    // any longer than the keystroke that produced them.
    for (int i = 0; i < kSuggestionCount; ++i) {
        if (suggestions_[i] != nullptr) {
            suggestions_[i]->setText(QString());
            suggestions_[i]->hide();
        }
    }
    // The composed forms of the two display lines hold the same fragments the
    // labels do - the word being typed, a revealed passphrase - so they go at
    // the same moment.
    mnemonicShown_.clear();
    mnemonicSuffix_.clear();
    passphraseShown_.clear();
    passphraseSuffix_.clear();
    confirmShown_.clear();
    confirmSuffix_.clear();
    if (mnemonicDisplay_ != nullptr)
        mnemonicDisplay_->clear();
    if (passphraseDisplay_ != nullptr)
        passphraseDisplay_->clear();
    if (confirmDisplay_ != nullptr)
        confirmDisplay_->clear();
    if (signBtn_ != nullptr)
        signBtn_->setEnabled(false);
}

void SignScreen::setField(Field f)
{
    // The confirmation field exists only while there is something to confirm.
    if (f == Field::Confirm &&
        (source_ != KeySource::Mnemonic || passphraseBuffer().empty()))
        f = Field::Passphrase;
    if (f == Field::Passphrase && source_ != KeySource::Mnemonic)
        f = Field::Mnemonic;

    field_ = f;
    osk_->setMode(f == Field::Mnemonic && source_ == KeySource::Mnemonic
                      ? OnScreenKeyboard::Mode::Bip39
                      : OnScreenKeyboard::Mode::FullText);
    // Restart the blink on the visible half of its cycle: a field switch that
    // happened to land during the off phase would otherwise show a caret in
    // neither box for up to half a second, which is the exact confusion the
    // caret is here to remove.
    caretOn_ = true;
    refreshDisplays();
}

void SignScreen::setOskVisible(bool visible)
{
    oskVisible_ = visible;
    oskToggle_->setChecked(visible);
    osk_->setPanelVisible(visible);
    namePage_->setKeyboardShown(visible);
    // The hint line lists physical-keyboard shortcuts. It is not useful on the
    // machine that reached for the on-screen keys, and the panel covers that
    // corner of the page anyway.
    hint_->setVisible(!visible);
    refreshDisplays();
}

void SignScreen::refreshPaying()
{
    const TxSummary &s = app_->engine().summary();

    QString text;
    for (const OutputInfo &o : s.outputs) {
        if (o.isOpReturn)
            continue;

        // Before a key is entered nothing can be called change, so an output
        // that says it is one is reported as a claim. After it, the label is
        // the verified one. Saying "PAYMENT OUT" about an operator's own change
        // is what makes a correct transaction look like a theft.
        QString tag;
        switch (o.ownership) {
        case OutputOwnership::Verified:     tag = QStringLiteral("change back to you"); break;
        case OutputOwnership::Claimed:      tag = QStringLiteral("claims to be your change"); break;
        case OutputOwnership::Unverifiable: tag = QStringLiteral("claim unproved"); break;
        case OutputOwnership::Mismatch:     tag = QStringLiteral("FORGED CHANGE LABEL"); break;
        case OutputOwnership::ThirdParty:   tag = QStringLiteral("PAYMENT OUT"); break;
        }

        text += QStringLiteral("%1  %2  %3\n")
                    .arg(qs(o.address).isEmpty() ? QStringLiteral("(no address)")
                                                 : qs(o.address),
                         -46)
                    .arg(qs(formatBtc(o.amountSat)), 14)
                    .arg(tag);
    }
    text += QStringLiteral("\nfee %1 BTC")
                .arg(qs(s.feeKnown ? formatBtc(s.feeSat) : std::string("unknown")));

    payingLabel_->setText(text);
}

// The one-line restatement above the key entry. Recomputed after "Check key",
// because until then change cannot be told apart from a payment out and this
// line would count an operator's own change as money they are sending away.
void SignScreen::refreshReminder()
{
    const TxSummary &s = app_->engine().summary();

    std::size_t payments = 0;
    for (const OutputInfo &o : s.outputs)
        if (!o.isVerifiedChange() && !o.isOpReturn)
            ++payments;

    reminder_->setText(
        s.ownershipChecked
            ? QStringLiteral("Signing %1  -  %2 BTC leaving this wallet across %3 "
                             "output(s), fee %4 sat")
                  .arg(qs(app_->engine().sourceName()),
                       qs(formatBtc(s.leavingSat)))
                  .arg(payments)
                  .arg(qs(s.feeKnown ? formatSat(s.feeSat) : std::string("unknown")))
            : QStringLiteral("Signing %1  -  %2 BTC to %3 output(s), fee %4 sat  "
                             "(change is identified once you check your key)")
                  .arg(qs(app_->engine().sourceName()),
                       qs(formatBtc(s.totalOutSat)))
                  .arg(payments)
                  .arg(qs(s.feeKnown ? formatSat(s.feeSat) : std::string("unknown"))));
}

void SignScreen::setKeySource(KeySource s)
{
    if (source_ != s) {
        // Changing what is being entered invalidates whatever was typed. Wiping
        // is the only correct response: half a mnemonic re-read as an xprv is
        // meaningless and keeping it around is just a secret with no purpose.
        mnemonicBuffer().clear();
        keyChecked_ = false;
        signBtn_->setEnabled(false);
        keyStatus_->clear();
    }
    source_ = s;
    sourceMnemonicBtn_->setChecked(s == KeySource::Mnemonic);
    sourceXprvBtn_->setChecked(s == KeySource::Xprv);
    if (s == KeySource::Xprv && field_ == Field::Passphrase)
        setField(Field::Mnemonic);
    else
        setField(field_);
}

// ---------------------------------------------------------------------------

// Which buffer the next keystroke lands in. The three fields are the three
// buffers of secret_buffers.h and nothing else on this screen decides between
// them, so there is one place to look when a character goes somewhere
// surprising.
SecureString &SignScreen::activeBuffer()
{
    switch (field_) {
    case Field::Passphrase: return passphraseBuffer();
    case Field::Confirm:    return passphraseConfirmBuffer();
    default:                return mnemonicBuffer();
    }
}

void SignScreen::typeCharacter(char c)
{
    // The floating keyboard is the screen's, not a page's, so it lands
    // wherever the physical keyboard would land - including the save-as page.
    if (pages_->currentIndex() == kNamePage) {
        namePage_->typeCharacter(c);
        refreshEcho();
        return;
    }

    SecureString &target = activeBuffer();

    bool allowed = false;
    if (field_ != Field::Mnemonic)
        allowed = isPrintableAscii(c);
    else if (source_ == KeySource::Mnemonic)
        allowed = isBip39Char(c);
    else
        allowed = isBase58Char(c);

    if (!allowed)
        return;

    // Any edit invalidates a previous "Check key".
    if (keyChecked_) {
        keyChecked_ = false;
        signBtn_->setEnabled(false);
        keyStatus_->clear();
        app_->engine().clearKey();
    }

    if (!target.append(c)) {
        showError(QStringLiteral("That is as much text as this field holds "
                                "(%1 characters). A 24-word mnemonic needs far "
                                "less, so something has gone wrong.")
                      .arg(SecureString::capacity() - 1));
        return;
    }
    error_->hide();
    refreshDisplays();
}

void SignScreen::backspace()
{
    if (pages_->currentIndex() == kNamePage) {
        namePage_->backspace();
        refreshEcho();
        return;
    }
    activeBuffer().backspace();
    keyChecked_ = false;
    signBtn_->setEnabled(false);
    keyStatus_->clear();
    refreshDisplays();
}

void SignScreen::deleteWord()
{
    if (pages_->currentIndex() == kNamePage) {
        namePage_->clearName();
        refreshEcho();
        return;
    }
    activeBuffer().backspaceWord();
    keyChecked_ = false;
    signBtn_->setEnabled(false);
    keyStatus_->clear();
    refreshDisplays();
}

void SignScreen::clearAll()
{
    if (pages_->currentIndex() == kNamePage) {
        namePage_->clearName();
        refreshEcho();
        return;
    }
    activeBuffer().clear();
    keyChecked_ = false;
    signBtn_->setEnabled(false);
    keyStatus_->clear();
    error_->hide();
    refreshDisplays();
}

void SignScreen::keyPressEvent(QKeyEvent *event)
{
    // Physical keyboard support, mapped from key codes rather than
    // QKeyEvent::text(): that keeps the character out of a QString on its way
    // into the secure buffer.
    const int k = event->key();

    // Off the entry page there is nothing to type into. A letter arriving on
    // the confirmation page must not reach the mnemonic buffer: it would edit
    // the key behind a screen that is showing what that key just verified.
    // Escape and F12 fall through to AppWindow as everywhere else.
    if (pages_->currentIndex() != kEntryPage) {
        if (pages_->currentIndex() == kConfirmPage &&
            (k == Qt::Key_Return || k == Qt::Key_Enter)) {
            if (confirmSignBtn_->isEnabled())
                doSign();
            return;
        }
        // The save-as page is typed into through this screen, like every other
        // field in the application: this screen holds the focus and hands the
        // keystrokes on. See ui/save_as.h.
        if (pages_->currentIndex() == kNamePage) {
            if (k == Qt::Key_F2) {
                setOskVisible(!osk_->panelVisible());
                return;
            }
            if (namePage_->handleKey(event))
                return;
        }
        QWidget::keyPressEvent(event);
        return;
    }

    if (k == Qt::Key_F2) {
        setOskVisible(!oskVisible_);
        return;
    }

    // Every button on this page is unfocusable so that Space reaches the secure
    // buffer (see buildEntryPage). The cost of that is a field switcher only a
    // pointer can reach, which leaves a wallet with a passphrase unusable on a
    // machine driven by the keyboard - so the switch has a key of its own.
    // Not Enter: Enter already means "check this key", and that meaning is
    // load-bearing on the screen that leads to signing.
    //
    // It cycles rather than toggles now that there can be three fields, and
    // skips the confirmation while there is no passphrase to confirm - setField
    // does that part, so the cycle cannot land somewhere that is not on screen.
    if (k == Qt::Key_F3 && source_ == KeySource::Mnemonic) {
        switch (field_) {
        case Field::Mnemonic:   setField(Field::Passphrase); break;
        case Field::Passphrase: setField(passphraseBuffer().empty()
                                             ? Field::Mnemonic
                                             : Field::Confirm); break;
        case Field::Confirm:    setField(Field::Mnemonic); break;
        }
        return;
    }

#ifdef SIGNEROS_WORD_SUGGESTIONS
    // 1-5 and Tab accept a suggested word. Confined to the mnemonic field of a
    // mnemonic entry, where a digit cannot be part of what is being typed - the
    // BIP39 wordlist is letters only. An xprv is base58 and a passphrase is
    // anything at all, so in those fields the digits below still type.
    if (source_ == KeySource::Mnemonic && field_ == Field::Mnemonic) {
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
        // Enter never signs from here. It checks the key, then moves on to the
        // confirmation page; signing takes a second, deliberate Enter there.
        if (keyChecked_)
            showConfirm();
        else
            checkKey();
        return;
    }
    if (k >= Qt::Key_A && k <= Qt::Key_Z) {
        const bool shifted = (event->modifiers() & Qt::ShiftModifier) != 0;
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

// ---------------------------------------------------------------------------

void SignScreen::refreshDisplays()
{
    SecureString &key = mnemonicBuffer();

    if (source_ == KeySource::Mnemonic) {
        // Completed words are shown as three dots each - a fixed count, so the
        // display does not even leak word lengths. The word being typed is
        // shown in clear, because a signer that will not let you see the
        // character you just pressed is a signer people mistype seeds into.
        char current[16] = {};
        const std::size_t currentLen = key.copyTrailingWord(current, sizeof(current));
        const std::size_t words = key.wordCount();
        const std::size_t completed = (currentLen > 0 && words > 0) ? words - 1 : words;

        QString shown;
        for (std::size_t i = 0; i < completed; ++i)
            shown += QStringLiteral("... ");
        if (currentLen > 0)
            shown += QString::fromLatin1(current, static_cast<int>(currentLen));

        mnemonicPlaceholder_ = shown.isEmpty();
        if (mnemonicPlaceholder_) {
            mnemonicShown_.clear();
            mnemonicSuffix_ = app_->config().physicalKeyboard
                ? QStringLiteral("  type your 12 or 24 recovery words, "
                                 "a space between each")
                : QStringLiteral("  tap the keys below to enter your "
                                 "12 or 24 recovery words");
        } else {
            mnemonicShown_ = shown;
            mnemonicSuffix_.clear();
        }
        secureWipe(current, sizeof(current));

        const bool plausible = (words == 12 || words == 15 || words == 18 ||
                                words == 21 || words == 24);
        mnemonicMeta_->setText(
            QStringLiteral("%1 word(s)%2")
                .arg(words)
                .arg(plausible ? QStringLiteral("  -  a valid BIP39 length")
                               : QStringLiteral("  -  BIP39 needs 12, 15, 18, 21 or 24")));
    } else {
        // An xprv is not a secret you can usefully proof-read on a panel, and it
        // is one long token: dots only, with a length count.
        mnemonicPlaceholder_ = key.empty();
        if (mnemonicPlaceholder_) {
            mnemonicShown_.clear();
            mnemonicSuffix_ = QStringLiteral("  enter an xprv / tprv");
        } else {
            mnemonicShown_ = QString(static_cast<int>(qMin<std::size_t>(key.size(), 96)),
                                     QLatin1Char('*'));
            mnemonicSuffix_.clear();
        }
        mnemonicMeta_->setText(QStringLiteral("%1 character(s)").arg(key.size()));
    }

    const SecureString &pass = passphraseBuffer();
    const std::size_t plen = pass.size();
    if (source_ == KeySource::Mnemonic) {
        if (plen == 0) {
            // An empty passphrase is the normal case, so this line says so
            // rather than looking like something that has not been filled in
            // yet - and, when it is not the active field, says how to get to
            // it. The passphrase is the field people forget exists.
            passphrasePlaceholder_ = true;
            passphraseShown_.clear();
            passphraseSuffix_ = (field_ == Field::Passphrase)
                ? QStringLiteral("  type it now, or leave this empty")
                : QStringLiteral("  none - leave empty unless your wallet has one");
            passphraseDisplay_->setStyleSheet(QString());
        } else {
            // In clear. See buildEntryPage for why a signer does this.
            passphrasePlaceholder_ = false;
            passphraseDisplay_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::warn()));
            passphraseShown_ = revealedSecret(pass);
            passphraseSuffix_ = QStringLiteral("\n(%1 characters)").arg(plen);
        }
        passphraseBox_->show();
    } else {
        // Nothing to enter: an xprv is already derived past the passphrase.
        passphraseBox_->hide();
    }

    // --- and the same passphrase, typed again ----------------------------
    const SecureString &again = passphraseConfirmBuffer();
    const std::size_t clen = again.size();
    if (source_ == KeySource::Mnemonic && plen > 0) {
        if (clen == 0) {
            confirmPlaceholder_ = true;
            confirmShown_.clear();
            confirmSuffix_ = QStringLiteral("  type the same passphrase again");
            confirmDisplay_->setStyleSheet(QString());
        } else {
            confirmPlaceholder_ = false;
            confirmShown_ = revealedSecret(again);
            confirmSuffix_ = QStringLiteral("\n(%1 characters)").arg(clen);
            confirmDisplay_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::warn()));
        }
        confirmBox_->show();
    } else {
        // Nothing typed to confirm. The buffer goes too: a confirmation left
        // over from a passphrase that has since been cleared would otherwise
        // sit in memory saying nothing about anything.
        if (clen > 0)
            passphraseConfirmBuffer().clear();
        confirmBox_->hide();
        if (field_ == Field::Confirm)
            field_ = Field::Passphrase;
    }

    refreshFieldChrome();
    applyCaret();
    refreshEcho();
    refreshSuggestions();
}

// The keyboard panel covers the bottom of the page, which on a short screen is
// the card being typed into. So the panel repeats it: which field, and what is
// in it, on the line directly above the keys.
void SignScreen::refreshEcho()
{
    if (osk_ == nullptr)
        return;

    if (pages_->currentIndex() == kNamePage) {
        osk_->setEcho(QStringLiteral("FILE NAME"), namePage_->fileName(), nullptr);
        return;
    }

    switch (field_) {
    case Field::Passphrase:
        osk_->setEcho(QStringLiteral("PASSPHRASE"),
                      passphrasePlaceholder_ ? QString() : passphraseShown_,
                      theme::warn());
        break;
    case Field::Confirm:
        osk_->setEcho(QStringLiteral("PASSPHRASE AGAIN"),
                      confirmPlaceholder_ ? QString() : confirmShown_,
                      passphraseConfirmed() ? theme::ok() : theme::warn());
        break;
    default:
        osk_->setEcho(source_ == KeySource::Mnemonic
                          ? QStringLiteral("RECOVERY WORDS")
                          : QStringLiteral("EXTENDED PRIVATE KEY"),
                      mnemonicPlaceholder_ ? QString() : mnemonicShown_,
                      nullptr);
        break;
    }
}

// Which of the two cards keystrokes are going into. Everything here is
// redundant with everything else here on purpose: the border, the caption
// colour and the caret all say the same thing, because on the one screen where
// a mistake costs coins, one signal being missed must not be enough.
void SignScreen::refreshFieldChrome()
{
    const bool havePassphraseField = (source_ == KeySource::Mnemonic);
    const bool haveConfirmField = havePassphraseField && !passphraseBuffer().empty();

    theme::setCardFocused(mnemonicBox_, field_ == Field::Mnemonic);
    theme::setCardFocused(passphraseBox_, field_ == Field::Passphrase);
    theme::setCardFocused(confirmBox_, field_ == Field::Confirm);

    mnemonicCaption_->setText(havePassphraseField
        ? QStringLiteral("RECOVERY WORDS")
        : QStringLiteral("EXTENDED PRIVATE KEY"));
    passphraseCaption_->setText(QStringLiteral("PASSPHRASE  (optional)"));

    auto captionColour = [](QLabel *l, bool active) {
        l->setStyleSheet(QStringLiteral("color: %1;")
                             .arg(active ? theme::accent() : theme::textDim()));
    };
    captionColour(mnemonicCaption_, field_ == Field::Mnemonic);
    captionColour(passphraseCaption_, field_ == Field::Passphrase);

    // The confirmation card's caption is the verdict: whether the two entries
    // are the same is the only thing it exists to say, so it says it where the
    // eye already is rather than in a status line further down.
    const bool matches = passphraseConfirmed();
    const bool confirmStarted = !passphraseConfirmBuffer().empty();
    if (haveConfirmField) {
        if (matches) {
            confirmCaption_->setText(QStringLiteral("PASSPHRASE AGAIN  -  MATCHES"));
            confirmCaption_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::ok()));
        } else if (confirmStarted) {
            confirmCaption_->setText(
                QStringLiteral("PASSPHRASE AGAIN  -  NOT THE SAME YET"));
            confirmCaption_->setStyleSheet(
                QStringLiteral("color: %1;").arg(theme::danger()));
        } else {
            confirmCaption_->setText(QStringLiteral("PASSPHRASE AGAIN"));
            captionColour(confirmCaption_, field_ == Field::Confirm);
        }
    }

    // The inactive card says how to get into it, in the terms of whichever
    // input the machine actually has. With no passphrase field there is nowhere
    // else for a keystroke to go, so none of the hints is worth the line noise.
    const QString here = QStringLiteral("TYPING HERE");
    const QString away = oskVisible_ ? QStringLiteral("tap here to type")
                                     : QStringLiteral("click here, or F3");

    auto hint = [&](QLabel *l, bool active) {
        l->setVisible(havePassphraseField);
        l->setText(active ? here : away);
        l->setStyleSheet(QStringLiteral("color: %1;")
                             .arg(active ? theme::accent() : theme::textDim()));
    };
    hint(mnemonicHint_, field_ == Field::Mnemonic);
    hint(passphraseHint_, field_ == Field::Passphrase);
    hint(confirmHint_, field_ == Field::Confirm);
}

// Whether the passphrase may be derived from yet.
//
// An EMPTY passphrase is simply accepted - most wallets have none, and a
// "are you sure?" step in front of the common case is a step everybody learns
// to press past. What cannot be accepted is a passphrase that has been typed
// once and not confirmed: that one is a slip nothing downstream can catch.
bool SignScreen::passphraseReady()
{
    if (source_ != KeySource::Mnemonic || passphraseBuffer().empty())
        return true;

    if (!passphraseConfirmed()) {
        setField(Field::Confirm);
        showError(QStringLiteral(
            "The passphrase and its repeat are not the same. Both are shown "
            "in clear above - compare them, and correct whichever one is "
            "wrong."));
        return false;
    }
    return true;
}

// Draws the caret into the text of the active field's label.
//
// A painted caret would have to know where the last glyph of a wrapped,
// proportionally-laid-out line ended up; appending a character to the string
// gets that from the layout for free. The off phase of the blink is a space,
// which is the same width in this monospaced font, so nothing reflows as it
// blinks.
void SignScreen::applyCaret()
{
    const QChar block(0x2588);   // FULL BLOCK - a caret readable across a room

    auto paint = [&](QLabel *label, bool active, bool placeholder,
                     const QString &shown, const QString &suffix) {
        const QString caret = active
            ? QString(caretOn_ ? block : QChar(QLatin1Char(' ')))
            : QString();

        if (placeholder) {
            // A prompt contains no secret, so this line - and only this line -
            // may be rich text: it is what lets the caret keep the accent
            // colour while the prompt behind it stays dim.
            label->setTextFormat(Qt::RichText);
            label->setText(
                QStringLiteral("<span style='color:%1'>%2</span>"
                               "<span style='color:%3'>%4</span>")
                    .arg(QString::fromLatin1(theme::accent()),
                         active ? (caretOn_ ? QString(block)
                                            : QStringLiteral("&nbsp;"))
                                : QString(),
                         QString::fromLatin1(theme::textDim()),
                         suffix.toHtmlEscaped()));
            return;
        }

        // Everything else on these two labels is derived from the secret being
        // typed, so it is set as plain text explicitly and can never be
        // interpreted as markup.
        label->setTextFormat(Qt::PlainText);
        label->setText(shown + caret + suffix);
    };

    paint(mnemonicDisplay_, field_ == Field::Mnemonic, mnemonicPlaceholder_,
          mnemonicShown_, mnemonicSuffix_);
    paint(passphraseDisplay_, field_ == Field::Passphrase, passphrasePlaceholder_,
          passphraseShown_, passphraseSuffix_);
    paint(confirmDisplay_, field_ == Field::Confirm, confirmPlaceholder_,
          confirmShown_, confirmSuffix_);
}

bool SignScreen::eventFilter(QObject *watched, QEvent *event)
{
    // A click anywhere on a card puts the typing there. This is the whole of
    // the pointer half of the field switch now that the "Typing:" toggle
    // buttons are gone - the target is the card the operator is already
    // looking at, rather than a control somewhere else on the screen.
    if (event->type() == QEvent::MouseButtonPress) {
        if (watched == mnemonicBox_) {
            setField(Field::Mnemonic);
            setFocus();
            return true;
        }
        if (watched == passphraseBox_ && source_ == KeySource::Mnemonic) {
            setField(Field::Passphrase);
            setFocus();
            return true;
        }
        if (watched == confirmBox_ && source_ == KeySource::Mnemonic) {
            setField(Field::Confirm);
            setFocus();
            return true;
        }
    }
    return QWidget::eventFilter(watched, event);
}

void SignScreen::refreshSuggestions()
{
#ifdef SIGNEROS_WORD_SUGGESTIONS
    for (int i = 0; i < kSuggestionCount; ++i) {
        if (suggestions_[i] == nullptr)
            continue;
        suggestions_[i]->setText(QString());
        suggestions_[i]->hide();
    }

    QStringList panelLabels;

    if (source_ == KeySource::Mnemonic && field_ == Field::Mnemonic) {
        char prefix[16] = {};
        const std::size_t len = mnemonicBuffer().copyTrailingWord(prefix, sizeof(prefix));
        if (len > 0) {
            std::vector<std::string> words;
            bip39Suggestions(prefix, kSuggestionCount, &words);
            secureWipe(prefix, sizeof(prefix));

            // The label carries the accelerator; the word itself is kept in a
            // property so applySuggestion() never has to parse it back out of
            // display text.
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

    // Whichever of the two rows the operator can actually reach. The page's own
    // row is underneath the floating keyboard while that is up, so the panel
    // takes the words over and the page's row stays hidden - the alternative is
    // the same five words in two places, one of them invisible.
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

void SignScreen::applySuggestion(int index)
{
#ifdef SIGNEROS_WORD_SUGGESTIONS
    if (index < 0 || index >= kSuggestionCount || suggestions_[index] == nullptr)
        return;
    QByteArray word = suggestions_[index]->property("word").toString().toLatin1();
    if (word.isEmpty())
        return;

    SecureString &key = mnemonicBuffer();
    key.backspaceWord();
    key.append(word.constData(), static_cast<std::size_t>(word.size()));
    key.append(' ');

    // The word is now in the secure buffer; scrub the copy Qt made for the
    // button label on its way there.
    secureWipe(word.data(), static_cast<std::size_t>(word.size()));

    keyChecked_ = false;
    signBtn_->setEnabled(false);
    keyStatus_->clear();
    refreshDisplays();
#else
    (void)index;
#endif
}

// ---------------------------------------------------------------------------

void SignScreen::showError(const QString &text)
{
    error_->setText(text);
    error_->show();
}

void SignScreen::checkKey()
{
    error_->hide();
    keyStatus_->clear();
    keyChecked_ = false;
    signBtn_->setEnabled(false);

    SecureString &key = mnemonicBuffer();
    if (key.empty()) {
        showError(QStringLiteral("Nothing entered yet."));
        return;
    }

    // The passphrase gate comes before the derivation, not after: deriving with
    // a passphrase the operator has not confirmed produces a wallet that is
    // wrong in a way this machine cannot see.
    if (!passphraseReady())
        return;

    std::string err;
    bool ok = false;
    if (source_ == KeySource::Mnemonic) {
        key.normaliseWhitespace();
        ok = app_->engine().setKeyFromMnemonic(key, passphraseBuffer(), &err);
    } else {
        key.normaliseWhitespace();
        ok = app_->engine().setKeyFromXprv(key, &err);
    }

    if (!ok) {
        showError(qs(err));
        return;
    }

    const TxSummary &s = app_->engine().summary();
    const bool canSign = s.signableInputs > 0;

    keyStatus_->setStyleSheet(QStringLiteral("color: %1;")
                                  .arg(canSign ? theme::ok() : theme::danger()));
    keyStatus_->setText(
        canSign
            ? QStringLiteral("Master fingerprint %1  -  this key signs %2 of %3 input(s). "
                             "Check the fingerprint matches your wallet, then sign.")
                  .arg(qs(app_->engine().masterFingerprint()))
                  .arg(s.signableInputs)
                  .arg(s.inputs.size())
            // The last cause on this list is the one nobody guesses, and on a
            // machine with no shell there is nothing else to go on. Qt's evdev
            // keyboard uses a built-in US keymap unless it is given one, and
            // this image ships none - so on a QWERTZ, AZERTY or Turkish-Q
            // keyboard the letters are mapped by position. A mnemonic survives
            // that (a wrong word fails BIP39 validation and you can see the
            // word you typed), but a passphrase takes any character silently,
            // and the only symptom is the message you are reading now.
            : QStringLiteral("Master fingerprint %1  -  this key signs NONE of the %2 "
                             "input(s). The derivation paths in this transaction "
                             "belong to another master key: different wallet, "
                             "different passphrase, wrong network (currently %3), "
                             "or a passphrase typed on a non-US keyboard layout - "
                             "this machine reads every keyboard as US, so read "
                             "the passphrase back off the screen character by "
                             "character, or enter it with the on-screen keys.")
                  .arg(qs(app_->engine().masterFingerprint()))
                  .arg(s.inputs.size())
                  .arg(QString::fromLatin1(networkName(app_->config().network))));

    // The key changes what is knowable about this transaction: which outputs
    // are really change, and therefore how much is actually leaving. Both of
    // these were computed without a key when the screen was entered, so both
    // are restated now rather than left standing as the pre-key guess.
    refreshPaying();
    refreshReminder();

    keyChecked_ = canSign;
    signBtn_->setEnabled(canSign && s.safeToSign);

    // A forged change label can only be detected once there is a key to derive
    // from, so this is the first moment the safety gate can fail. Say why here;
    // the operator would otherwise be left with a button that does nothing.
    if (canSign && !s.safeToSign)
        showError(QStringLiteral("Signing is blocked: %1.").arg(qs(s.blockReason)));
}

// Signs, wipes, and hands over to the save-as page. Nothing is written here.
//
// The order matters and is the reason these are two functions. Once sign() has
// returned, the signature is in the PSBT in memory and the mnemonic has no
// further part to play - so it goes immediately, and the page that asks what to
// call the file runs with no key material in the process at all. A write that
// then fails can be retried from that page, because the only thing it needs is
// a name.
void SignScreen::doSign()
{
    error_->hide();
    confirmError_->hide();

    if (!keyChecked_) {
        confirmError_->setText(QStringLiteral("Check the key first."));
        confirmError_->show();
        return;
    }

    std::size_t added = 0;
    std::string err;
    if (!app_->engine().sign(&added, &err)) {
        confirmError_->setText(qs(err));
        confirmError_->show();
        return;
    }

    signedInputs_ = added;
    signedTotal_ = app_->engine().summary().inputs.size();
    signedFingerprint_ = qs(app_->engine().masterFingerprint());

    wipeSecrets();

    const std::string dir = app_->config().dataDir.toStdString();
    namePage_->begin(
        QStringLiteral("Name the signed transaction"),
        QStringLiteral("%1 of %2 input(s) signed with master %3. Nothing has "
                       "been written yet.")
            .arg(signedInputs_).arg(signedTotal_).arg(signedFingerprint_),
        qs(app_->engine().proposedResultName(dir)),
        app_->config().dataDir,
        QStringLiteral("Save to the stick"),
        !app_->config().physicalKeyboard);
    pages_->setCurrentIndex(kNamePage);
    // A file name is typed with the full keyboard, and the panel echoes it.
    osk_->setMode(OnScreenKeyboard::Mode::FullText);
    osk_->setSuggestions(QStringList());
    refreshEcho();
    setOskVisible(!app_->config().physicalKeyboard);
    setFocus();
}

void SignScreen::doWrite()
{
    std::string psbtPath, txPath, err;
    const bool wrote = app_->engine().writeResult(
        app_->config().dataDir.toStdString(),
        namePage_->fileName().toStdString(),
        app_->config().writeFinalTx,
        &psbtPath, &txPath, &err);

    if (!wrote) {
        // Still recoverable, and this is the page to recover on: the signature
        // is made and the secrets are gone, so all that is left is a name and a
        // stick.
        namePage_->setError(
            QStringLiteral("%1\n\nNothing has been written. The transaction is "
                           "still signed in memory - change the name, or put the "
                           "stick back, and save again.").arg(qs(err)));
        return;
    }

    const QString name = QString::fromStdString(
        psbtPath.substr(psbtPath.find_last_of('/') + 1));
    const QString fingerprint = signedFingerprint_;
    const std::size_t added = signedInputs_;
    const std::size_t total = signedTotal_;

    resultHeading_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::ok()));
    resultHeading_->setText(QStringLiteral("Signed"));

    QString detail =
        // Counted as "added of total", not against summary().signableInputs.
        // That figure is read after sign() has run, by which point the inputs
        // this key just signed no longer count as signable - so a completely
        // successful signing reported "2 signature(s) added for 0 of 2
        // input(s)", which reads as a failure on the one screen that exists to
        // say it worked.
        QStringLiteral("%1 of %2 input(s) signed\n"
                       "master fingerprint %3\n\n"
                       "written to\n%4\n")
            .arg(added)
            .arg(total)
            .arg(fingerprint, name);

    if (!txPath.empty())
        detail += QStringLiteral("\nbroadcast-ready transaction also written to\n%1\n")
                      .arg(QString::fromStdString(
                          txPath.substr(txPath.find_last_of('/') + 1)));

    detail += QStringLiteral(
        "\nYour key has been wiped from memory.\n"
        "Shut down before removing the USB stick - the shutdown flushes the "
        "partition and scrubs free memory.");

    resultDetail_->setText(detail);
    pages_->setCurrentIndex(kResultPage);
}

} // namespace signeros
