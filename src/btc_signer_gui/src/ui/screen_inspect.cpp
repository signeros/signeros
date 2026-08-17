// SPDX-License-Identifier: MIT

#include "ui/screen_inspect.h"

#include <QFrame>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QScrollBar>
#include <QVBoxLayout>

#include "ui/app_window.h"
#include "ui/theme.h"

namespace signeros {
namespace {

QString qs(const std::string &s)
{
    return QString::fromStdString(s);
}

// "0.00123456 BTC  (123 456 sat)" - both units, always. People check the one
// they think in, and the mismatch between units is a classic loss.
QString amountText(std::uint64_t sat)
{
    return QStringLiteral("%1 BTC   (%2 sat)")
        .arg(qs(formatBtc(sat)), qs(formatSat(sat)));
}

QLabel *fieldRow(const QString &key, const QString &value, QWidget *parent,
                 bool monoValue = true, const char *valueColour = nullptr)
{
    auto *l = new QLabel(parent);
    l->setWordWrap(true);
    l->setFont(monoValue ? theme::monoFont(15) : theme::uiFont(15));
    QString colour = valueColour ? QString::fromLatin1(valueColour)
                                 : QString::fromLatin1(theme::text());
    l->setText(QStringLiteral("<span style='color:%1'>%2</span>  "
                              "<span style='color:%3'>%4</span>")
                   .arg(QString::fromLatin1(theme::textDim()), key.toHtmlEscaped(),
                        colour, value.toHtmlEscaped()));
    return l;
}

} // namespace

InspectScreen::InspectScreen(AppWindow *app, QWidget *parent)
    : QWidget(parent), app_(app)
{
    auto *v = new QVBoxLayout(this);
    v->setContentsMargins(24, 16, 24, 20);
    v->setSpacing(10);

    v->addWidget(theme::heading(QStringLiteral("Review before signing"), this));

    scroll_ = new QScrollArea(this);
    scroll_->setWidgetResizable(true);
    scroll_->setFrameShape(QFrame::NoFrame);
    scroll_->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);

    content_ = new QWidget(scroll_);
    contentLayout_ = new QVBoxLayout(content_);
    contentLayout_->setContentsMargins(0, 0, 8, 0);
    contentLayout_->setSpacing(8);
    scroll_->setWidget(content_);
    // A scrolled column rather than the full width of the glass. Text set across
    // 1920 pixels is not read, it is scanned - and this is the screen where
    // every character of an address is supposed to be checked.
    scroll_->setAlignment(Qt::AlignHCenter | Qt::AlignTop);
    content_->setMaximumWidth(theme::px(1040));
    v->addWidget(scroll_, 1);

    blockLabel_ = new QLabel(this);
    blockLabel_->setFont(theme::uiFont(16, true));
    blockLabel_->setWordWrap(true);
    blockLabel_->setStyleSheet(QStringLiteral("color: %1;").arg(theme::danger()));
    blockLabel_->hide();
    v->addWidget(blockLabel_);

    auto *buttons = new QHBoxLayout;
    buttons->setSpacing(12);

    QPushButton *back = theme::secondaryButton(QStringLiteral("Back"), this);
    connect(back, &QPushButton::clicked, app_, &AppWindow::showScan);
    buttons->addWidget(back);

    // Explicit scroll buttons. A resistive touchscreen has no scroll wheel and
    // flick gestures are unreliable on cheap panels; a long transaction must
    // still be fully readable.
    QPushButton *up = theme::secondaryButton(QStringLiteral("Page up"), this);
    up->setAutoRepeat(true);
    connect(up, &QPushButton::clicked, this, [this]() { scrollBy(-320); });
    buttons->addWidget(up);

    QPushButton *down = theme::secondaryButton(QStringLiteral("Page down"), this);
    down->setAutoRepeat(true);
    connect(down, &QPushButton::clicked, this, [this]() { scrollBy(320); });
    buttons->addWidget(down);

    buttons->addStretch(1);

    signBtn_ = theme::primaryButton(QStringLiteral("Sign this transaction"), this);
    connect(signBtn_, &QPushButton::clicked, app_, &AppWindow::showSign);
    buttons->addWidget(signBtn_);

    v->addLayout(buttons);
}

void InspectScreen::scrollBy(int pixels)
{
    QScrollBar *bar = scroll_->verticalScrollBar();
    bar->setValue(bar->value() + pixels);
}

void InspectScreen::clearContent()
{
    // Rebuild from scratch every time: partial updates of a screen whose whole
    // job is to be trustworthy are not worth the risk of a stale row.
    while (QLayoutItem *item = contentLayout_->takeAt(0)) {
        if (QWidget *w = item->widget())
            w->deleteLater();
        delete item;
    }
}

void InspectScreen::onEnter()
{
    clearContent();

    if (!app_->engine().isLoaded()) {
        contentLayout_->addWidget(theme::body(QStringLiteral("No PSBT is loaded."), content_));
        signBtn_->setEnabled(false);
        return;
    }

    addSummary();
    addFindings();
    addOutputs();     // where the money goes comes first: it is what matters
    addInputs();
    contentLayout_->addStretch(1);

    const TxSummary &s = app_->engine().summary();
    signBtn_->setEnabled(s.safeToSign);
    if (!s.safeToSign) {
        blockLabel_->setText(
            QStringLiteral("Signing is blocked: %1.").arg(qs(s.blockReason)));
        blockLabel_->show();
    } else {
        blockLabel_->hide();
    }

    scroll_->verticalScrollBar()->setValue(0);
}

void InspectScreen::addSummary()
{
    const TxSummary &s = app_->engine().summary();

    contentLayout_->addWidget(theme::sectionHeader(QStringLiteral("Summary"), content_));

    QFrame *box = theme::card(content_);
    auto *g = new QVBoxLayout(box);
    g->setContentsMargins(14, 12, 14, 12);
    g->setSpacing(6);

    g->addWidget(fieldRow(QStringLiteral("file"),
                          qs(app_->engine().sourceName()), box));
    g->addWidget(fieldRow(QStringLiteral("network"),
                          QString::fromLatin1(networkName(app_->config().network)), box,
                          false,
                          app_->config().network == Network::Mainnet ? theme::accent()
                                                                     : theme::warn()));
    g->addWidget(fieldRow(QStringLiteral("txid (unsigned)"), qs(s.txid), box));
    g->addWidget(fieldRow(QStringLiteral("format"),
                          QStringLiteral("PSBT v%1 (%2), tx version %3, locktime %4")
                              .arg(s.psbtVersion)
                              .arg(s.psbtVersion == 2 ? QStringLiteral("BIP370")
                                                      : QStringLiteral("BIP174"))
                              .arg(s.txVersion)
                              .arg(s.locktime),
                          box, false));

    g->addWidget(theme::hLine(box));

    g->addWidget(fieldRow(QStringLiteral("spending  "),
                          amountText(s.totalInSat), box));
    g->addWidget(fieldRow(QStringLiteral("to outputs"),
                          amountText(s.totalOutSat), box));

    // What actually leaves the wallet is the number people mean when they ask
    // "how much am I sending?", and it cannot be known before a key is entered:
    // until then there is no way to tell change from a payment out.
    if (s.ownershipChecked) {
        g->addWidget(fieldRow(QStringLiteral("your change"),
                              amountText(s.verifiedChangeSat), box, true, theme::ok()));
        g->addWidget(fieldRow(QStringLiteral("leaving you"),
                              amountText(s.leavingSat), box, true, theme::accent()));
    } else {
        g->addWidget(fieldRow(QStringLiteral("leaving you"),
                              QStringLiteral("not yet known - change is identified "
                                             "once you enter your key"),
                              box, false, theme::textDim()));
    }

    if (s.feeKnown) {
        const char *feeColour =
            (s.feeRate > 100.0) ? theme::danger()
            : (s.feeRate > 30.0) ? theme::warn()
                                 : theme::text();
        g->addWidget(fieldRow(QStringLiteral("miner fee "),
                              amountText(s.feeSat), box, true, feeColour));
        g->addWidget(fieldRow(QStringLiteral("fee rate  "),
                              QStringLiteral("%1 sat/vB  (approx. %2 vbytes signed)")
                                  .arg(qs(formatFeeRate(s.feeRate)))
                                  .arg(s.estimatedVsize),
                              box, true, feeColour));
    } else {
        g->addWidget(fieldRow(QStringLiteral("miner fee "),
                              QStringLiteral("CANNOT BE DETERMINED"), box, true,
                              theme::danger()));
    }

    contentLayout_->addWidget(box);
}

void InspectScreen::addFindings()
{
    const TxSummary &s = app_->engine().summary();
    if (s.findings.empty())
        return;

    contentLayout_->addWidget(
        theme::sectionHeader(QStringLiteral("Things to check"), content_));

    for (const Finding &f : s.findings) {
        QFrame *box = theme::card(content_);
        const char *colour = theme::textDim();
        QString tag = QStringLiteral("NOTE");
        if (f.severity == Severity::Warning) {
            box->setObjectName(QStringLiteral("cardWarn"));
            colour = theme::warn();
            tag = QStringLiteral("CHECK");
        } else if (f.severity == Severity::Danger) {
            box->setObjectName(QStringLiteral("cardDanger"));
            colour = theme::danger();
            tag = QStringLiteral("DANGER");
        }

        auto *h = new QVBoxLayout(box);
        h->setContentsMargins(14, 10, 14, 10);
        h->setSpacing(4);

        auto *tagLabel = new QLabel(tag, box);
        tagLabel->setFont(theme::uiFont(12, true));
        tagLabel->setStyleSheet(QStringLiteral("color: %1;").arg(colour));
        h->addWidget(tagLabel);

        auto *text = new QLabel(qs(f.text), box);
        text->setFont(theme::uiFont(15));
        text->setWordWrap(true);
        h->addWidget(text);

        contentLayout_->addWidget(box);
    }
}

void InspectScreen::addOutputs()
{
    const TxSummary &s = app_->engine().summary();

    contentLayout_->addWidget(theme::sectionHeader(
        QStringLiteral("Where the money goes - %1 output(s)").arg(s.outputs.size()),
        content_));

    for (std::size_t i = 0; i < s.outputs.size(); ++i) {
        const OutputInfo &o = s.outputs[i];

        QFrame *box = theme::card(content_);
        if (o.ownership == OutputOwnership::Mismatch)
            box->setObjectName(QStringLiteral("cardDanger"));

        auto *v = new QVBoxLayout(box);
        v->setContentsMargins(14, 12, 14, 12);
        v->setSpacing(6);

        // This screen runs before a key exists, so most of the time the honest
        // answer is "the file claims X". Calling an unverified change output a
        // payment to a stranger is how an operator gets talked out of a
        // transaction that was fine; calling it change without proof is how one
        // gets talked into a transaction that was not. Neither is said here.
        QString title = QStringLiteral("Output %1").arg(i + 1);
        QString note;
        const char *colour = theme::accent();
        if (!o.isOpReturn) {
            switch (o.ownership) {
            case OutputOwnership::Verified:
                title += QStringLiteral("  -  COMING BACK TO YOU  (VERIFIED)");
                colour = theme::ok();
                note = QStringLiteral("The key you entered derives to this exact "
                                      "address. This is your own change.");
                break;
            case OutputOwnership::Claimed:
                title += QStringLiteral("  -  DECLARED AS YOUR OWN CHANGE  (NOT VERIFIED)");
                colour = theme::textDim();
                note = QStringLiteral("The file says this address belongs to the "
                                      "wallet being spent from. Nothing proves that "
                                      "yet - it is checked against your key on the "
                                      "next screen.");
                break;
            case OutputOwnership::Unverifiable:
                title += QStringLiteral("  -  CLAIMS TO BE YOURS  (CANNOT BE PROVED)");
                colour = theme::warn();
                note = QStringLiteral("This PSBT does not carry what is needed to "
                                      "prove the claim. Treat it as money leaving.");
                break;
            case OutputOwnership::Mismatch:
                title += QStringLiteral("  -  FORGED CHANGE LABEL");
                colour = theme::danger();
                note = QStringLiteral("This output claims to be your change, but "
                                      "your key does not control it. Signing is "
                                      "blocked.");
                break;
            case OutputOwnership::ThirdParty:
                title += QStringLiteral("  -  PAYMENT TO SOMEONE ELSE");
                break;
            }
        }

        auto *t = new QLabel(title, box);
        t->setFont(theme::uiFont(15, true));
        t->setStyleSheet(QStringLiteral("color: %1;").arg(colour));
        v->addWidget(t);

        // The address gets its own big monospaced line. This is the single most
        // important string on the entire device.
        auto *addr = new QLabel(qs(o.address), box);
        addr->setFont(theme::monoFont(o.address.size() > 60 ? 15 : 17, true));
        addr->setWordWrap(true);
        v->addWidget(addr);

        if (!note.isEmpty()) {
            auto *n = new QLabel(note, box);
            n->setFont(theme::uiFont(13));
            n->setWordWrap(true);
            n->setStyleSheet(QStringLiteral("color: %1;").arg(theme::textDim()));
            v->addWidget(n);
        }

        v->addWidget(fieldRow(QStringLiteral("amount"), amountText(o.amountSat), box));
        v->addWidget(fieldRow(QStringLiteral("type  "), qs(o.scriptType), box));
        if (!o.derivation.empty())
            v->addWidget(fieldRow(QStringLiteral("path  "),
                                  o.claimedFingerprint.empty()
                                      ? qs(o.derivation)
                                      : QStringLiteral("%1  (master %2)")
                                            .arg(qs(o.derivation), qs(o.claimedFingerprint)),
                                  box));
        if (o.isOpReturn && !o.opReturnHex.empty())
            v->addWidget(fieldRow(QStringLiteral("data  "), qs(o.opReturnHex), box));

        contentLayout_->addWidget(box);
    }
}

void InspectScreen::addInputs()
{
    const TxSummary &s = app_->engine().summary();

    contentLayout_->addWidget(theme::sectionHeader(
        QStringLiteral("Coins being spent - %1 input(s)").arg(s.inputs.size()),
        content_));

    for (std::size_t i = 0; i < s.inputs.size(); ++i) {
        const InputInfo &in = s.inputs[i];

        QFrame *box = theme::card(content_);
        if (!in.amountKnown)
            box->setObjectName(QStringLiteral("cardDanger"));

        auto *v = new QVBoxLayout(box);
        v->setContentsMargins(14, 12, 14, 12);
        v->setSpacing(6);

        QString title = QStringLiteral("Input %1").arg(i + 1);
        if (in.canSign)
            title += QStringLiteral("  -  YOU CAN SIGN THIS");
        else if (app_->engine().hasKey())
            title += QStringLiteral("  -  not yours");

        auto *t = new QLabel(title, box);
        t->setFont(theme::uiFont(15, true));
        t->setStyleSheet(QStringLiteral("color: %1;")
                             .arg(in.canSign ? theme::ok() : theme::textDim()));
        v->addWidget(t);

        v->addWidget(fieldRow(QStringLiteral("amount  "),
                              in.amountKnown ? amountText(in.amountSat)
                                             : QStringLiteral("UNKNOWN - the PSBT does "
                                                              "not include this UTXO"),
                              box, true,
                              in.amountKnown ? theme::text() : theme::danger()));
        v->addWidget(fieldRow(QStringLiteral("address "), qs(in.address), box));
        v->addWidget(fieldRow(QStringLiteral("outpoint"), qs(in.outpoint), box));
        v->addWidget(fieldRow(QStringLiteral("type    "), qs(in.scriptType), box));
        if (!in.derivation.empty())
            v->addWidget(fieldRow(QStringLiteral("path    "),
                                  QStringLiteral("%1  (master %2)")
                                      .arg(qs(in.derivation), qs(in.fingerprint)),
                                  box));
        if (in.existingSignatures > 0)
            v->addWidget(fieldRow(QStringLiteral("signed  "),
                                  QStringLiteral("%1 signature(s) already present")
                                      .arg(in.existingSignatures),
                                  box, false, theme::warn()));
        if (in.sighash != 0 && in.sighash != 1)
            v->addWidget(fieldRow(QStringLiteral("sighash "),
                                  QStringLiteral("0x%1 - NOT SIGHASH_ALL")
                                      .arg(in.sighash, 2, 16, QLatin1Char('0')),
                                  box, true, theme::danger()));

        contentLayout_->addWidget(box);
    }
}

} // namespace signeros
