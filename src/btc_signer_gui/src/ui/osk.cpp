// SPDX-License-Identifier: MIT

#include "ui/osk.h"

#include <QHBoxLayout>
#include <QPushButton>
#include <QStackedLayout>
#include <QVBoxLayout>

#include "ui/theme.h"

namespace signeros {

OnScreenKeyboard::OnScreenKeyboard(QWidget *parent) : QWidget(parent)
{
    pages_ = new QStackedLayout(this);
    pages_->setContentsMargins(0, 0, 0, 0);

    lowerIndex_  = pages_->addWidget(buildLetterPage(false));
    upperIndex_  = pages_->addWidget(buildLetterPage(true));
    symbolIndex_ = pages_->addWidget(buildSymbolPage());

    showPage(lowerIndex_);
}

void OnScreenKeyboard::setMode(Mode mode)
{
    mode_ = mode;
    // Coming back to a mnemonic always starts on lowercase letters: the BIP39
    // alphabet has nothing else in it.
    showPage(lowerIndex_);
}

void OnScreenKeyboard::showPage(int index)
{
    pages_->setCurrentIndex(index);
}

QWidget *OnScreenKeyboard::buildRow(const char *keys, bool upper, QWidget *parent)
{
    auto *row = new QWidget(parent);
    auto *h = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(6);

    for (const char *k = keys; *k != '\0'; ++k) {
        const char c = upper ? static_cast<char>(*k - 32) : *k;
        QPushButton *b = theme::keyButton(QString(QChar::fromLatin1(c)), row);
        connect(b, &QPushButton::clicked, this, [this, c]() {
            emit characterTyped(c);
        });
        h->addWidget(b, 1);
    }
    return row;
}

void OnScreenKeyboard::addControlRow(QWidget *page, QVBoxLayout *layout, bool allowLayerSwitch)
{
    auto *row = new QWidget(page);
    auto *h = new QHBoxLayout(row);
    h->setContentsMargins(0, 0, 0, 0);
    h->setSpacing(6);

    // The layer keys are always present. Pages are built once, in the
    // constructor, so making their presence depend on the current mode would
    // bake in whatever mode happened to be set first. Instead the *consumer*
    // filters: SignScreen in Bip39 mode accepts only a-z and space, so an
    // uppercase or punctuation keystroke is simply ignored there.
    if (allowLayerSwitch) {
        QPushButton *shift = theme::keyButton(QStringLiteral("ABC"), row);
        connect(shift, &QPushButton::clicked, this, [this]() {
            showPage(pages_->currentIndex() == upperIndex_ ? lowerIndex_ : upperIndex_);
        });
        h->addWidget(shift, 2);

        QPushButton *sym = theme::keyButton(QStringLiteral("123#"), row);
        connect(sym, &QPushButton::clicked, this, [this]() {
            showPage(pages_->currentIndex() == symbolIndex_ ? lowerIndex_ : symbolIndex_);
        });
        h->addWidget(sym, 2);
    }

    // Space doubles as "next word" while entering a mnemonic, which is why it
    // is wide and central.
    QPushButton *space = theme::keyButton(QStringLiteral("space"), row);
    connect(space, &QPushButton::clicked, this, [this]() {
        emit characterTyped(' ');
    });
    h->addWidget(space, 6);

    // Plain ASCII labels only: there is no fontconfig on the image and the
    // shipped DejaVu faces are the only fallback, so a missing glyph would
    // render as a blank key.
    QPushButton *bs = theme::keyButton(QStringLiteral("Bksp"), row);
    bs->setFont(theme::uiFont(15, true));
    bs->setAutoRepeat(true);
    bs->setAutoRepeatDelay(500);
    bs->setAutoRepeatInterval(90);
    connect(bs, &QPushButton::clicked, this, &OnScreenKeyboard::backspacePressed);
    h->addWidget(bs, 2);

    QPushButton *delWord = theme::keyButton(QStringLiteral("del word"), row);
    delWord->setFont(theme::uiFont(14, true));
    connect(delWord, &QPushButton::clicked, this, &OnScreenKeyboard::deleteWordPressed);
    h->addWidget(delWord, 3);

    QPushButton *clear = theme::keyButton(QStringLiteral("clear"), row);
    clear->setFont(theme::uiFont(14, true));
    connect(clear, &QPushButton::clicked, this, &OnScreenKeyboard::clearAllPressed);
    h->addWidget(clear, 2);

    // The keyboard floats over the page it is typing into (ui/osk_panel.h), so
    // the buttons underneath it - "Check key", "Derive the keys" - are covered
    // while it is up. On a machine with no physical keyboard this key is the
    // only way back to them, so it is part of the keyboard rather than
    // something the page has to remember to provide.
    QPushButton *hide = theme::keyButton(QStringLiteral("hide keys"), row);
    hide->setFont(theme::uiFont(14, true));
    connect(hide, &QPushButton::clicked, this, &OnScreenKeyboard::hidePressed);
    h->addWidget(hide, 3);

    layout->addWidget(row);
}

QWidget *OnScreenKeyboard::buildLetterPage(bool upper)
{
    auto *page = new QWidget(this);
    auto *v = new QVBoxLayout(page);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(6);

    v->addWidget(buildRow("qwertyuiop", upper, page));
    v->addWidget(buildRow("asdfghjkl", upper, page));
    v->addWidget(buildRow("zxcvbnm", upper, page));

    addControlRow(page, v, true);
    return page;
}

QWidget *OnScreenKeyboard::buildSymbolPage()
{
    auto *page = new QWidget(this);
    auto *v = new QVBoxLayout(page);
    v->setContentsMargins(0, 0, 0, 0);
    v->setSpacing(6);

    v->addWidget(buildRow("1234567890", false, page));
    v->addWidget(buildRow("!@#$%^&*()", false, page));
    v->addWidget(buildRow("-_=+[]{};:", false, page));
    v->addWidget(buildRow("'\",.<>/?\\|", false, page));

    addControlRow(page, v, true);
    return page;
}

} // namespace signeros
