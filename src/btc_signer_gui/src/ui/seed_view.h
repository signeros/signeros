// SPDX-License-Identifier: MIT
//
// seed_view.h - draws a mnemonic on screen without ever assembling it.
//
// A widget is needed here rather than a QLabel because of one rule this project
// does not bend: the mnemonic never becomes a QString. A QLabel would require
// exactly that - a heap-allocated, reference-counted, implicitly shared string
// holding all twenty-four words, whose buffer is released to Qt's allocator
// when the label is cleared and is not wiped on the way out.
//
// So this paints straight from the SecureString: it walks the locked buffer,
// works out where each word starts and ends, and draws the characters. The only
// QStrings that exist are one character long and live for the duration of a
// single drawText call.
//
// That is not paranoia for its own sake. This screen exists to show a seed that
// has never been written to any medium; leaving a copy of it in the heap of the
// process that promised not to keep one would make that promise false in the
// most literal way available.

#pragma once

#include <QWidget>

#include <cstdint>

namespace signeros {

class SecureString;

class SeedView : public QWidget {
    Q_OBJECT

public:
    explicit SeedView(QWidget *parent = nullptr);

    // Borrows the buffer; it must outlive this widget's use of it. Nothing is
    // copied. Pass nullptr to show nothing.
    void setSource(const SecureString *source);

    // Masked mode: the grid, the numbers and the cell outlines stay, the words
    // become blocks. Used the moment the operator says they have written the
    // words down, so nothing is left readable over their shoulder while they
    // type the verification.
    void setMasked(bool masked);
    bool masked() const { return masked_; }

    // Draw a fixed number of cells regardless of how many words the source
    // currently holds, so the verification grid shows all twelve places from
    // the first keystroke and fills in rather than growing. 0 restores "as many
    // cells as there are words".
    //
    // Not called setSlots(): `slots` is a Qt keyword (moc's #define), and a
    // parameter of that name does not survive the preprocessor.
    void setCellCount(std::size_t cells);

    // Cells to outline in red, as a bitmask - bit i is cell i. A mask rather
    // than a single index because once the operator can move freely between
    // cells there is no longer a "first" wrong word that stands for the rest:
    // words 3 and 9 can both be wrong, and showing only one of them sends
    // somebody back to their paper twice.
    void setErrorWords(std::uint32_t mask);

    // Cell to mark as the one being typed. -1 for none.
    void setActiveWord(int index);

    // Cells the operator can click. Off for a grid that is only being read -
    // the seed page, where there is nothing to move a cursor to.
    void setInteractive(bool interactive);

    // How many cells wide the grid is currently drawn, so a screen can move the
    // cursor a row at a time without duplicating the layout rule.
    int columns() const;

    QSize sizeHint() const override;

signals:
    // A cell was clicked, by index. This is the pointer half of moving between
    // words: SignerOS is driven by a mouse or a trackpad first (see CLAUDE.md),
    // so "go and fix word 7" cannot be a key combination only.
    void cellClicked(int index);

protected:
    void paintEvent(QPaintEvent *event) override;
    void mousePressEvent(QMouseEvent *event) override;

private:
    std::size_t cellCount() const;
    // The cell under a point, or -1. Shares its geometry with paintEvent()
    // through cellRect() so what is clicked is always what was drawn.
    int cellAt(const QPointF &pos) const;
    QRectF cellRect(std::size_t index, int cols) const;

    const SecureString *source_ = nullptr;
    bool masked_ = false;
    bool interactive_ = false;
    std::size_t cellCount_ = 0;
    std::uint32_t errorWords_ = 0;
    int activeWord_ = -1;
};

} // namespace signeros
