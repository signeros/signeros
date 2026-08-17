// SPDX-License-Identifier: MIT

#include "ui/seed_view.h"

#include <QColor>
#include <QFontMetrics>
#include <QMouseEvent>
#include <QPainter>
#include <QPen>

#include "core/secure_memory.h"
#include "ui/theme.h"

namespace signeros {
namespace {

QColor colourOf(const char *hex, int alpha = 255)
{
    QColor c(QString::fromLatin1(hex));
    c.setAlpha(alpha);
    return c;
}

// Number of columns for a given word count. Twelve words read best as three
// columns of four; twenty-four as four of six. Both keep the grid squarer than
// the screen, which is what makes "word 17" findable at a glance while copying
// it onto paper.
int columnsFor(std::size_t words)
{
    if (words <= 12)
        return 3;
    return 4;
}

} // namespace

SeedView::SeedView(QWidget *parent) : QWidget(parent)
{
    setMinimumHeight(theme::px(200));
}

void SeedView::setSource(const SecureString *source)
{
    source_ = source;
    update();
}

void SeedView::setMasked(bool masked)
{
    if (masked_ == masked)
        return;
    masked_ = masked;
    update();
}

void SeedView::setCellCount(std::size_t cells)
{
    if (cellCount_ == cells)
        return;
    cellCount_ = cells;
    update();
}

void SeedView::setErrorWords(std::uint32_t mask)
{
    if (errorWords_ == mask)
        return;
    errorWords_ = mask;
    update();
}

void SeedView::setActiveWord(int index)
{
    if (activeWord_ == index)
        return;
    activeWord_ = index;
    update();
}

void SeedView::setInteractive(bool interactive)
{
    if (interactive_ == interactive)
        return;
    interactive_ = interactive;
    // Only where a cursor is actually drawn. On the appliance's own touchscreen
    // there is none, and a hand cursor would be a shape nobody ever sees
    // attached to a widget a finger already reaches.
    if (theme::cursorVisible())
        setCursor(interactive ? Qt::PointingHandCursor : Qt::ArrowCursor);
}

std::size_t SeedView::cellCount() const
{
    if (cellCount_ > 0)
        return cellCount_;
    // No fixed count: as many cells as the source has fields. An empty buffer
    // draws nothing rather than one empty cell - the seed page has no grid
    // until there is a seed.
    if (source_ == nullptr || source_->empty())
        return 0;
    return source_->slotCount();
}

int SeedView::columns() const
{
    return columnsFor(cellCount());
}

QRectF SeedView::cellRect(std::size_t index, int cols) const
{
    const int rows = static_cast<int>((cellCount() + cols - 1) / cols);
    if (rows <= 0)
        return QRectF();

    const double gap = theme::px(8);
    const double cellW = (width() - gap * (cols - 1)) / cols;
    const double cellH = (height() - gap * (rows - 1)) / rows;

    const int col = static_cast<int>(index % static_cast<std::size_t>(cols));
    const int row = static_cast<int>(index / static_cast<std::size_t>(cols));
    return QRectF(col * (cellW + gap), row * (cellH + gap), cellW, cellH);
}

int SeedView::cellAt(const QPointF &pos) const
{
    const std::size_t cells = cellCount();
    if (cells == 0)
        return -1;
    const int cols = columnsFor(cells);
    for (std::size_t i = 0; i < cells; ++i) {
        // The gaps between cells count as the nearest cell rather than as
        // nothing: a fingertip that lands two pixels short of a border meant
        // the cell, and "nothing happened" is the worst possible answer.
        if (cellRect(i, cols).adjusted(-theme::px(4), -theme::px(4),
                                       theme::px(4), theme::px(4))
                .contains(pos))
            return static_cast<int>(i);
    }
    return -1;
}

void SeedView::mousePressEvent(QMouseEvent *event)
{
    if (!interactive_) {
        QWidget::mousePressEvent(event);
        return;
    }
    // QMouseEvent::position() is Qt 6 only; this tree builds against either.
#if QT_VERSION >= QT_VERSION_CHECK(6, 0, 0)
    const QPointF where = event->position();
#else
    const QPointF where = QPointF(event->pos());
#endif
    const int index = cellAt(where);
    if (index < 0) {
        QWidget::mousePressEvent(event);
        return;
    }
    emit cellClicked(index);
    event->accept();
}

QSize SeedView::sizeHint() const
{
    return QSize(theme::px(720), theme::px(280));
}

void SeedView::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setRenderHint(QPainter::TextAntialiasing, true);

    const std::size_t cells = cellCount();
    if (cells == 0 || source_ == nullptr)
        return;

    const int cols = columnsFor(cells);
    const QRectF first = cellRect(0, cols);
    const double cellW = first.width();
    const double cellH = first.height();

    // Fonts scale with the cell, so the same widget is legible on a 600px panel
    // and comfortable on a desktop monitor.
    QFont wordFont = theme::monoFont(1, true);
    wordFont.setPixelSize(static_cast<int>(qMin(cellH * 0.46, cellW * 0.155)));
    QFont indexFont = theme::monoFont(1);
    indexFont.setPixelSize(static_cast<int>(wordFont.pixelSize() * 0.72));

    const QFontMetrics wordMetrics(wordFont);
    const QFontMetrics indexMetrics(indexFont);

    // Where each word starts and how long it is. Offsets into the locked
    // buffer, not copies of it: this array is a set of integers, and the
    // characters themselves are read straight out of the SecureString when they
    // are drawn.
    //
    // Split on every separator rather than on runs of them, so an EMPTY field
    // is a cell of its own. That is the whole difference between a grid the
    // operator can move around in and one they can only append to: emptying
    // word 7 to re-type it must not slide words 8 upwards by one cell.
    struct Span { std::size_t start; std::size_t len; };
    Span spans[32] = {};
    std::size_t found = 0;

    const char *buf = source_->c_str();
    const std::size_t len = source_->size();
    {
        std::size_t begin = 0;
        for (std::size_t i = 0; i <= len && found < 32; ++i) {
            if (i != len && buf[i] != ' ')
                continue;
            spans[found].start = begin;
            spans[found].len = i - begin;
            ++found;
            begin = i + 1;
        }
    }

    for (std::size_t index = 0; index < cells; ++index) {
        const QRectF cell = cellRect(index, cols);

        const bool isError = (index < 32) &&
                             ((errorWords_ & (1u << index)) != 0);
        const bool isActive = (activeWord_ >= 0 &&
                               static_cast<std::size_t>(activeWord_) == index);
        const bool filled = (index < found) && (spans[index].len > 0);

        QPen pen(colourOf(isError ? theme::danger()
                          : isActive ? theme::accent()
                                     : theme::border()),
                 (isError || isActive) ? 2.0 : 1.0);
        p.setPen(pen);
        p.setBrush(colourOf(filled ? theme::panelAlt() : theme::panel(),
                            filled ? 255 : 140));
        p.drawRoundedRect(cell, theme::px(6), theme::px(6));
        p.setBrush(Qt::NoBrush);

        // The number. Always shown, even for an empty or masked cell: the
        // numbering is what makes a written-down backup checkable, and it is
        // not a secret. It carries the accent on the active cell too, because
        // an outline among twenty-three other outlines is not enough on its own
        // to answer "which word am I on".
        const QString number = QStringLiteral("%1").arg(index + 1, 2, 10, QLatin1Char(' '));
        p.setFont(indexFont);
        p.setPen(isActive ? colourOf(theme::accent())
                          : colourOf(theme::textDim(), filled ? 200 : 120));
        const double numberX = cell.left() + theme::px(12);
        const double baseline = cell.center().y() + wordMetrics.ascent() * 0.36;
        p.drawText(QPointF(numberX, baseline), number);

        const double wordX = numberX + indexMetrics.horizontalAdvance(number) +
                             theme::px(12);

        // The caret, drawn wherever the word being typed ends - in an empty
        // cell that is the start of it. This is the one mark that tracks the
        // cursor rather than the content, and it is what makes a just-finished
        // word visibly hand over to the next cell.
        const double caretH = wordMetrics.ascent() * 1.05;
        auto drawCaret = [&](double x) {
            p.setPen(Qt::NoPen);
            p.setBrush(colourOf(theme::accent(), 235));
            p.drawRect(QRectF(x, baseline - caretH * 0.9,
                              qMax(2.0, static_cast<double>(theme::px(2))), caretH));
            p.setBrush(Qt::NoBrush);
        };

        if (!filled) {
            if (isActive)
                drawCaret(wordX);
            continue;
        }

        const Span &span = spans[index];

        if (masked_) {
            // One block per character, so the shape of the word is not leaked
            // either - only that there is one.
            p.setPen(Qt::NoPen);
            p.setBrush(colourOf(theme::border(), 210));
            const double blockW = wordMetrics.horizontalAdvance(QChar('m')) * 0.62;
            const double blockH = wordMetrics.ascent() * 0.52;
            double x = wordX;
            for (std::size_t k = 0; k < span.len; ++k) {
                p.drawRoundedRect(QRectF(x, baseline - blockH, blockW, blockH), 2, 2);
                x += blockW + theme::px(3);
            }
            p.setBrush(Qt::NoBrush);
            if (isActive)
                drawCaret(x);
        } else {
            p.setFont(wordFont);
            p.setPen(colourOf(isError ? theme::danger() : theme::text()));
            double x = wordX;
            for (std::size_t k = 0; k < span.len; ++k) {
                // One character, drawn and discarded. This is the entire reason
                // this widget exists instead of a QLabel.
                const QChar ch = QLatin1Char(buf[span.start + k]);
                p.drawText(QPointF(x, baseline), QString(ch));
                x += wordMetrics.horizontalAdvance(ch);
            }
            if (isActive)
                drawCaret(x + theme::px(2));
        }
    }
}

} // namespace signeros
