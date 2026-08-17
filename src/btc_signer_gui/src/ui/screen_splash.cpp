// SPDX-License-Identifier: MIT

#include "ui/screen_splash.h"

#include <QColor>
#include <QFontMetrics>
#include <QKeyEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPainterPath>
#include <QPen>
#include <QRadialGradient>
#include <QTimer>

#include <cmath>

#include "core/psbt_engine.h"
#include "ui/app_window.h"
#include "ui/theme.h"

namespace signeros {
namespace {

// Eric Hughes, A Cypherpunk's Manifesto, 9 March 1993 - the sentence this
// entire machine is an implementation of. Plain ASCII on purpose: the image
// ships DejaVu and nothing else, and a missing glyph on the first screen the
// operator ever sees would be a poor advertisement for a device that claims to
// leave nothing to chance.
const char kQuote[] = "Privacy is necessary for an open society "
                      "in the electronic age.";
const char kAttribution[] = "A Cypherpunk's Manifesto, Eric Hughes, 1993";

// The animation timeline, in milliseconds from the moment the screen appears.
constexpr int kMarkIn      = 400;    // the padlock fades and scales in
constexpr int kWordmarkIn  = 300;    // the wordmark starts
constexpr int kWordmarkEnd = 800;
constexpr int kTypeStart   = 550;    // the quote starts typing
constexpr int kTypeEnd     = 2250;
constexpr int kTailIn      = 2300;   // attribution and the guarantee chips

double clamp01(double v)
{
    return v < 0.0 ? 0.0 : (v > 1.0 ? 1.0 : v);
}

// Ease-out cubic. Everything here decelerates into place; nothing bounces.
double ease(double t)
{
    const double inv = 1.0 - clamp01(t);
    return 1.0 - inv * inv * inv;
}

double progress(qint64 elapsed, int from, int to)
{
    if (to <= from)
        return 1.0;
    return ease(static_cast<double>(elapsed - from) / static_cast<double>(to - from));
}

QColor withAlpha(const char *hex, int alpha)
{
    QColor c(QString::fromLatin1(hex));
    c.setAlpha(alpha);
    return c;
}

// A regular hexagon, flat-topped, inscribed in `r`.
QPainterPath hexagon(const QRectF &r)
{
    const QPointF c = r.center();
    const double rad = qMin(r.width(), r.height()) / 2.0;
    QPainterPath p;
    for (int i = 0; i < 6; ++i) {
        // Start at -90 degrees so the flat edges are left and right, which
        // makes the shape read as a seal rather than as a warning sign.
        const double angle = (M_PI / 180.0) * (60.0 * i - 90.0);
        const QPointF pt(c.x() + rad * std::cos(angle), c.y() + rad * std::sin(angle));
        if (i == 0)
            p.moveTo(pt);
        else
            p.lineTo(pt);
    }
    p.closeSubpath();
    return p;
}

// A padlock: shackle arc plus body, drawn as strokes so it stays crisp at any
// size and needs no glyph from any font.
void drawPadlock(QPainter &p, const QRectF &r, const QColor &colour, double weight)
{
    const double w = r.width();
    const double h = r.height();

    QPen pen(colour);
    pen.setWidthF(weight);
    pen.setCapStyle(Qt::RoundCap);
    pen.setJoinStyle(Qt::RoundJoin);
    p.setPen(pen);
    p.setBrush(Qt::NoBrush);

    // Shackle: a half-circle sitting on top of the body.
    const QRectF shackle(r.left() + w * 0.28, r.top() + h * 0.02,
                         w * 0.44, h * 0.46);
    p.drawArc(shackle, 0 * 16, 180 * 16);
    p.drawLine(QPointF(shackle.left(), shackle.center().y()),
               QPointF(shackle.left(), r.top() + h * 0.42));
    p.drawLine(QPointF(shackle.right(), shackle.center().y()),
               QPointF(shackle.right(), r.top() + h * 0.42));

    // Body.
    const QRectF body(r.left() + w * 0.14, r.top() + h * 0.40, w * 0.72, h * 0.52);
    p.drawRoundedRect(body, w * 0.08, w * 0.08);

    // Keyhole: a dot with a slot under it.
    const double keyR = w * 0.055;
    const QPointF keyC(body.center().x(), body.top() + body.height() * 0.36);
    p.setBrush(colour);
    p.drawEllipse(keyC, keyR, keyR);
    p.setBrush(Qt::NoBrush);
    QPen slot(colour);
    slot.setWidthF(keyR * 1.3);
    slot.setCapStyle(Qt::RoundCap);
    p.setPen(slot);
    p.drawLine(keyC + QPointF(0, keyR * 0.4),
               QPointF(keyC.x(), body.bottom() - body.height() * 0.24));
}

} // namespace

// ---------------------------------------------------------------------------

SplashScreen::SplashScreen(AppWindow *app, QWidget *parent)
    : QWidget(parent), app_(app)
{
    setFocusPolicy(Qt::StrongFocus);
    setAutoFillBackground(true);

    timer_ = new QTimer(this);
    // ~30 fps. The framebuffer is software-composited by linuxfb, and a full
    // repaint of a 4K screen is not free; 33 ms is smooth to the eye and leaves
    // the CPU alone. Nothing else is happening during these three seconds
    // anyway.
    timer_->setInterval(33);
    connect(timer_, &QTimer::timeout, this, &SplashScreen::tick);
}

void SplashScreen::onEnter()
{
    done_ = false;
    clock_.start();
    timer_->start();
    setFocus();
    update();
}

void SplashScreen::onLeave()
{
    timer_->stop();
}

void SplashScreen::tick()
{
    if (clock_.elapsed() >= kDurationMs) {
        finish();
        return;
    }
    update();
}

void SplashScreen::finish()
{
    if (done_)
        return;
    done_ = true;
    timer_->stop();
    app_->showHome();
}

void SplashScreen::keyPressEvent(QKeyEvent *event)
{
    // Anything at all skips ahead, except the keys AppWindow reserves - F12
    // still has to reach the shutdown screen from here, because a machine
    // booted by mistake should be switchable off during the splash too.
    if (event->key() == Qt::Key_F12) {
        QWidget::keyPressEvent(event);
        return;
    }
    finish();
}

void SplashScreen::mousePressEvent(QMouseEvent *)
{
    finish();
}

// ---------------------------------------------------------------------------

void SplashScreen::paintEvent(QPaintEvent *)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);
    p.setRenderHint(QPainter::TextAntialiasing, true);

    const QRectF full(rect());
    const qint64 t = clock_.isValid() ? clock_.elapsed() : 0;

    // --- background ------------------------------------------------------
    p.fillRect(full, QColor(QString::fromLatin1(theme::bg())));

    // A single warm glow behind the mark. It is what stops a flat dark screen
    // reading as "nothing has happened yet".
    {
        const QPointF centre(full.center().x(), full.height() * 0.34);
        QRadialGradient g(centre, full.height() * 0.55);
        g.setColorAt(0.0, withAlpha(theme::accent(), 34));
        g.setColorAt(0.5, withAlpha(theme::accent(), 10));
        g.setColorAt(1.0, withAlpha(theme::accent(), 0));
        p.fillRect(full, g);
    }

    // Scanlines. Two pixels of nothing every four, at an alpha you notice only
    // if you look for it: enough to say "terminal", not enough to fight the
    // text for attention.
    {
        p.setPen(Qt::NoPen);
        p.setBrush(withAlpha("#000000", 26));
        for (int y = 0; y < height(); y += 4)
            p.drawRect(0, y, width(), 1);
        p.setBrush(Qt::NoBrush);
    }

    const double unit = qMin(full.width() / 16.0, full.height() / 9.0);

    // --- the shell prompt, top left --------------------------------------
    {
        QFont f = theme::monoFont(14);
        p.setFont(f);
        p.setPen(withAlpha(theme::textDim(), 150));
        const bool cursorOn = ((t / 500) % 2) == 0;
        p.drawText(QPointF(unit * 0.7, unit * 0.9),
                   QStringLiteral("signeros@airgap:~$ boot --offline%1")
                       .arg(cursorOn ? QStringLiteral(" _") : QString()));
    }

    // --- the mark ---------------------------------------------------------
    {
        const double a = progress(t, 0, kMarkIn);
        const double size = unit * 2.9 * (0.82 + 0.18 * a);
        const QRectF markRect(full.center().x() - size / 2.0,
                              full.height() * 0.30 - size / 2.0, size, size);

        p.save();
        p.setOpacity(a);

        // Outward glow: the same hexagon stroked several times, wide and faint
        // first. Cheaper than a blur and it reads the same at this scale.
        const QPainterPath hex = hexagon(markRect);
        const struct { double width; int alpha; } layers[] = {
            { size * 0.075, 16 }, { size * 0.045, 34 },
            { size * 0.022, 70 }, { size * 0.010, 235 },
        };
        for (const auto &layer : layers) {
            QPen pen(withAlpha(theme::accent(), layer.alpha));
            pen.setWidthF(layer.width);
            pen.setJoinStyle(Qt::RoundJoin);
            p.setPen(pen);
            p.drawPath(hex);
        }

        const QRectF inner = markRect.adjusted(size * 0.28, size * 0.24,
                                               -size * 0.28, -size * 0.22);
        drawPadlock(p, inner, withAlpha(theme::accent(), 245), size * 0.030);
        p.restore();
    }

    // --- wordmark ---------------------------------------------------------
    double wordmarkBottom = full.height() * 0.60;
    {
        const double a = progress(t, kWordmarkIn, kWordmarkEnd);
        QFont f = theme::uiFont(1, true);
        f.setPixelSize(static_cast<int>(unit * 0.86));
        // The letters settle outwards as they arrive. Wide tracking is what
        // makes eight capitals read as a mark rather than as a word.
        f.setLetterSpacing(QFont::AbsoluteSpacing, unit * 0.30 * a);
        p.setFont(f);

        const QString mark = QStringLiteral("SIGNEROS");
        const QFontMetrics fm(f);
        const int w = fm.horizontalAdvance(mark);
        const double y = full.height() * 0.575;

        p.setOpacity(a);
        p.setPen(QColor(QString::fromLatin1(theme::text())));
        p.drawText(QPointF((full.width() - w) / 2.0, y), mark);
        p.setOpacity(1.0);
        wordmarkBottom = y;
    }

    // --- the manifesto line, typed ---------------------------------------
    {
        const QString quote = QString::fromLatin1(kQuote);

        QFont f = theme::monoFont(1);
        int size = static_cast<int>(unit * 0.30);
        f.setPixelSize(size);
        // Shrink until the whole sentence fits with a margin either side. A
        // sentence that wraps mid-animation looks like a bug, and this screen
        // has to survive a 1024x600 panel and a 3840x2160 monitor with the same
        // code.
        while (size > 8 &&
               QFontMetrics(f).horizontalAdvance(quote) > full.width() * 0.86) {
            f.setPixelSize(--size);
        }
        p.setFont(f);

        const QFontMetrics fm(f);
        const int shown = static_cast<int>(
            clamp01(static_cast<double>(t - kTypeStart) / (kTypeEnd - kTypeStart)) *
            quote.size());
        const QString typed = quote.left(shown);

        const double x = (full.width() - fm.horizontalAdvance(quote)) / 2.0;
        const double y = wordmarkBottom + unit * 0.95;

        p.setPen(QColor(QString::fromLatin1(theme::accentCool())));
        p.drawText(QPointF(x, y), typed);

        // A block cursor at the end of what has been typed, blinking once the
        // sentence is complete.
        const bool typing = shown < quote.size();
        if (typing || ((t / 400) % 2) == 0) {
            const double cx = x + fm.horizontalAdvance(typed);
            p.fillRect(QRectF(cx + fm.horizontalAdvance(QChar(' ')) * 0.15,
                              y - fm.ascent() * 0.82,
                              fm.horizontalAdvance(QChar('M')) * 0.62,
                              fm.ascent() * 0.92),
                       withAlpha(theme::accentCool(), typing ? 200 : 120));
        }

        // Attribution, after the sentence has landed.
        const double a = progress(t, kTailIn, kTailIn + 400);
        if (a > 0.0) {
            QFont af = theme::uiFont(1);
            af.setPixelSize(static_cast<int>(unit * 0.22));
            p.setFont(af);
            p.setOpacity(a * 0.85);
            p.setPen(QColor(QString::fromLatin1(theme::textDim())));
            const QString attr = QStringLiteral("- %1").arg(QString::fromLatin1(kAttribution));
            const int aw = QFontMetrics(af).horizontalAdvance(attr);
            p.drawText(QPointF((full.width() - aw) / 2.0, y + unit * 0.52), attr);
            p.setOpacity(1.0);
        }
    }

    // --- what this machine promises --------------------------------------
    {
        const double a = progress(t, kTailIn, kTailIn + 500);
        const QString chips[] = {
            QStringLiteral("AIR-GAPPED"),
            QStringLiteral("NO NETWORK STACK"),
            QStringLiteral("RAM ONLY"),
            QStringLiteral("YOUR KEYS NEVER LEAVE"),
        };

        QFont f = theme::uiFont(1, true);
        f.setPixelSize(static_cast<int>(unit * 0.20));
        f.setLetterSpacing(QFont::AbsoluteSpacing, unit * 0.03);
        p.setFont(f);
        const QFontMetrics fm(f);

        const double padX = unit * 0.28;
        const double gap = unit * 0.30;
        const double h = fm.height() + unit * 0.22;

        double total = 0;
        for (const QString &c : chips)
            total += fm.horizontalAdvance(c) + padX * 2 + gap;
        total -= gap;

        double x = (full.width() - total) / 2.0;
        const double y = full.height() * 0.845;

        p.setOpacity(a);
        for (const QString &c : chips) {
            const double w = fm.horizontalAdvance(c) + padX * 2;
            const QRectF box(x, y, w, h);
            p.setPen(QPen(withAlpha(theme::border(), 220), 1.0));
            p.setBrush(withAlpha(theme::panel(), 200));
            p.drawRoundedRect(box, h / 2.0, h / 2.0);
            p.setBrush(Qt::NoBrush);
            p.setPen(withAlpha(theme::textDim(), 235));
            p.drawText(box, Qt::AlignCenter, c);
            x += w + gap;
        }
        p.setOpacity(1.0);
    }

    // --- the three seconds, made visible ----------------------------------
    //
    // A progress bar rather than a spinner: it says how long this lasts, which
    // is the difference between waiting and wondering.
    {
        const double frac = clamp01(static_cast<double>(t) / kDurationMs);
        const double barW = full.width() * 0.34;
        const double barH = qMax(2.0, unit * 0.045);
        const QRectF track((full.width() - barW) / 2.0, full.height() * 0.935,
                           barW, barH);
        p.setPen(Qt::NoPen);
        p.setBrush(withAlpha(theme::border(), 160));
        p.drawRoundedRect(track, barH / 2.0, barH / 2.0);
        QRectF fill = track;
        fill.setWidth(barW * frac);
        p.setBrush(withAlpha(theme::accent(), 220));
        p.drawRoundedRect(fill, barH / 2.0, barH / 2.0);
        p.setBrush(Qt::NoBrush);
    }

    // --- identity, bottom right -------------------------------------------
    {
        QFont f = theme::monoFont(1);
        f.setPixelSize(static_cast<int>(unit * 0.19));
        p.setFont(f);
        p.setPen(withAlpha(theme::textDim(), 120));
        const QString id =
            QStringLiteral("SignerOS %1  ·  libwally %2  ·  %3  ·  press any key to continue")
                .arg(QStringLiteral(SIGNEROS_VERSION_STR),
                     QString::fromStdString(PsbtEngine::libraryVersion()),
                     QString::fromLatin1(networkName(app_->config().network)));
        const int w = QFontMetrics(f).horizontalAdvance(id);
        p.drawText(QPointF(full.width() - w - unit * 0.7, full.height() - unit * 0.35), id);
    }
}

} // namespace signeros
