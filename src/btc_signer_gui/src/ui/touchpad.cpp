// SPDX-License-Identifier: MIT

#include "ui/touchpad.h"

#include <cerrno>
#include <cmath>
#include <cstdio>
#include <cstring>

#include <fcntl.h>
#include <linux/input.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <QCursor>
#include <QGuiApplication>
#include <QRect>
#include <QScreen>
#include <QSocketNotifier>
#include <QWindow>

#include <qpa/qwindowsysteminterface.h>

namespace signeros {

namespace {

constexpr std::size_t kBitsPerLong = sizeof(unsigned long) * 8;

bool testBit(int bit, const unsigned long *arr)
{
    return (arr[bit / kBitsPerLong] >> (bit % kBitsPerLong)) & 1UL;
}

// How much of the screen one full traversal of the pad covers at neutral
// acceleration. Expressed as a ratio rather than a pixels-per-millimetre figure
// so that it means the same thing on a 1024x600 industrial panel and on a 4K
// laptop, and so that no pad's physical size is baked in.
constexpr qreal kPadTraversal = 1.3;

// Acceleration. factor = kAccelBase + kAccelGain * (fraction of the pad crossed
// in one report), clamped. Slow, deliberate motion lands near kAccelMin, which
// is what makes it possible to put the pointer on a specific character of an
// address; a fast flick lands near kAccelMax and crosses the screen.
constexpr qreal kAccelBase = 0.45;
constexpr qreal kAccelGain = 42.0;
constexpr qreal kAccelMin  = 0.45;
constexpr qreal kAccelMax  = 2.6;

// A single report that claims to have crossed more than this fraction of the
// pad is not a finger moving, it is a finger being swapped for another one or a
// dropped frame. Dropping it costs nothing; acting on it throws the pointer
// across the screen.
constexpr qreal kJumpReject = 0.35;

// Two-finger scrolling. Pad units are converted to pixels with the same gain as
// the pointer, then to wheel notches. 120 is Qt's angle delta per notch.
constexpr qreal kPixelsPerNotch = 50.0;

// Tap-to-click: a contact shorter than this, that moved less than kTapSlop of
// the pad, is a click. Both numbers are the usual libinput defaults.
constexpr qint64 kTapMs = 180;
constexpr qreal kTapSlop = 0.03;

} // namespace

// ---------------------------------------------------------------------------

Touchpad::Touchpad(int fd, const QString &path, QObject *parent)
    : QObject(parent), fd_(fd), path_(path)
{
}

Touchpad::~Touchpad()
{
    if (fd_ >= 0) {
        ::ioctl(fd_, EVIOCGRAB, 0);
        ::close(fd_);
    }
}

Touchpad *Touchpad::open(const QString &devicePath, QObject *parent)
{
    const QByteArray raw = devicePath.toLocal8Bit();
    const int fd = ::open(raw.constData(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        std::fprintf(stderr, "signer: touchpad %s: cannot open (%s)\n",
                     raw.constData(), std::strerror(errno));
        return nullptr;
    }

    Touchpad *pad = new Touchpad(fd, devicePath, parent);
    if (!pad->init()) {
        delete pad;
        return nullptr;
    }
    return pad;
}

bool Touchpad::init()
{
    const QByteArray raw = path_.toLocal8Bit();

    unsigned long absBits[(ABS_MAX / kBitsPerLong) + 1] = {};
    if (::ioctl(fd_, EVIOCGBIT(EV_ABS, sizeof(absBits)), absBits) < 0) {
        std::fprintf(stderr, "signer: touchpad %s: no absolute axes\n", raw.constData());
        return false;
    }
    // Slots are what makes the multitouch path usable: without ABS_MT_SLOT this
    // is a protocol-A pad, whose contacts cannot be told apart from one report
    // to the next. Those are driven through ABS_X/ABS_Y and the BTN_TOOL_* bits
    // instead, which is enough for one-finger motion and two-finger scrolling.
    multitouch_ = testBit(ABS_MT_POSITION_X, absBits) &&
                  testBit(ABS_MT_POSITION_Y, absBits) &&
                  testBit(ABS_MT_SLOT, absBits);

    // Axis ranges. The MT axes are authoritative when the pad has them: on some
    // pads ABS_X/ABS_Y carry a different range from ABS_MT_POSITION_*.
    struct input_absinfo ax = {}, ay = {};
    const int codeX = multitouch_ ? ABS_MT_POSITION_X : ABS_X;
    const int codeY = multitouch_ ? ABS_MT_POSITION_Y : ABS_Y;
    if (::ioctl(fd_, EVIOCGABS(codeX), &ax) < 0 ||
        ::ioctl(fd_, EVIOCGABS(codeY), &ay) < 0) {
        std::fprintf(stderr, "signer: touchpad %s: EVIOCGABS failed (%s)\n",
                     raw.constData(), std::strerror(errno));
        return false;
    }

    minX_ = ax.minimum; maxX_ = ax.maximum; resX_ = ax.resolution;
    minY_ = ay.minimum; maxY_ = ay.maximum; resY_ = ay.resolution;

    const int spanX = maxX_ - minX_;
    const int spanY = maxY_ - minY_;
    if (spanX <= 0 || spanY <= 0) {
        std::fprintf(stderr, "signer: touchpad %s: degenerate axis range "
                             "(x %d..%d, y %d..%d)\n",
                     raw.constData(), minX_, maxX_, minY_, maxY_);
        return false;
    }

    // ABS_MT_SLOT's maximum is the highest slot index the pad uses. Capped
    // because the array is indexed by whatever the device sends.
    int slotCount = 1;
    if (multitouch_) {
        struct input_absinfo as = {};
        if (::ioctl(fd_, EVIOCGABS(ABS_MT_SLOT), &as) == 0 && as.maximum >= 0)
            slotCount = as.maximum + 1;
    }
    if (slotCount < 1) slotCount = 1;
    if (slotCount > 16) slotCount = 16;
    contacts_.resize(slotCount);

    const QScreen *screen = QGuiApplication::primaryScreen();
    if (screen == nullptr) {
        std::fprintf(stderr, "signer: touchpad %s: no screen to point at\n", raw.constData());
        return false;
    }
    const QRect geom = screen->geometry();
    gainX_ = qreal(geom.width())  / (qreal(spanX) * kPadTraversal);
    gainY_ = qreal(geom.height()) / (qreal(spanY) * kPadTraversal);

    pos_ = QPointF(geom.center());
    lastSent_ = pos_.toPoint();

    // EVIOCGRAB, for the same reason the keyboard is grabbed: no other reader on
    // the image sees this device. Not fatal if it fails - a pad that works but
    // is also visible to something else is better than no pointer.
    if (::ioctl(fd_, EVIOCGRAB, 1) < 0)
        std::fprintf(stderr, "signer: touchpad %s: EVIOCGRAB failed (%s)\n",
                     raw.constData(), std::strerror(errno));

    notifier_ = new QSocketNotifier(fd_, QSocketNotifier::Read, this);
    QObject::connect(notifier_, &QSocketNotifier::activated,
                     this, [this]() { readEvents(); });

    std::fprintf(stderr,
                 "signer: touchpad %s: %s, x %d..%d y %d..%d, %d slot(s), "
                 "res %d/%d units/mm, gain %.4f/%.4f px/unit\n",
                 raw.constData(), multitouch_ ? "multitouch" : "single-touch",
                 minX_, maxX_, minY_, maxY_, int(contacts_.size()), resX_, resY_,
                 double(gainX_), double(gainY_));
    return true;
}

// ---------------------------------------------------------------------------

void Touchpad::readEvents()
{
    struct input_event evs[64];
    for (;;) {
        const ssize_t n = ::read(fd_, evs, sizeof(evs));
        if (n > 0) {
            const int count = int(std::size_t(n) / sizeof(struct input_event));
            for (int i = 0; i < count; ++i)
                handleEvent(evs[i]);
            continue;
        }
        if (n < 0 && errno == EINTR)
            continue;
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
            return;

        // The node went away, or is returning nothing readable. Stop listening
        // rather than spinning on a dead descriptor: there is no hotplug path on
        // this image, so it will not come back within this session.
        std::fprintf(stderr, "signer: touchpad %s: read failed (%s), detaching\n",
                     path_.toLocal8Bit().constData(),
                     n < 0 ? std::strerror(errno) : "eof");
        notifier_->setEnabled(false);
        return;
    }
}

void Touchpad::handleEvent(const struct input_event &ev)
{
    switch (ev.type) {
    case EV_ABS:
        switch (ev.code) {
        case ABS_MT_SLOT:
            currentSlot_ = (ev.value >= 0 && ev.value < contacts_.size()) ? ev.value : 0;
            break;
        case ABS_MT_TRACKING_ID:
            contacts_[currentSlot_].trackingId = ev.value;
            break;
        case ABS_MT_POSITION_X:
            contacts_[currentSlot_].x = ev.value;
            break;
        case ABS_MT_POSITION_Y:
            contacts_[currentSlot_].y = ev.value;
            break;
        case ABS_X:
            singleX_ = ev.value;
            break;
        case ABS_Y:
            singleY_ = ev.value;
            break;
        default:
            break;
        }
        break;

    case EV_KEY:
        switch (ev.code) {
        case BTN_TOUCH:        singleTouch_ = ev.value != 0; break;
        case BTN_TOOL_FINGER:  toolFinger_  = ev.value != 0; break;
        case BTN_TOOL_DOUBLETAP: toolDouble_ = ev.value != 0; break;
        case BTN_TOOL_TRIPLETAP: toolTriple_ = ev.value != 0; break;

        // A clickpad's physical click. Handled directly rather than through the
        // tap logic: it is unambiguous, and it must still work when tapping is
        // suppressed because a finger is moving.
        case BTN_LEFT:
            physicalButtonDown_ = ev.value != 0;
            // A clickpad press happens with a finger already down, and that
            // finger then lifts. Without cancelling the tap here, a short
            // physical click emits its own press/release and then a second,
            // phantom click when the finger comes up - on a screen whose
            // buttons advance an irreversible signing flow.
            if (ev.value != 0)
                tapCandidate_ = false;
            setButton(Qt::LeftButton, ev.value != 0);
            break;
        case BTN_RIGHT:
            setButton(Qt::RightButton, ev.value != 0);
            break;
        case BTN_MIDDLE:
            setButton(Qt::MiddleButton, ev.value != 0);
            break;
        default:
            break;
        }
        break;

    case EV_SYN:
        if (ev.code == SYN_REPORT)
            frameComplete();
        break;

    default:
        break;
    }
}

int Touchpad::activeContacts() const
{
    if (multitouch_) {
        int n = 0;
        for (const Contact &c : contacts_)
            if (c.trackingId >= 0)
                ++n;
        return n;
    }
    // A protocol-A or single-touch pad reports how many fingers are down
    // through the tool bits instead of through slots.
    if (toolTriple_) return 3;
    if (toolDouble_) return 2;
    if (toolFinger_ || singleTouch_) return 1;
    return 0;
}

bool Touchpad::primaryPosition(int *x, int *y) const
{
    if (multitouch_) {
        for (const Contact &c : contacts_) {
            if (c.trackingId >= 0) {
                *x = c.x;
                *y = c.y;
                return true;
            }
        }
        return false;
    }
    if (toolFinger_ || toolDouble_ || toolTriple_ || singleTouch_) {
        *x = singleX_;
        *y = singleY_;
        return true;
    }
    return false;
}

void Touchpad::frameComplete()
{
    const int fingers = activeContacts();
    int x = 0, y = 0;
    const bool havePos = primaryPosition(&x, &y);

    // Any change in how many fingers are down invalidates the previous position:
    // the finger the next delta would be measured from is not the one the last
    // one was measured to. Without this, resting a second finger to scroll makes
    // the pointer jump to wherever that finger landed.
    if (fingers != prevFingers_) {
        havePrev_ = false;

        if (prevFingers_ == 0 && fingers == 1 && havePos) {
            // Possible tap. Confirmed or rejected when the finger comes up.
            tapCandidate_ = !physicalButtonDown_;
            tapStartX_ = x;
            tapStartY_ = y;
            tapTimer_.start();
        } else if (fingers == 0) {
            if (tapCandidate_ && prevFingers_ == 1 && !physicalButtonDown_ &&
                tapTimer_.isValid() && tapTimer_.elapsed() <= kTapMs) {
                setButton(Qt::LeftButton, true);
                setButton(Qt::LeftButton, false);
            }
            tapCandidate_ = false;
        } else {
            // Two or more fingers, or a finger added mid-gesture: not a tap.
            tapCandidate_ = false;
        }
    }
    prevFingers_ = fingers;

    if (!havePos) {
        havePrev_ = false;
        return;
    }

    if (havePrev_) {
        const qreal dx = qreal(x - prevX_);
        const qreal dy = qreal(y - prevY_);

        const qreal spanX = qreal(maxX_ - minX_);
        const qreal spanY = qreal(maxY_ - minY_);
        const qreal fracX = dx / spanX;
        const qreal fracY = dy / spanY;

        if (std::fabs(fracX) > kJumpReject || std::fabs(fracY) > kJumpReject) {
            // Rejected as a contact swap - but the position is still current, so
            // keep it as the origin for the next delta.
            prevX_ = x;
            prevY_ = y;
            return;
        }

        // Two fingers scroll - unless a button is held, which on a clickpad is
        // how a drag is performed: one finger presses the pad down, a second
        // does the moving. Scrolling there instead of dragging would make the
        // gesture do the opposite of what it looks like.
        if (fingers == 1 || (fingers == 2 && buttons_ != Qt::MouseButtons()))
            movePointer(dx, dy);
        else if (fingers == 2)
            scroll(dx, dy);
        // Three or more fingers: no gesture. This kiosk has four screens and no
        // window management, so there is nothing a swipe could usefully mean,
        // and an accidental one must not do anything at all.

        // Tap slop: a contact that travelled too far was a drag, not a tap.
        if (tapCandidate_) {
            const qreal tx = qreal(x - tapStartX_) / spanX;
            const qreal ty = qreal(y - tapStartY_) / spanY;
            if (std::sqrt(tx * tx + ty * ty) > kTapSlop)
                tapCandidate_ = false;
        }
    }

    prevX_ = x;
    prevY_ = y;
    havePrev_ = true;
}

// ---------------------------------------------------------------------------

void Touchpad::movePointer(qreal dxUnits, qreal dyUnits)
{
    if (qFuzzyIsNull(dxUnits) && qFuzzyIsNull(dyUnits))
        return;

    const qreal fx = dxUnits / qreal(maxX_ - minX_);
    const qreal fy = dyUnits / qreal(maxY_ - minY_);
    const qreal travelled = std::sqrt(fx * fx + fy * fy);

    qreal accel = kAccelBase + kAccelGain * travelled;
    if (accel < kAccelMin) accel = kAccelMin;
    if (accel > kAccelMax) accel = kAccelMax;

    // Start from where the cursor actually is, not from where this object last
    // put it, so a USB mouse plugged in alongside the pad and this handler do
    // not fight over the pointer. The sub-pixel accumulator is kept because
    // QCursor::pos() is integral: without it, motion slow enough to produce less
    // than a pixel per report would never move the cursor at all.
    QPointF p = pos_;
    const QPoint actual = QCursor::pos();
    if ((actual - lastSent_).manhattanLength() > 1)
        p = QPointF(actual);

    p += QPointF(dxUnits * gainX_ * accel, dyUnits * gainY_ * accel);

    const QScreen *screen = QGuiApplication::primaryScreen();
    if (screen != nullptr) {
        const QRect g = screen->geometry();
        if (p.x() < g.left())        p.setX(g.left());
        if (p.x() > g.right())       p.setX(g.right());
        if (p.y() < g.top())         p.setY(g.top());
        if (p.y() > g.bottom())      p.setY(g.bottom());
    }

    pos_ = p;
    lastSent_ = p.toPoint();
    deliver(QEvent::MouseMove, Qt::NoButton);
}

void Touchpad::scroll(qreal dxUnits, qreal dyUnits)
{
    const qreal dxPx = dxUnits * gainX_;
    const qreal dyPx = dyUnits * gainY_;
    if (qFuzzyIsNull(dxPx) && qFuzzyIsNull(dyPx))
        return;

    QWindow *w = targetWindow(lastSent_);
    if (w == nullptr)
        return;

    // Traditional, not natural: two fingers moving down the pad scrolls the view
    // down, the same direction a wheel rotated towards the operator does. Qt
    // reports that as a negative angle delta, hence the sign flip. An appliance
    // whose scrolling matches the machine the operator uses every day is one
    // less thing to be surprised by while reading a transaction.
    const QPoint pixelDelta(int(-dxPx), int(-dyPx));
    const QPoint angleDelta(int(-dxPx / kPixelsPerNotch * 120.0),
                            int(-dyPx / kPixelsPerNotch * 120.0));
    if (pixelDelta.isNull() && angleDelta.isNull())
        return;

    const QPointF global(lastSent_);
    const QPointF local = QPointF(w->mapFromGlobal(lastSent_));
    QWindowSystemInterface::handleWheelEvent(w, local, global, pixelDelta, angleDelta,
                                             Qt::NoModifier, Qt::NoScrollPhase);
}

void Touchpad::setButton(Qt::MouseButton button, bool pressed)
{
    if (pressed == buttons_.testFlag(button))
        return;
    buttons_.setFlag(button, pressed);
    deliver(pressed ? QEvent::MouseButtonPress : QEvent::MouseButtonRelease, button);
}

void Touchpad::deliver(QEvent::Type type, Qt::MouseButton button)
{
    QWindow *w = targetWindow(lastSent_);
    if (w == nullptr)
        return;

    const QPointF global(lastSent_);
    const QPointF local = QPointF(w->mapFromGlobal(lastSent_));

    // Qt::MouseEventNotSynthesized is not decoration. QGuiApplicationPrivate
    // skips moving the platform cursor for events it considers synthetic, which
    // is exactly the bug this class exists to fix - a cursor that is drawn but
    // never moves.
    QWindowSystemInterface::handleMouseEvent(w, local, global, buttons_, button, type,
                                             Qt::NoModifier,
                                             Qt::MouseEventNotSynthesized);
}

QWindow *Touchpad::targetWindow(const QPoint &global) const
{
    if (QWindow *w = QGuiApplication::topLevelAt(global))
        return w;
    if (QWindow *w = QGuiApplication::focusWindow())
        return w;
    const QWindowList tops = QGuiApplication::topLevelWindows();
    return tops.isEmpty() ? nullptr : tops.first();
}

} // namespace signeros
