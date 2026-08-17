// SPDX-License-Identifier: MIT
//
// touchpad.h - relative pointer motion from a laptop touchpad.
//
// WHY THIS FILE EXISTS
//
// Qt's evdev input stack has two handlers: a mouse handler that wants relative
// motion (REL_X/REL_Y), and a touchscreen handler that wants absolute touch
// semantics. A touchpad is neither. It reports absolute finger positions like a
// touchscreen, but the operator is pointing at the *screen*, not at the pad, so
// those positions have to be turned into pointer deltas before they mean
// anything. On a normal Linux system libinput does that. libinput needs udev,
// udev needs AF_NETLINK, and this kernel has no network stack at all - see
// guardrail 1 in the README - so there is nothing on the image to do it.
//
// Before this existed, a multitouch touchpad matched the touchscreen branch in
// main.cpp and was handed to QEvdevTouchScreenHandler. The result on real
// hardware: the pointer never moved (Qt does not move the platform cursor for
// touch-synthesised mouse events, QGuiApplicationPrivate::processMouseEvent
// skips the cursor for anything marked synthetic) and taps landed wherever on
// the screen the finger happened to sit on the pad. QEMU never showed this,
// because scripts/test_in_qemu.sh attaches a usb-tablet, which has no BTN_TOUCH
// and no MT slots and so takes the absolute-pointer branch instead.
//
// So this class reads the pad's evdev node itself and feeds
// QWindowSystemInterface directly. Going in at that level rather than
// synthesising QMouseEvents onto widgets is what keeps hover highlighting,
// press-move-release grabbing and the drawn cursor working: the events are
// indistinguishable from a real mouse's, and because they are not marked
// synthetic the platform cursor follows them.
//
// It is deliberately independent of *which* touchpad this is. Everything that
// varies between an I2C-HID clickpad, a Synaptics RMI4 pad and an Elan PS/2 pad
// is read from the device: the axis ranges come from EVIOCGABS and the pointer
// gain is expressed as a fraction of the pad traversed, so no constant here is
// tied to one machine's hardware.

#pragma once

#include <QElapsedTimer>
#include <QEvent>
#include <QObject>
#include <QPoint>
#include <QPointF>
#include <QString>
#include <QVector>

QT_BEGIN_NAMESPACE
class QSocketNotifier;
class QWindow;
QT_END_NAMESPACE

struct input_event;

namespace signeros {

class Touchpad : public QObject {
    Q_OBJECT

public:
    // Opens devicePath and starts feeding pointer events. Returns nullptr if the
    // node cannot be opened or does not look like a touchpad, having said why on
    // stderr - which under signeros.inputdebug=1 is the panel.
    //
    // Must be called after QApplication exists: the gain is derived from the
    // screen geometry and events are posted into the GUI event loop.
    static Touchpad *open(const QString &devicePath, QObject *parent = nullptr);

    ~Touchpad() override;

private:
    explicit Touchpad(int fd, const QString &path, QObject *parent);

    bool init();
    void readEvents();
    void handleEvent(const struct input_event &ev);
    void frameComplete();

    // One MT contact. trackingId < 0 means the slot is empty.
    struct Contact {
        int trackingId = -1;
        int x = 0;
        int y = 0;
    };

    int activeContacts() const;
    bool primaryPosition(int *x, int *y) const;

    void movePointer(qreal dxUnits, qreal dyUnits);
    void scroll(qreal dxUnits, qreal dyUnits);
    void setButton(Qt::MouseButton button, bool pressed);
    void deliver(QEvent::Type type, Qt::MouseButton button);
    QWindow *targetWindow(const QPoint &global) const;

    int fd_ = -1;
    QString path_;
    QSocketNotifier *notifier_ = nullptr;

    // Axis geometry, from EVIOCGABS.
    int minX_ = 0, maxX_ = 0, minY_ = 0, maxY_ = 0;
    int resX_ = 0, resY_ = 0;          // units per mm, 0 when the pad does not say
    bool multitouch_ = false;

    // Per-axis pointer gain: screen pixels per pad unit. See kPadTraversal.
    qreal gainX_ = 1.0;
    qreal gainY_ = 1.0;

    // Contact state.
    QVector<Contact> contacts_;
    int currentSlot_ = 0;
    int singleX_ = 0, singleY_ = 0;    // ABS_X/ABS_Y, for pads with no MT slots
    bool singleTouch_ = false;         // BTN_TOUCH
    bool toolFinger_ = false;
    bool toolDouble_ = false;
    bool toolTriple_ = false;

    // Motion tracking across SYN frames.
    int prevFingers_ = 0;
    int prevX_ = 0, prevY_ = 0;
    bool havePrev_ = false;

    // Tap-to-click.
    QElapsedTimer tapTimer_;
    bool tapCandidate_ = false;
    int tapStartX_ = 0, tapStartY_ = 0;
    bool physicalButtonDown_ = false;

    // Pointer state.
    QPointF pos_;
    QPoint lastSent_;
    Qt::MouseButtons buttons_;
};

} // namespace signeros
