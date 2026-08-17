// SPDX-License-Identifier: MIT
//
// btc_signer_gui - SignerOS kiosk entry point.
//
// Two modes out of one binary:
//
//   (default)      full-screen Qt kiosk on the KMS/DRM framebuffer
//   --self-test    headless parse/inspect/sign/write/verify, machine-readable
//
// They share the signing core, the process hardening and the account they run
// as, which is what makes the self-test meaningful as a build gate.

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "core/psbt_engine.h"
#include "core/secure_memory.h"
#include "core/selftest.h"

#ifdef SIGNEROS_GUI
#include <dirent.h>
#include <fcntl.h>
#include <linux/input.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include <QApplication>
#include <QString>

#include "ui/app_window.h"
#include "ui/theme.h"
#ifdef SIGNEROS_TOUCHPAD
#include "ui/touchpad.h"
#endif
#endif

namespace {

const char *envOr(const char *name, const char *fallback)
{
    const char *v = ::getenv(name);
    return (v != nullptr && v[0] != '\0') ? v : fallback;
}

void printUsage()
{
    std::fputs(
        "SignerOS " SIGNEROS_VERSION_STR " - PSBT signer\n"
        "\n"
        "usage: btc_signer_gui [options]\n"
        "\n"
        "  -platform <plugin>       Qt platform plugin (eglfs, linuxfb)\n"
        "  --network <name>         mainnet | testnet | signet | regtest\n"
        "  --data-dir <path>        where *.psbt files are read and written\n"
        "                           (default: /mnt/data)\n"
        "  --write-final-tx         also write a broadcast-ready raw transaction\n"
        "                           when the PSBT becomes complete\n"
        "\n"
        "  --self-test              run headless and exit; prints SELFTEST: lines\n"
        "  --psbt <path>            self-test: the file to sign (default: the\n"
        "                           first unsigned *.psbt in --data-dir)\n"
        "  --mnemonic-file <path>   self-test: file holding the BIP39 mnemonic\n"
        "  --expect-blocked <path>  self-test: a PSBT with a forged change\n"
        "                           output; the run fails unless it is refused\n"
        "  --discard-output         self-test: unlink what it wrote when done\n"
        "\n"
        "  --version, --help\n",
        stderr);
}

} // namespace

#ifdef SIGNEROS_GUI
namespace {

// ---------------------------------------------------------------------------
// Input device discovery.
//
// Qt normally finds keyboards and touchscreens through libudev. There is no
// udev on SignerOS - udev needs AF_NETLINK and this kernel has no network stack
// at all - so the devices are enumerated here, classified by their evdev
// capability bits, and named to Qt explicitly.
//
// Named through QT_QPA_EVDEV_{KEYBOARD,MOUSE,TOUCHSCREEN}_PARAMETERS, NOT
// through QT_QPA_GENERIC_PLUGINS, which is what this used to do and which was
// wrong twice over:
//
//   * QGuiApplication splits that variable on ',', not ';' (qguiapplication.cpp:
//     `pluginList += envPlugins.split(',')`). One semicolon-joined string is
//     therefore a single plugin entry, so `evdevkeyboard:/dev/input/event0;
//     evdevmouse:/dev/input/event4` asks for a keyboard on the device literally
//     called "/dev/input/event0;evdevmouse" - which cannot be opened - and never
//     loads the mouse plugin at all. It only appeared to work on a machine where
//     exactly one class of device was found.
//
//   * The generic plugins instantiate a *second* QEvdev*Manager. The linuxfb and
//     eglfs plugins already create one each in createInputHandlers(); if both
//     sets end up alive on the same device node, every keystroke and every click
//     is delivered to the application twice.
//
// The QT_QPA_EVDEV_*_PARAMETERS variables are read by exactly those managers
// the platform plugin already created (QEvdevKeyboardManager and friends check
// the environment first and fall back to their plugin specification), so this
// enumeration replaces their device discovery instead of duplicating it.
//
// Must run before QApplication is constructed: Qt reads these while it
// initialises the platform plugin.
// ---------------------------------------------------------------------------

constexpr std::size_t kBitsPerLong = sizeof(unsigned long) * 8;

bool testBit(int bit, const unsigned long *arr)
{
    return (arr[bit / kBitsPerLong] >> (bit % kBitsPerLong)) & 1UL;
}

// What the enumeration found, for the two UI decisions that depend on it.
struct DetectedInput {
    // A device that moves a pointer around the screen. A touchscreen does not
    // count: you point at a touchscreen with a finger, and a cursor chasing the
    // finger is noise. A mouse, a trackpad or an absolute tablet does count,
    // because without a drawn cursor there is no way to see where the click is
    // going to land.
    bool pointer = false;

    // A real keyboard. Decides whether the on-screen keyboard is shown by
    // default: on the personal computer this image is meant to take over there
    // is always one, and the space it occupies is better spent showing the
    // operator what they are about to sign.
    bool keyboard = false;

    // Touchpads, which are not handed to Qt at all - see ui/touchpad.h. Qt has
    // no handler that fits one, so main() opens these itself once QApplication
    // exists and converts finger motion to pointer deltas.
    std::vector<std::string> touchpads;
};

DetectedInput configureInputDevices()
{
    // Respect an explicit override from the environment. Nothing is enumerated
    // on this path, so nothing is known about what is attached: the caller
    // keeps the cursor hidden, and an operator who configures input by hand can
    // set QT_QPA_FB_HIDECURSOR=0 by hand too.
    if (::getenv("QT_QPA_EVDEV_KEYBOARD_PARAMETERS") != nullptr ||
        ::getenv("QT_QPA_GENERIC_PLUGINS") != nullptr)
        return {};

    DetectedInput found;
    std::string keyboards, mice, touches;

    // Set when a device that reports absolute coordinates ends up on the mouse
    // list. It changes how Qt is asked to read that list - see the "abs" option
    // where the variables are set, at the bottom of this function.
    bool absolutePointer = false;

    DIR *d = ::opendir("/dev/input");
    if (d == nullptr) {
        std::fprintf(stderr, "signer: /dev/input is not readable; no input devices\n");
        return {};
    }

    while (const struct dirent *de = ::readdir(d)) {
        if (std::strncmp(de->d_name, "event", 5) != 0)
            continue;

        const std::string path = std::string("/dev/input/") + de->d_name;
        const int fd = ::open(path.c_str(), O_RDONLY | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0)
            continue;

        unsigned long evTypes[(EV_MAX / kBitsPerLong) + 1] = {};
        unsigned long keyBits[(KEY_MAX / kBitsPerLong) + 1] = {};
        unsigned long relBits[(REL_MAX / kBitsPerLong) + 1] = {};
        unsigned long absBits[(ABS_MAX / kBitsPerLong) + 1] = {};
        unsigned long propBits[(INPUT_PROP_MAX / kBitsPerLong) + 1] = {};

        if (::ioctl(fd, EVIOCGBIT(0, sizeof(evTypes)), evTypes) < 0) {
            ::close(fd);
            continue;
        }
        if (testBit(EV_KEY, evTypes))
            ::ioctl(fd, EVIOCGBIT(EV_KEY, sizeof(keyBits)), keyBits);
        if (testBit(EV_REL, evTypes))
            ::ioctl(fd, EVIOCGBIT(EV_REL, sizeof(relBits)), relBits);
        if (testBit(EV_ABS, evTypes))
            ::ioctl(fd, EVIOCGBIT(EV_ABS, sizeof(absBits)), absBits);
        // Device properties. Never fatal: a driver that sets none leaves this
        // zeroed, which the classification below treats as "no opinion".
        ::ioctl(fd, EVIOCGPROP(sizeof(propBits)), propBits);
        ::close(fd);

        // Absolute coordinates plus touch. TWO different devices land here and
        // they need opposite treatment, which is what INPUT_PROP_* is for:
        //
        //   INPUT_PROP_DIRECT   a touchscreen. The operator points at the thing
        //                       they are touching, so the coordinate IS the
        //                       answer and Qt's touchscreen handler is right.
        //   INPUT_PROP_POINTER  a touchpad. The operator points at the screen
        //                       via a pad somewhere else entirely, so the
        //                       coordinate means nothing until it is turned
        //                       into a delta. Qt has no handler that does that
        //                       (that is libinput's job, and libinput needs
        //                       udev, which needs a network stack this kernel
        //                       does not have), so ui/touchpad.h does it.
        //
        // Getting this wrong is not a cosmetic failure. A touchpad driven as a
        // touchscreen leaves the pointer motionless - Qt does not move the
        // platform cursor for touch-synthesised events - and puts every click
        // at the finger's position on the pad rather than the pointer's
        // position on the screen. It looks exactly like broken hardware.
        //
        // BTN_TOOL_FINGER is the fallback for a driver old enough to set no
        // property bits at all: a touchscreen has no concept of a finger tool.
        // With neither signal the device is treated as a touchscreen, which is
        // what this branch has always assumed.
        if (testBit(EV_ABS, evTypes) && testBit(ABS_X, absBits) &&
            testBit(ABS_Y, absBits) &&
            (testBit(BTN_TOUCH, keyBits) || testBit(ABS_MT_POSITION_X, absBits))) {

            const bool isPad = !testBit(INPUT_PROP_DIRECT, propBits) &&
                               (testBit(INPUT_PROP_POINTER, propBits) ||
                                testBit(BTN_TOOL_FINGER, keyBits));
#ifdef SIGNEROS_TOUCHPAD
            if (isPad) {
                found.touchpads.push_back(path);
                continue;
            }
#else
            // Built without QPA private headers, so there is no touchpad
            // handler to hand it to. Falling back to the touchscreen handler
            // keeps taps working, badly, rather than losing the device.
            if (isPad)
                std::fprintf(stderr,
                             "signer: %s is a touchpad, but this build has no "
                             "touchpad support; treating it as a touchscreen\n",
                             path.c_str());
#endif
            touches += ":" + path;
            continue;
        }

        // A mouse or trackpad reports relative motion plus a button.
        if (testBit(EV_REL, evTypes) && testBit(REL_X, relBits) &&
            testBit(BTN_LEFT, keyBits)) {
            mice += ":" + path;
            continue;
        }

        // A keyboard has letter keys. Checking a couple of them rules out power
        // buttons and lid switches, which also advertise EV_KEY.
        if (testBit(EV_KEY, evTypes) && testBit(KEY_A, keyBits) &&
            testBit(KEY_Z, keyBits) && testBit(KEY_ENTER, keyBits)) {
            keyboards += ":" + path;
            continue;
        }

        // An absolute pointing device that is not a touchscreen: QEMU's
        // usb-tablet, and the "absolute pointer" mode most hypervisor guest
        // additions and KVM switches present. It reports ABS_X/ABS_Y and a
        // mouse button, but no BTN_TOUCH and no multitouch slots, so the
        // touchscreen test above does not claim it, and it has no REL_X, so
        // neither does the mouse test.
        //
        // It goes to the mouse handler rather than the touch one because
        // QEvdevMouseHandler reads absolute axes natively - it decides between
        // relative and absolute from EVIOCGABS when it opens the device -
        // whereas QEvdevTouchScreenHandler expects touch semantics this device
        // does not have.
        //
        // Until this branch existed the device matched nothing and was dropped
        // without a word, which is what left the QEMU window with no usable
        // pointer at all.
        if (testBit(EV_ABS, evTypes) && testBit(ABS_X, absBits) &&
            testBit(ABS_Y, absBits) && testBit(BTN_LEFT, keyBits)) {
            mice += ":" + path;
            absolutePointer = true;
            continue;
        }

        // Nothing claimed it. Worth a line: a device that matches no branch is
        // invisible to the GUI, and it was the silence here - not the missing
        // branch - that made the last one of these take a rebuild to find.
        // Power buttons and lid switches land here legitimately.
        std::fprintf(stderr, "signer: %s unclassified (abs=%d rel=%d key=%d)\n",
                     path.c_str(), testBit(EV_ABS, evTypes) ? 1 : 0,
                     testBit(EV_REL, evTypes) ? 1 : 0,
                     testBit(EV_KEY, evTypes) ? 1 : 0);
    }
    ::closedir(d);

    if (keyboards.empty() && mice.empty() && touches.empty() &&
        found.touchpads.empty()) {
        // Not fatal: a touchscreen-less, keyboard-less machine can still be
        // driven by whatever the QPA plugin finds itself, and the operator needs
        // to see the message rather than a silent dead kiosk.
        std::fprintf(stderr, "signer: no input devices detected in /dev/input\n");
        return {};
    }

    // Each variable holds one colon-separated argument list; anything starting
    // with /dev/ is taken as a device, everything else as an option
    // (QEvdevUtil::parseSpecification).
    //
    // grab=1 is EVIOCGRAB: the kernel stops delivering these events to any other
    // reader, including the framebuffer console. Belt and braces against the
    // console echoing a mnemonic onto the panel if the VT handover in
    // signer-session ever fails, and it means no second process on the image can
    // observe what is being typed.
    //
    // disable-zap turns off Qt's built-in Ctrl+Alt+Backspace handler, which
    // otherwise calls QCoreApplication::quit() - a key chord that terminates the
    // signer mid-transaction is not something a kiosk should ship with.
    auto setInput = [](const char *var, const char *options,
                       const std::string &devices) {
        if (devices.empty())
            return;
        const std::string value = std::string(options) + devices;
        ::setenv(var, value.c_str(), 0);
        std::fprintf(stderr, "signer: %s=%s\n", var, value.c_str());
    };
    // "abs" is not optional decoration when an absolute pointer is present, and
    // its absence does not degrade gracefully. QEvdevMouseHandler reads the
    // literal token out of this string and nowhere else:
    //
    //     else if (arg == QLatin1String("abs"))
    //         abs = true;
    //
    // Without it the handler still receives every ABS_X/ABS_Y event but treats
    // the coordinates as relative deltas (sendMouseEvent: `x = m_x - m_prevx`).
    // A tablet reporting a jump to 29160 then reads as "move 29160 pixels
    // right", the pointer is pinned in a corner, and clicks land nowhere near
    // where the operator aimed - which looks exactly like a pointer that does
    // not work at all.
    //
    // Safe to set whenever any absolute device is on the list even though the
    // string is shared by all of them: the handler calls getHardwareMaximum()
    // per device and turns m_abs back off for anything that has no ABS_X/ABS_Y,
    // so an ordinary relative mouse alongside a tablet is unaffected.
    setInput("QT_QPA_EVDEV_KEYBOARD_PARAMETERS", "grab=1:disable-zap", keyboards);
    setInput("QT_QPA_EVDEV_MOUSE_PARAMETERS",
             absolutePointer ? "grab=1:abs" : "grab=1", mice);
    setInput("QT_QPA_EVDEV_TOUCHSCREEN_PARAMETERS", "", touches);

    // A touchpad counts as a pointer: it is about to drive a drawn cursor, and
    // without one there is nothing on screen saying where a tap will land.
    found.pointer = !mice.empty() || !found.touchpads.empty();
    found.keyboard = !keyboards.empty();
    return found;
}

} // namespace
#endif // SIGNEROS_GUI

int main(int argc, char *argv[])
{
    // Before anything else: no core dumps, not dumpable, everything mlocked.
    signeros::hardenProcess();

    signeros::SelfTestOptions st;
    st.dataDir = envOr("SIGNEROS_DATA_DIR", "/mnt/data");
    st.network = envOr("SIGNEROS_NETWORK", SIGNEROS_DEFAULT_NETWORK);
    bool selfTest = false;
    bool writeFinalTx = (std::strcmp(envOr("SIGNEROS_WRITE_FINAL_TX", "0"), "1") == 0);

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        auto next = [&](const char *what) -> const char * {
            if (i + 1 >= argc) {
                std::fprintf(stderr, "signer: %s needs a value\n", what);
                std::exit(2);
            }
            return argv[++i];
        };

        if (std::strcmp(a, "--self-test") == 0)
            selfTest = true;
        else if (std::strcmp(a, "--psbt") == 0)
            st.psbtPath = next(a);
        else if (std::strcmp(a, "--mnemonic-file") == 0)
            st.mnemonicFile = next(a);
        else if (std::strcmp(a, "--expect-blocked") == 0)
            st.blockedPsbtPath = next(a);
        else if (std::strcmp(a, "--data-dir") == 0)
            st.dataDir = next(a);
        else if (std::strcmp(a, "--network") == 0)
            st.network = next(a);
        else if (std::strcmp(a, "--write-final-tx") == 0)
            writeFinalTx = true;
        else if (std::strcmp(a, "--discard-output") == 0)
            st.keepOutput = false;
        else if (std::strcmp(a, "--help") == 0 || std::strcmp(a, "-h") == 0) {
            printUsage();
            return 0;
        } else if (std::strcmp(a, "--version") == 0) {
            // One version, from VERSION at the repo root: the same string the
            // image file name carries and the kiosk shows on screen.
            std::printf("SignerOS %s (btc_signer_gui, libwally-core %s, "
                        "default network %s)\n",
                        SIGNEROS_VERSION_STR,
                        signeros::PsbtEngine::libraryVersion().c_str(),
                        SIGNEROS_DEFAULT_NETWORK);
            return 0;
        }
        // Anything else (notably -platform <plugin>) is left for Qt.
    }

    st.writeFinalTx = writeFinalTx;

    if (selfTest)
        return signeros::runSelfTest(st);

#ifndef SIGNEROS_GUI
    std::fputs("signer: this build has no user interface "
               "(configured with -DSIGNEROS_BUILD_GUI=OFF).\n"
               "        Use --self-test.\n", stderr);
    return 2;
#else
    bool netOk = false;
    const signeros::Network network = signeros::networkFromString(st.network, &netOk);
    if (!netOk) {
        std::fprintf(stderr, "signer: unknown network '%s'\n", st.network.c_str());
        return 2;
    }

    std::string initWarning;
    if (!signeros::PsbtEngine::initLibrary(&initWarning)) {
        std::fputs("signer: libwally-core failed to initialise\n", stderr);
        return 3;
    }
    if (!initWarning.empty())
        std::fprintf(stderr, "signer: %s\n", initWarning.c_str());

    const DetectedInput input = configureInputDevices();

    // No window manager, no compositor, no session bus. Qt is asked for exactly
    // one full-screen surface on the framebuffer.
    //
    // The cursor follows what is actually attached. This started life
    // unconditionally hidden, which is right for the touchscreen panel the
    // appliance is built around - a cursor trailing a finger is just noise - but
    // it makes a machine driven by a mouse or a trackpad unusable, because
    // nothing on screen says where the click is about to land. That is the state
    // the QEMU window was in.
    //
    // QFbCursor reads this variable once, at construction: set means visible
    // when the value is 0, and unset means visible. Written with overwrite=0 so
    // an operator who sets it explicitly still wins, and read back immediately
    // afterwards so that the platform cursor and the per-widget cursors below
    // can never disagree about whether there is one.
    ::setenv("QT_QPA_FB_HIDECURSOR", input.pointer ? "0" : "1", 0);
    const bool showCursor =
        (std::strcmp(envOr("QT_QPA_FB_HIDECURSOR", "1"), "0") == 0);
    signeros::theme::setCursorVisible(showCursor);
    std::fprintf(stderr, "signer: mouse cursor %s\n",
                 showCursor ? "visible" : "hidden");

    QApplication app(argc, argv);
    app.setApplicationName(QStringLiteral("SignerOS"));
    app.setApplicationVersion(QStringLiteral(SIGNEROS_VERSION_STR));

#ifdef SIGNEROS_TOUCHPAD
    // After QApplication, not before: the pointer gain comes from the screen
    // geometry and the events go into this event loop. Parented to app, so a
    // handler's descriptor and its EVIOCGRAB are released on the way out.
    for (const std::string &pad : input.touchpads) {
        if (signeros::Touchpad::open(QString::fromStdString(pad), &app) == nullptr)
            std::fprintf(stderr, "signer: touchpad %s: not usable, ignored\n",
                         pad.c_str());
    }
#endif

    // Fonts come from QT_QPA_FONTDIR (there is no fontconfig on the image), so
    // log what Qt actually resolved. QFontDatabase is deliberately not used:
    // its API is static in Qt6 and instance-based in Qt5, and this binary is
    // built against both.
    std::fprintf(stderr, "signer: base font resolved to '%s'\n",
                 app.font().family().toLocal8Bit().constData());

    signeros::applyTheme(&app);

    signeros::AppConfig cfg;
    cfg.network = network;
    cfg.dataDir = QString::fromStdString(st.dataDir);
    cfg.dataLabel = QString::fromUtf8(envOr("SIGNEROS_DATA_LABEL", "PSBT_DATA"));
    cfg.writeFinalTx = writeFinalTx;
    cfg.physicalKeyboard = input.keyboard;

    signeros::AppWindow window(cfg);
    window.showFullScreen();

    const int rc = app.exec();
    signeros::PsbtEngine::shutdownLibrary();
    return rc;
#endif
}
