# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

SignerOS is an air-gapped, RAM-only x86_64 UEFI live image that does three things:
creates a wallet, exports watch-only keys for a mnemonic the operator already has, and
signs Bitcoin PSBTs. **The target machine is an ordinary personal computer** — a laptop or
desktop the operator already owns, booted from a USB stick — not a purpose-built
appliance, and **a mouse or trackpad is the first-choice input, not a fallback**. See
[Who it runs on, and what drives it](#who-it-runs-on-and-what-drives-it) before touching
anything under `src/btc_signer_gui/src/ui/`.

It is a Buildroot `BR2_EXTERNAL` tree plus one Qt Widgets kiosk application.
`README.md` is the design document and is unusually complete — read the relevant
section before changing anything in `buildroot-external/`.

`buildroot/` and `output/` are gitignored build artefacts. `buildroot/` is a pinned
upstream checkout (`BR_VERSION` in `scripts/build.sh`, currently `2026.02.3`) that
`build.sh` clones and re-checks on every run — never edit it.

## Commands

`make help` is authoritative. The Makefile is a thin wrapper; the scripts are the real
interface and work standalone.

```bash
make host-test WALLY=build   # FAST LOOP: builds src/core without Qt, signs a fixture,
                             # verifies independently. Seconds. Use this first.
make host-test               # same, reusing an already-built libwally in output/host-selftest
make check-scripts           # shell/python syntax + fixture crypto self-check. Cheap pre-commit gate.

make image                   # full build (30-90 min first time: toolchain + Qt)
make app                     # re-sync src/ and rebuild the kiosk, then re-make images
make reconfigure             # after editing the defconfig or a kernel fragment
make test                    # boot both images under UEFI in QEMU, verify end to end
make test-selftest           # just run 1 (headless signing)
make test-gui                # just run 2 (framebuffer pixel check)
make gui                     # open the production kiosk in a QEMU window
make menuconfig / source / clean / distclean
make flash DEV=/dev/sdX [EXPAND=1]
make version                 # what this tree builds as, from VERSION
```

Narrower invocations (no `make` equivalent):

```bash
./scripts/build.sh --no-test-image        # halves kernel work when only iterating on the UI
./scripts/build.sh --fragment eglfs       # or --fragment gpu-firmware
./scripts/test_in_qemu.sh --interactive --keep
python3 scripts/make_test_data.py self-check      # crypto vs published test vectors
python3 scripts/make_test_data.py generate --out-dir DIR [--network testnet]
python3 scripts/make_test_data.py verify --dir DIR
python3 scripts/make_test_data.py wallet-expect --network testnet [--account N]
                                  [--section accounts|cosigners]
                                  # the account xpubs and first addresses a
                                  # watch-only export MUST contain, derived
                                  # independently of libwally; --section
                                  # cosigners does the same for the BIP48
                                  # multisig keys, which have no address.
                                  # host_selftest.sh diffs both sections for
                                  # accounts 0 and 1 against this.
```

There is no unit-test framework. The three test layers are: `make check-scripts`
(syntax + fixture crypto), `make host-test` (signing core on the host), `make test`
(the real image under QEMU). Logs from a failed `host-test` land in
`output/host-selftest/{cmake,compile,wally-build}.log`.

## Architecture

### The one thing that shapes everything else

The initramfs and the kernel command line are **compiled into the kernel**
(`BR2_TARGET_ROOTFS_INITRAMFS=y`, `CONFIG_CMDLINE_OVERRIDE=y`), so the signed PE binary
at `EFI/BOOT/bootx64.efi` *is* the entire boot payload. There is no bootloader. Three
consequences you will hit:

- **Nothing can vary the command line at boot**, including the test harness. That is
  why `signeros-test.img` is a *second kernel build* — the `signeros-test-image` target
  in `buildroot-external/external.mk`, run by `build.sh` after the main build. Read the
  long comment there before touching it: the `.config` restore and the `touch` that
  follows it are load-bearing, and getting them wrong once shipped a self-test kernel
  as the production appliance.
- **Any change under `src/` relinks and recompresses the kernel**, twice if the test
  image is built. `make app` is minutes, not seconds.
- Runtime settings in `/etc/signeros.conf` are overridable as `signeros.<name>=<value>`
  on the command line — which means a rebuild, not a boot-time edit.

### Who it runs on, and what drives it

A personal computer the operator already owns, booted from a USB stick. **A mouse or a
trackpad is the primary pointing device and a physical keyboard is assumed present.**
Touchscreen panels are supported and must keep working, but they are the second case,
not the one to design for — do not reason about the UI as if it were a kiosk panel with
no mouse.

None of this is configured. `configureInputDevices()` in `main.cpp` enumerates
`/dev/input/event*` at startup, because there is no udev, and exactly two UI decisions
follow from what it finds:

| Found | Consequence |
|---|---|
| a pointer — mouse, trackpad or absolute tablet. A touchscreen deliberately does **not** count | the framebuffer cursor is drawn (`QT_QPA_FB_HIDECURSOR=0`, mirrored into `theme::cursorVisible()` so the platform cursor and the per-widget cursors cannot disagree). With no pointer it stays hidden: a cursor chasing a finger is noise |
| a keyboard | `AppConfig::physicalKeyboard`, which hides the on-screen keyboard by default so the space goes to the content instead. **F2** brings it back on the two entry screens |

What that means when you add or change a screen:

- **Every flow must be completable with the keyboard alone *and* with the pointer
  alone.** Optional aids may be one or the other — the word-count buttons are
  click-only, F4 does the same job from the keyboard — but nothing on the path to
  a signature or an export may be.
- Keyboard handling on an entry screen lives in that screen's `keyPressEvent`, not in
  focus traversal. The two mnemonic **grids** — `screen_create`'s verification and
  `screen_import`'s entry — are the worked example, and they behave identically: Space,
  Enter and → finish a cell, ←/→/↑/↓ and Home/End move between cells, clicking a cell
  goes straight to it, and Backspace in an empty cell steps back into the previous one.
  The on-screen keyboard reaches the same operations for the touch case.
- **The cursor is a cell index, not the end of the buffer.** It used to be the latter,
  and correcting word 3 of 24 meant re-typing 21 words that were already right. What
  makes the current behaviour possible is `SecureString`'s *grid view*
  (`setSlotCount`/`appendToSlot`/`clearSlot`/…): the buffer holds one field per cell,
  separated by exactly one space, and a field may be **empty**. So the number of
  separators *is* the cell count — there is no second piece of state to drift — and
  `wordCount()` keeps meaning "cells that are filled", which makes
  `wordCount() == slotCount()` the test for a complete grid and guarantees a complete
  grid is already in the single-space form BIP39 wants. Editing in the middle lives in
  `secure_memory.cpp` (`insertAt`/`eraseAt`, private) and wipes the tail it shifts past
  rather than leaving it behind the terminator.
- The entry screens set `Qt::NoFocus` on **every** button, so that Space reaches the
  secure buffer instead of re-triggering the last button pressed. The cost is that those
  buttons are pointer-only, which is fine for an optional aid and not fine on the
  critical path — which is why switching between the mnemonic and passphrase fields has
  a key of its own (**F3**) on both `screen_sign` and `screen_import`, and why the word
  count on `screen_import` has **F4**. Without F3 a wallet with a passphrase is unusable
  on a keyboard-driven machine; it was, until 2026-08-09.
- **The on-screen keyboard is a layer, and it belongs to the screen.** It used
  to be a widget in each page's column, so every page had to find room for it —
  and the pages that most need a keyboard are the ones with no room, which is
  how you get key rows a few pixels tall on exactly the screens somebody is
  typing a seed into. `OskPanel` is a child of the *screen*, positioned across
  the bottom on top of whatever page is showing, opaque, one per screen. It
  carries three things the pages therefore do not: an **echo line** (the field
  being typed into is usually underneath it now), the **BIP39 suggestions**
  (the page's own row is under the panel and unreachable — the words move into
  the panel while it is up and back to the page when it is down, never both),
  and a **"hide keys"** key (the page's buttons are behind it too). Every page that takes typing also carries a visible
  **On-screen keys (F2)** button — F2 alone is not discoverable, and a laptop
  that reports a keyboard may still be used as a tablet.
- **The screen owns the keyboard; a page inside its `QStackedWidget` must not.**
  Every screen sets `Qt::NoFocus` on everything it contains and keeps the focus
  itself, and that is not only about the space bar. Two ways it was broken, both
  found by driving the UI rather than by reading it:
  - a **`QScrollArea` defaults to `WheelFocus`**, which made it the one focusable
    widget on the signing screen's confirmation page, so it took the focus when
    the page appeared - after `showConfirm()` had asked for it - and the first
    Enter there did nothing. Every scroll area on a page whose buttons are
    `NoFocus` now sets `NoFocus` too.
  - a page that reads the keyboard itself gets **some** keys and not others:
    `ui/save_as.h`'s field was a `QLineEdit` first (Return consumed, no
    `returnPressed`, no propagation), then a hand-drawn field with its own
    `keyPressEvent` (letters arrived, Return did not - traced with the screen
    and the page each reporting what they saw). It is now driven by the screen
    calling `SaveAsPage::handleKey()`, which is how every other field on this
    machine works. Enter on those pages is answered in `AppWindow::eventFilter`
    for the same reason.
- **A field nobody can see the focus of is a field nobody trusts.** The same NoFocus rule
  means Qt draws no focus ring and no caret anywhere on the entry screens — the screen
  holds the focus and routes characters into a `SecureString` itself — so the chrome has
  to be drawn by hand. `screen_sign` is the worked example: the mnemonic and the
  passphrase are **two `theme::card()`s, both on screen at once**, the active one carrying
  an accent border (`theme::setCardFocused()`), an accent caption and a blinking caret
  appended to the label text, and a click anywhere on either card moves the typing there.
  It replaced a pair of "Typing: key / Typing: passphrase" toggle buttons — a tab strip
  in all but name, which hid the passphrase behind a control you had to know about and
  said nothing about where the next keystroke would land. Do not put either field back
  behind a tab, and do not let one be the only one visible.
- `make gui` gives you a QEMU window with a pointer and a keyboard, so it exercises both
  of those. It proves nothing about touchpads (`ui/touchpad.cpp`): `usb-tablet` is an
  absolute pointer, not a pad.

### The guardrails are mechanically enforced

`buildroot-external/board/signeros/post-build.sh` fails the build if any of these is
lost, checked against the *generated* artefacts rather than the defconfig: `CONFIG_NET`
surviving kconfig, any BusyBox networking applet, any X11/Wayland/display-manager
binary, any setuid/setgid file, an unresolvable `DT_NEEDED` or a build-host `RUNPATH`,
a missing `CONFIG_CMDLINE_OVERRIDE`, or a production command line containing
`signeros.selftest=1` or a serial console. `scripts/test_in_qemu.sh` re-proves the
runtime half inside the booted image (`socket()` returns `ENOSYS`, `/proc/net` absent,
mount flags, the change-forgery refusal).

If a guardrail check fails, the check is almost certainly right. Fix the cause.

### Layers

| Where | What |
|---|---|
| `src/btc_signer_gui/src/core/` | **No Qt header, ever.** `psbt_engine` (libwally: load/inspect/key/sign/write, plus `bip39UnknownSlots()`), `secure_memory` (inline, mlock'd, self-wiping containers, and the *grid view* the mnemonic screens edit through), `entropy` (the multi-source pool a new seed comes from), `wallet_export` (mnemonic generation, account xpubs, the BIP48 cosigner keys, the descriptor file), `selftest` (headless end-to-end, including the grid arithmetic — the screens are Qt and cannot be driven from that binary, but every operation they call can). This is what `host_selftest.sh` builds with `-DSIGNEROS_BUILD_GUI=OFF`. |
| `src/btc_signer_gui/src/ui/` | Qt Widgets: splash → home → (create \| scan → inspect → sign), plus shutdown, `osk_panel` (the on-screen keyboard, as a layer over the page rather than a row in it — one per screen, with its own echo line and "hide keys"), `save_as` (the page that names an output file, shared by all three writers), and `seed_view` — which both *paints* a mnemonic straight from the SecureString (a QLabel would mean assembling one into a QString) and *is* the entry grid: it splits on every separator so an empty cell stays a cell, takes a bitmask of wrong cells rather than one index, and emits `cellClicked` so a word can be corrected with the pointer. Draws on `/dev/fb0` via the linuxfb QPA plugin (eglfs is a fragment). |
| `src/btc_signer_gui/src/ui/screen_import.{h,cpp}` | Existing recovery words → the same watch-only export. Almost no new machinery: `buildWalletExport()` does not care where the mnemonic came from. What it adds is the **review page** — fingerprint and first addresses before the file exists — because a mistyped word is caught by the BIP39 checksum and a mistyped passphrase never is. The account (0-9) is selectable here and fixed at 0 when creating. Entry is the same numbered grid `screen_create` verifies into, with the word count chosen here (the seed was made elsewhere, so the device cannot know it) and the words shown in clear — creation masks its grid so the operator copies from paper rather than from the screen, and here the paper *is* the source. `bip39UnknownSlots()` marks a cell that is not a wordlist entry as it is typed, which is the question `bip39Validate()` cannot answer: it can only say the whole mnemonic is wrong. |
| `src/btc_signer_gui/src/ui/secret_buffers.h` | The only four SecureStrings in the process: mnemonic, passphrase, passphrase-again, verification. Shared by the signing, creation **and import** screens on purpose — a second pair in another translation unit would be two more page ranges that can hold a seed, wiped by a different code path. The grids do not change that: they add slot structure *inside* the same buffer rather than a parallel array of words, which would have been exactly the second copy this file exists to prevent. |
| `src/btc_signer_gui/src/main.cpp` | The kiosk *and* `--self-test` in one binary; also enumerates `/dev/input/event*` itself, because there is no udev. Classification is by evdev capability bits plus `INPUT_PROP_DIRECT`/`INPUT_PROP_POINTER` — a touchscreen and a touchpad are otherwise indistinguishable and need opposite treatment. What the result is used for: [Who it runs on](#who-it-runs-on-and-what-drives-it). |
| `src/btc_signer_gui/src/ui/touchpad.cpp` | Touchpad → pointer deltas, fed to `QWindowSystemInterface`. Qt's evdev stack has no touchpad handler; libinput does, but it needs udev, which needs netlink. QEMU's `usb-tablet` does not exercise this path, so `make gui` proves nothing about touchpads. |
| `buildroot-external/board/signeros/rootfs-overlay/` | BusyBox init: `S00early` (read-only root), `S01mount-data` (zero-trust mount), `S99signer` → `signer-session`. |
| `scripts/make_test_data.py` | Pure-stdlib reimplementation of RIPEMD-160, secp256k1, BIP32/39, bech32, PSBT, BIP143 sighash. Deliberate duplication: libwally must not be the thing that confirms libwally. Prove it with `self-check` before trusting a result from it. |

### Conventions that are not obvious

- **Exit code 42** is the entire privileged interface. The kiosk runs as uid 1000 with
  no setuid binary anywhere; it exits 42 and root `signer-session` runs
  `secure-poweroff`. Do not add a privileged helper.
- **Change is proved, not believed.** Outputs go through five `OutputOwnership` states;
  only `Verified` (our master re-derives the path *and* the rebuilt scriptPubKey matches
  byte for byte) is shown as change, and `Mismatch` blocks signing outright. The
  negative fixture `forged_change.psbt.bad` exists for this and both test layers fail if
  the engine ever signs it.
- **Refusals are refusals.** A PSBT missing a previous output for any input has an
  unknown fee and is refused with no override path. Keep it that way.
- **The passphrase is shown in clear and typed twice, everywhere it is entered.**
  It is the one secret on this machine with nothing behind it: any bytes are
  legal, so a wrong one silently derives a different, valid, empty wallet. The
  two checks catch different failures and both are needed — showing the
  characters catches the keyboard layout (this build reads every keyboard as
  US), and a second entry catches a slip, which no amount of looking will. An
  **empty** passphrase is simply accepted: most wallets have none, and an "are
  you sure?" in front of the common case is a step everybody learns to press
  past — it also had to appear from nowhere on an already full page, which is
  a layout this UI cannot afford. `passphraseConfirmBuffer()` is the fourth
  secure buffer and `passphraseConfirmed()` the only comparison — do not put a
  passphrase behind a reveal toggle again, and do not derive from an
  unconfirmed one.
- **Every file this machine writes is named by the operator.** Both writers take
  a file name (`PsbtEngine::writeResult`, `writeWalletExport`); the screens get
  it from the shared `ui/save_as.h` page, which offers the old timestamped name
  as the default so Enter is still the whole interaction. The rules for what a
  name may be live in `sanitiseFileName()` — one path component, printable
  ASCII, no leading dot, extension enforced — and are applied again inside the
  writers, because a UI that forgot to sanitise must not be able to write
  `../something`. A name already in use is now an error rather than a silent
  `-2` suffix. `runFileNameChecks()` in `core/selftest.cpp` is the build gate.
  On the signing screen the order is sign → wipe → name → write, so the naming
  step holds no key material and a failed write can be retried from it.
- **Key material** lives only in `SecureString`/`SecureBuffer<N>`/`SecureObject<T>`
  file-scope statics, never on the heap, never inside a `QString`. Keystrokes come from
  `QKeyEvent::key()`, not `text()` — except `ui/save_as.h`, which types a file
  name rather than a secret and reads `text()` so that dots and dashes survive.
  libwally is built `--disable-builtin-memset` and
  CMake passes `-fno-builtin-memset` so the wipes cannot be optimised away.
  There is exactly **one** master private key slot in the address space
  (`processMasterKey()` in `psbt_engine.cpp`); wallet creation derives into that
  same slot rather than opening a second one, and clears it before returning.
- **A created wallet writes public keys and nothing else.** No mnemonic, seed,
  xprv, recovery file, temporary file or log line derived from the seed reaches
  any medium, ever — `buildWalletExport()` and the whole of `screen_create` are
  shaped by that one rule. The self-test scans the rendered export for every word
  of the mnemonic and for `xprv`/`tprv`/`zprv`-shaped strings, so it is a build
  gate rather than a comment. The consequence is that the operator's
  transcription is the only backup, which is why every word has to be typed back
  before the export is offered — do not add a "skip verification" path.
- **A multisig cosigner key is not an account.** The export ends with this
  seed's BIP48 keys (`m/48'/coin'/account'/2'` and `.../1'`) so a SignerOS
  machine can be one signer of several, and they live in their own
  `CosignerKey` struct rather than as two more `AccountExport`s. Two of the
  four things an `AccountExport` promises cannot exist for a multisig key: a
  multisig wallet is undefined until every cosigner is known, so there is no
  descriptor and no first address, and those fields left empty render as
  "(could not be derived)" - a failure message for something that is not a
  failure. What the block carries instead is `keyOrigin`,
  `[fingerprint/48h/0h/0h/2h]xpub...`, which is what a coordinator asks each
  signer for. Nothing in the create or import flow asks about multisig: no new
  screen, no new question, one dim line on the review and result pages saying
  the keys are in the file. The signing half needed no change at all - it
  already verifies P2WSH/P2SH-P2WSH change against the witness script.
- **Every descriptor line in the export is uncommented, on purpose.** Each script type
  gets three: the multipath `<0;1>` form, then the same keys as a separate receive and
  change pair. The pair used to be commented out as a footnote — which is what made a
  watch-only import into Blockstream Green impossible, since its descriptor path takes
  one expression per chain and does not parse `<0;1>` at all, so every line it could
  have used was behind a `#`. The file is read by a person picking a line, not by a
  machine consuming all of them. Do not "tidy" the duplicates back into comments.
- **Entropy is mixed, never chosen.** `core/entropy.cpp` folds the kernel CSPRNG,
  the CPU's `RDSEED`, timing jitter and the operator's own pointer/key events
  through HMAC-SHA512, and refuses to generate at all if neither the kernel nor
  the CPU could be read. Signing is unaffected by any of this (RFC6979), so this
  is the only code path where RNG quality is load-bearing.
- **The exported xpubs are checked against a second implementation.**
  `--self-test` prints each account xpub and first address; `host_selftest.sh`
  diffs them against `make_test_data.py wallet-expect`. It caught a real one
  immediately: `wally_bip32_key_to_address()` takes a raw base58 prefix byte
  where its neighbours take a network identifier, and silently accepts the wrong
  one. Do not weaken that diff.
- **No widget may be able to make the window wider than the screen.** A label whose
  content cannot be wrapped — a passphrase or an xpub is one token with no spaces —
  reports a *minimum* width as wide as the whole thing; `QStackedWidget` takes the
  widest minimum of every page it holds, so the window grows past a display that has no
  window manager to scroll it back and the buttons in the bottom right of every screen
  go over the edge. A 160-character passphrase found this, and the import screen's xpub
  found it a second time.

  The load-bearing fix is **`root->setSizeConstraint(QLayout::SetNoConstraint)` in
  `AppWindow::buildUi`**. `setMaximumSize` alone does *not* hold: a top-level layout
  defaults to `SetDefaultConstraint`, which calls `setMinimumSize(totalMinimumSize())`
  on the window, and a minimum beats a maximum. With no constraint the window is the
  screen's size always, and an oversized widget is clipped inside it. Then, so that
  nothing is actually clipped: `revealedSecret()` (`ui/secret_buffers.h`) breaks long
  secrets into lines, `chunked()` does the same for xpubs, and every label holding an
  unbreakable token is `QSizePolicy::Ignored` horizontally.
- **The version lives in `VERSION`, and nowhere else.** One line at the repo
  root. `build.sh` reads and validates it, exports `SIGNEROS_VERSION`, and from
  there it reaches three places: the image file names
  (`signeros-<version>-x86_64.img`, with `signeros.img` left as a symlink so the
  scripts and the README keep working), the `SIGNEROS_VERSION=` line
  `post-build.sh` stamps into `/etc/signeros-build` - which is inside the
  initramfs, so the version is part of what `bzImage` hashes to - and a `-D` the
  package makefile passes to cmake, which is what the splash, home and shutdown
  screens show and what `--version` prints. Do not add a second place: a version
  string that disagrees with the file name it was flashed from is worse than no
  version at all. `build.sh` forces `btc-signer-gui-reconfigure` when the version
  changes, because a changed `-D` does not invalidate a cmake stamp on its own.
- **Binary size is permanently resident RAM** (the rootfs unpacks into tmpfs), which is
  why everything builds `MinSizeRel`/`-Os` — except that `BR2_OPTIMIZE_S=y` plus glibc
  does not link, so the *system* is `BR2_OPTIMIZE_2`. `build.sh` refuses that
  combination up front.
- **Reproducibility**: `BR2_REPRODUCIBLE=y`, every input pinned. Compare
  `output/images/bzImage`, not `signeros.img` — the latter embeds a per-key Secure Boot
  signature and is expected to differ.
- Secure Boot signing is opt-in via `SIGNEROS_SB_KEY` / `SIGNEROS_SB_CERT`;
  `build.sh` validates the pair in the first second rather than 90 minutes in.
  `keys/` is gitignored and `make_sb_keys.sh` refuses to overwrite an existing key.

### Verification status

The full Buildroot build, `./scripts/test_in_qemu.sh` (both runs) and
`./scripts/host_selftest.sh` have all been executed on this tree and pass, and
the wallet-creation flow has been driven end to end in the booted production
image with its exported keys re-derived independently. See the README section of
the same name for exactly what that covers.

What is still unproven: real hardware other than the machine this was flashed
on, Secure Boot enrolment on firmware other than EDK2, and `ui/touchpad.cpp` -
QEMU's `usb-tablet` is a pointer, not a pad, so `make gui` proves nothing about
touchpads.

Also unproven, and newer: **the mnemonic grids as an interaction.** The layer
underneath them *is* covered — `runGridChecks()` in `core/selftest.cpp` exercises
the slot arithmetic, the empty-cell semantics, the wipe on shrink and
`bip39UnknownSlots()`, so it runs on every `make host-test` and inside the booted
image. What no test touches is the Qt half: `test-gui` is a pixel check on the
splash, so nothing in this tree presses a key, moves a cursor or clicks a cell.
Arrow movement, click-to-cell, the import screen's word-count selector and the
live red marking are compiled and reasoned about but have not been operated.
Drive them with `make gui` before trusting this on a stick.
