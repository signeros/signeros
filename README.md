# SignerOS

A single-purpose, air-gapped, stateless x86_64 live USB operating system that
does exactly three things: create a Bitcoin wallet, export watch-only keys for
one you already have, and sign PSBT files (BIP174 / BIP370).

It boots on any UEFI machine. There is no network stack in the kernel, no
writable root filesystem, no shell, no login, and no driver for the machine's
internal disks.

```
   online machine                    SignerOS machine (air-gapped)
   ┌──────────────┐                  ┌────────────────────────────────────────┐
   │              │                  │  splash  ·  then three choices         │
   │              │                  ├───────────────┬──────────┬─────────────┤
   │ watch-only   │   USB stick      │ CREATE A      │ EXPORT   │ SIGN A      │
   │ wallet       │  ◀────────────── │ WALLET        │ KEYS     │ TRANSACTION │
   │              │  descriptors.txt │  entropy      │ you have │ 1 pick .psbt│
   │ builds       │                  │  seed once    │ the words│ 2 check it  │
   │ unsigned.psbt│  ──────────────▶ │  words typed  │ type them│ 3 type key  │
   │              │                  │  back         │ check fp │ 4 sign      │
   │ broadcasts   │  ◀────────────── │  xpub file    │ xpub file│             │
   │ signed.psbt  │   USB stick      └───────────────┴──────────┴─────────────┘
   └──────────────┘                     wipe key material, then power off
```

Creating a wallet writes **only** extended public keys. The recovery words are
shown once, are never written to any medium by any code path, and every one of
them has to be typed back before the export is offered - see
[Creating a wallet](#creating-a-wallet).

---

## Quick start

```bash
# 1. A Secure Boot signing key, once. Skip this and the image still builds and
#    boots - but only on a machine with Secure Boot turned off.
#    Relative paths work (they are resolved against the repo root), but the
#    script prints absolute ones and those are what to paste.
./scripts/make_sb_keys.sh               # → keys/SignerOS_db.{key,crt,cer}
export SIGNEROS_SB_KEY=$PWD/keys/SignerOS_db.key
export SIGNEROS_SB_CERT=$PWD/keys/SignerOS_db.crt

# 2. Build. First run compiles a toolchain and Qt, so budget 30-90 minutes.
./scripts/build.sh                      # → output/images/signeros.img

# 3. Verify. Boots the real image under UEFI in QEMU and checks that it
#    parses, inspects, signs and writes a PSBT correctly - and that the
#    kiosk actually renders on the framebuffer.
./scripts/test_in_qemu.sh

# 4. Flash, then enrol keys/SignerOS_db.cer into db from firmware setup.
sudo ./scripts/flash_usb.sh /dev/sdX --expand-data
```

Faster inner loop while working on the signing logic — no Buildroot, no QEMU,
seconds instead of minutes:

```bash
./scripts/host_selftest.sh --build-wally
```

`make help` lists everything.

---

## The five guardrails, and how each one is enforced

Design intent that is not mechanically checked is a wish. Each of these is
enforced in the build and re-verified after it, by
[post-build.sh](buildroot-external/board/signeros/post-build.sh) against the
generated artefacts and by [test_in_qemu.sh](scripts/test_in_qemu.sh) against the
booted image.

### 1. Zero network attack surface

The kernel is built with `CONFIG_NET=n`
([linux_hardening_defconfig](buildroot-external/board/signeros/linux_hardening_defconfig)).
Not "drivers disabled" — there is no socket layer, no netlink, no packet
scheduler, and every network driver becomes unbuildable. BusyBox is additionally
compiled without a single networking applet
([busybox.fragment](buildroot-external/board/signeros/busybox.fragment)), so
there is no `ping`, `wget`, `nc` or `ip` on the image even for an attacker who
achieves code execution.

Two consequences worth knowing, because they shape the rest of the system:

- **No udev.** udev needs `AF_NETLINK` for uevents. SignerOS uses BusyBox `mdev`
  plus `devtmpfs`, and [mdev.conf](buildroot-external/board/signeros/rootfs-overlay/etc/mdev.conf)
  is where the kiosk gets access to the framebuffer, DRM and input devices.
- **No hotplug helper.** `CONFIG_STATIC_USERMODEHELPER_PATH=""` means the kernel
  cannot spawn a process at all. A USB stick inserted after boot is picked up by
  [signeros-datawatch](buildroot-external/board/signeros/rootfs-overlay/usr/sbin/signeros-datawatch)
  polling `blkid` once a second — no privileged listener to attack.

`post-build.sh` fails the build if `CONFIG_NET=y` survives kconfig dependency
resolution, or if any networking applet is left in BusyBox. That is the
build-time half. The runtime half is proven inside the booted image by
`test_in_qemu.sh`: the self-test calls `socket(AF_INET, SOCK_STREAM, 0)` and the
harness requires it to fail with `ENOSYS` - the syscall does not exist, it is not
merely blocked - and requires `/proc/net` to be absent. The test VM is also
started with `-nic none`, so QEMU does not attach its default emulated NIC to a
machine whose whole point is not having one.

### 2. RAM-only stateless execution

The root filesystem is a cpio archive **linked into the kernel image** and
unpacked into tmpfs by the kernel at boot. There is no block-based rootfs image
in the build at all, and no separate initramfs file on the ESP either — see
[Secure Boot](#secure-boot-and-the-unified-kernel-image) for why that matters.
[S00early](buildroot-external/board/signeros/rootfs-overlay/etc/init.d/S00early)
then does `mount -o remount,ro /`, so even the RAM copy is read-only for the rest
of the session. `/tmp`, `/run` and `/dev/shm` are tmpfs; `/mnt/data` is the only
writable storage the system can reach.

The build prints both figures, because the unpacked one is permanently occupied
physical memory:

```
  production image
  bootx64.efi ......  22400 KiB   (kernel + initramfs, one signed PE)
  of which rootfs ..  44500 KiB   (unpacked into RAM at boot)
  ------------------------------
  ESP payload ......  22400 KiB of 262144 KiB (8%)
```

The price of linking the rootfs into the kernel is build latency: any change
under `src/` now relinks and recompresses the kernel, so `make app` is minutes
rather than seconds.

### 3. No X11, no Wayland, no display manager

The kiosk is a Qt Widgets application drawing directly on the kernel KMS/DRM
framebuffer. The default build uses the **linuxfb** QPA plugin on `/dev/fb0`,
which the kernel's DRM fbdev emulation exposes for whichever KMS driver bound —
`simpledrm` on the UEFI GOP framebuffer at minimum, which is what makes one image
portable across machines. **eglfs** is a one-flag alternative
(`./scripts/build.sh --fragment eglfs`) that talks KMS/GBM directly with GPU
acceleration; it costs roughly 40 MB of permanently resident RAM for the GL
stack, which is why it is not the default.
[signer-session](buildroot-external/board/signeros/rootfs-overlay/usr/bin/signer-session)
picks between them at boot and falls back if the first choice cannot open a
screen.

`post-build.sh` fails the build if `libX11`, `libxcb`, `libwayland-*`, or any
display server or display manager binary appears on the image.

### 4. Zero-trust USB data partition

Partition 1 is the ESP: FAT32, containing exactly one file — `EFI/BOOT/bootx64.efi`,
the unified kernel image. Nothing on the running system ever reads or writes it.

Partition 2 is FAT32 labelled `PSBT_DATA`, found by label and mounted at
`/mnt/data` with:

```
rw,noexec,nodev,nosuid,sync,uid=1000,gid=1000,fmask=0117,dmask=0007
```

`signeros-datawatch` then **re-reads `/proc/mounts` and unmounts the volume again
if any of `rw`, `noexec`, `nodev` or `nosuid` is missing.** A mount that silently
came up without `nosuid` must not be presented to the user as the safe one.
`test_in_qemu.sh` asserts the same flags on the booted system.

Only the kiosk's uid can touch files there, and it gets that from the mount
options rather than from directory permissions, so a *failed* mount can never be
silently written to in RAM instead.

### 5. IOMMU on, DMA attack surface removed

`CONFIG_INTEL_IOMMU_DEFAULT_ON=y`, `CONFIG_AMD_IOMMU=y`,
`CONFIG_IOMMU_DEFAULT_DMA_STRICT=y`, and the compiled-in kernel command line
repeats `intel_iommu=on amd_iommu=on iommu.strict=1 iommu.passthrough=0
efi=disable_early_pci_dma` because platform defaults differ.
`CONFIG_EFI_DISABLE_PCI_DMA=y` sets the last of those at build time as well, so
the busmaster bit is cleared across `ExitBootServices()` even if command-line
parsing is ever refactored out from under it.

Then the buses whose entire purpose is giving an external connector DMA are
simply not compiled in: **USB4/Thunderbolt, FireWire, PCMCIA/CardBus, PCI
hotplug, VFIO**. USB video and audio class drivers are gone with
`CONFIG_MEDIA_SUPPORT=n` and `CONFIG_SOUND=n`.

There is also no driver for any non-removable storage — no SATA, no NVMe, no
SD/MMC, no virtio-blk. The internal disks of whatever machine you boot this on
are invisible to it. And only two filesystem parsers are reachable from untrusted
removable media: `vfat` and `exfat`.

---

## Repository layout

```
buildroot-external/                  Buildroot external tree (BR2_EXTERNAL)
├── configs/
│   ├── buildroot_x86_64_defconfig   the appliance configuration
│   └── fragments/
│       ├── eglfs.fragment           swap linuxfb → eglfs + mesa
│       └── gpu-firmware.fragment    add amdgpu/i915 firmware blobs
├── external.mk                      + the signeros-test-image target: the
│                                      second kernel build behind the self-test
├── board/signeros/
│   ├── linux_hardening_defconfig    kernel fragment: the guardrails, and the
│   │                                  production command line (section 2b)
│   ├── cmdline-selftest             the self-test kernel's command line
│   ├── busybox.fragment             remove every network applet
│   ├── genimage.cfg                 two-partition GPT, fixed UUIDs
│   ├── genimage-test.cfg            the test variant
│   ├── image-layout.conf            offsets/labels, single source of truth
│   ├── users.table  device_table.txt
│   ├── post-build.sh                asserts the guardrails, fails the build
│   ├── post-image.sh                signs the UKI onto the ESP, builds an image
│   └── rootfs-overlay/
│       ├── etc/inittab              BusyBox init, no getty, no login
│       ├── etc/init.d/S00early      sysctls, mdev, read-only root, RAM scrub
│       ├── etc/init.d/S01mount-data the zero-trust mount
│       ├── etc/init.d/S99signer     start the kiosk (or the self-test)
│       ├── etc/mdev.conf  etc/signeros.conf
│       ├── usr/bin/signer-session   privilege drop + supervision
│       ├── usr/sbin/signeros-datawatch
│       ├── usr/sbin/secure-poweroff
│       └── usr/lib/signeros/functions.sh
└── package/
    ├── libwally-core/               pinned to release_1.5.6, static only
    └── btc-signer-gui/              the kiosk, built from src/

src/btc_signer_gui/
├── src/core/                        NO Qt: buildable and testable standalone
│   ├── secure_memory.{h,cpp}        fixed, mlock'd, self-wiping containers
│   ├── psbt_engine.{h,cpp}          libwally: parse, inspect, sign, write
│   ├── entropy.{h,cpp}              the multi-source pool a new seed is
│   │                                  minted from (kernel, RDSEED, jitter,
│   │                                  the operator's own movement)
│   ├── wallet_export.{h,cpp}        mnemonic generation, account xpubs and
│   │                                  the descriptor file - the ONLY thing
│   │                                  wallet creation ever writes
│   └── selftest.{h,cpp}             the headless end-to-end exercise
├── src/ui/                          Qt Widgets: theme, keyboard, the screens,
│   │                                  and touchpad.cpp - the pointer handler
│   │                                  Qt does not ship and libinput cannot
│   │                                  provide without udev
│   ├── secret_buffers.{h,cpp}       every secret in the process, in one place
│   ├── seed_view.{h,cpp}            paints a mnemonic without ever building
│   │                                  a QString out of it
│   ├── screen_splash.cpp            three seconds, drawn with QPainter
│   ├── screen_home.cpp              create a wallet, or sign a transaction
│   └── screen_create.cpp            the seven-page creation wizard
├── src/tools/ramwipe.c              shutdown-time free-memory scrub
└── src/main.cpp                     kiosk and --self-test in one binary

scripts/
├── build.sh                         pinned Buildroot, fragments, artefacts
├── make_sb_keys.sh                  generate a Secure Boot signing key
├── test_in_qemu.sh                  UEFI boot + signing + pixel verification
├── make_test_data.py                independent PSBT fixture + verifier
├── host_selftest.sh                 fast core-only loop
└── flash_usb.sh                     write and verify a stick - and unmount it
                                       first, because a desktop that mounts
                                       PSBT_DATA the instant the write ends
                                       rewrites the FAT dirty flag and fails
                                       the readback on a perfect stick

VERSION                              one line: the release version, and the
                                       only place it is written down
```

---

## Creating a wallet

The second thing this device does, and the one with the sharper edges. Signing a
transaction is recoverable if it goes wrong: you can always try again. Creating
a wallet produces twelve or twenty-four words that exist nowhere else in the
universe, and a mistake is permanent in both directions - a copy an attacker can
read loses the money, and a copy the owner cannot read loses it just as
completely.

So the flow is built around one rule:

> **Nothing derived from the seed is ever written to any medium.** Not the
> mnemonic, not the BIP39 seed, not an xprv, not a "recovery file", not a
> temporary file, not a log line. The private half of the wallet exists only in
> locked RAM, for as long as the creation screen is open, and is wiped on the way
> out.

The single file that reaches the data partition is
`signeros-<fingerprint>-<timestamp>.descriptors.txt`: output descriptors and
extended **public** keys for BIP84, BIP86, BIP49 and BIP44, plus the BIP48
multisig cosigner keys described below, account 0. It is
enough for Sparrow, Bitcoin Core or any other coordinator to watch the wallet
and build transactions for it, and it cannot spend a satoshi.

Each script type gets **three** uncommented descriptor lines: the multipath
`<0;1>` form, then the same keys as a separate receive and change pair. The pair
used to be commented out as a footnote for "wallets that do not understand
multipath", which turned out to describe Blockstream Green - its watch-only
import takes one descriptor per chain and does not parse `<0;1>` at all, so
every line in the file it could have used was hidden behind a `#`. The file is
read by a person picking a line, not by a machine consuming all of them, so the
cost of printing both forms is length; the cost of hiding one was an export that
looked complete and silently was not for a whole class of wallet.

### The multisig block at the end

The same file ends with this seed's **BIP48 cosigner keys** -
`m/48'/<coin>'/<account>'/2'` (P2WSH) and `.../1'` (P2SH-P2WSH) - so that a
SignerOS machine can be one signer of a multisig without a second flow, a second
screen or a second decision. Nothing in the creation or import path asks about
multisig; the keys are simply in the file for the operator who needs them.

They are **not** AccountExports and are not rendered as one. A multisig wallet
does not exist until every cosigner's key is known, and this device knows only
its own, so there is no descriptor to write and no first address to print. An
`AccountExport` with those two fields empty would render as
`first address (could not be derived)`: a failure message for something that is
not a failure. What the block carries instead is the key with its origin
attached - `[<fingerprint>/48h/0h/0h/2h]xpub...` - which is exactly the string a
coordinator asks each signer for.

The consequence for the operator is that the file's usual proof - compare the
first address with what your wallet shows - does not apply to this block, and it
says so: what you compare in the coordinator is the master fingerprint and the
derivation path, both of which every coordinator shows next to a cosigner once
it is added.

The signing half needed nothing: `psbt_engine` already verifies P2WSH and
P2SH-P2WSH change by finding its own derived public key inside the witness
script and rebuilding the `scriptPubKey` byte for byte, and
`wally_psbt_sign_bip32` signs multisig inputs as it signs any other. The one
thing to know is that an output is only shown as change when the PSBT carries
the witness script itself; without it the honest answer is `Unverifiable`, and
that is what the screen says.

### Where the randomness comes from

A seed is exactly as unguessable as the entropy it was made from, and this is
the one place in SignerOS where the quality of a random number decides whether
money can be stolen. (Signing needs no entropy at all: libwally uses RFC6979
deterministic nonces, so a lying RNG cannot leak a private key through a biased
`k`.)

[core/entropy.h](src/btc_signer_gui/src/core/entropy.h) therefore trusts no
single source. Four independent ones are folded together in an extract-style
HMAC-SHA512 chain, `state ← HMAC-SHA512(key = state, msg = sample)`:

| Source | Why it is in the list |
|---|---|
| Kernel CSPRNG | seeded from interrupt timing and from the CPU at boot, before userspace exists. Read **non-blocking**: a `getrandom(2)` that waits on an unseeded pool has no bound, and a kiosk with no shell behind it cannot survive a syscall that never returns. Whether it was actually seeded is reported, not assumed |
| CPU TRNG, read directly with `RDSEED` (`RDRAND` as fallback) | the same silicon through a completely different door, bypassing the kernel. An unprivileged instruction, so no device node and no permission is involved - `/dev/hwrng` is root-only on this image and deliberately unused |
| Timing jitter | the low bits of the timestamp counter across an unpredictable-latency loop. Weak alone, free, independent of both of the above |
| The operator's own movement | pointer motion, taps and keystrokes with the time each arrived. Physical, outside the machine, and the only source a purely software attacker cannot observe |

One unpredictable source among them is enough: an attacker would have to
compromise **all** of them simultaneously for the result to be guessable.

At least one source has to be one the device can stand behind - a seeded kernel
CRNG, or the CPU's own generator. If the kernel says it is not seeded yet *and*
the CPU offers neither instruction, generation is refused outright. There is no
override, because a signer that asks "randomness looks weak, continue anyway?"
has already lost the argument: the operator has no way to evaluate the question
and every incentive to press yes.

The screen states which sources actually contributed on this boot, and the seed
page prints the same line again above the words.

### Why you have to type all of them back

The words are shown once, then masked the instant verification starts, and the
export is not offered until every one of them has been typed back correctly.
The word grid fills in as you type and turns red on the first character that
stops matching, so an error is caught while the word is still in front of you.

The entry is a cursor standing in a cell of the grid, one cell per word. Space,
Enter and the right arrow finish the current cell and move to the next; the
arrow keys move between cells in both dimensions, Home and End go to the ends,
and clicking a cell goes straight to it. Backspace in an empty cell steps back
into the previous one. The cell being typed into carries a caret, an accented
number and an accented outline, and the line under the grid names it outright -
`word 7 of 12` - so "where am I" is never a question of counting filled cells.
Enter means "continue" only once the whole entry matches, so it cannot carry
anyone past a half-typed verification.

**A word you got wrong is corrected where it is.** The cursor is a cell index,
not the end of the buffer, so going back to word 3 costs word 3 and nothing
else. It used to cost the twenty-one words after it, which on a 24-word backup
is a strong incentive to squint at the paper and hope. Every cell that does not
match is outlined at once, rather than only the first one, for the same reason:
being sent back to the paper twice for two mistakes found one at a time is how
people give up and write the seed into a text file instead.

That in turn is why "Show the words again" no longer clears what has been
typed - eleven correct words are not a reasonable price for checking the
twelfth - and why `SecureString` grew a grid view. The buffer holds one field
per cell separated by exactly one space, a field may be empty, and the
in-the-middle edits go through `insertAt`/`eraseAt`, which wipe the tail they
shift past rather than leaving it readable behind the terminator. The number of
separators *is* the cell count, so there is no second piece of state that can
disagree with the text, and a grid with every cell filled is already exactly the
single-space form BIP39 validation wants.

This is not ceremony. It is the *only* check available to a device that refuses
to keep a copy: the moment the screen closes there is nothing left to compare a
transcription against, on this machine or anywhere else. "Show the words again"
is deliberately available throughout - handwriting is genuinely ambiguous, and
the alternative to letting someone look twice is a wallet lost to a badly formed
digit.

An optional BIP39 passphrase follows. It is shown in clear once, on the
confirmation page, for the same reason: a passphrase remembered incorrectly is
exactly as lost as a seed written down incorrectly, and this device will not
store it either. A long one is broken into lines of 32 characters where it is
shown, and the page says so - a passphrase is a single token with no spaces to
wrap at, and a label asked to lay one out reports a minimum width as wide as
the whole thing. That minimum reaches the QStackedWidget holding the screens,
which takes the widest minimum of every page it holds, so a 160-character
passphrase used to push the window past the edge of the panel and carry the
buttons in the bottom right of the following pages out of sight.

The window is additionally pinned to the size of the screen, which is what makes
that a clipped label rather than an unreachable button next time. Capping it
with `setMaximumSize` is not enough on its own and was tried first: a top-level
widget's layout calls `setMinimumSize(totalMinimumSize())` on the window, and a
minimum beats a maximum, so the window still grew - to roughly 1576 pixels on a
1280 pixel display, the second time this happened. The root layout is therefore
set to `QLayout::SetNoConstraint`, so it never reports a minimum upwards at all.

### How the export is checked

An xpub that is subtly wrong is the worst failure this feature has. The file
imports cleanly, the coordinator shows a plausible wallet, and nothing looks
wrong until coins have been received at addresses the owner's seed cannot spend
from.

So the account keys are not trusted to one implementation. `--self-test` prints
every account xpub and first address, and `scripts/host_selftest.sh` diffs all of
them against `scripts/make_test_data.py`, which derives the same values with
pure-stdlib Python that shares no code with libwally-core - including the BIP341
taproot tweak and the base58 address prefixes.

That check earned its place immediately: libwally's `wally_bip32_key_to_address()`
takes a raw base58 prefix byte where its neighbours take a network identifier,
and it accepts the wrong one without complaint, producing well-formed
checksummed addresses that no wallet recognises. Nothing else in the build would
have noticed.

The self-test additionally scans the rendered export for every word of the
mnemonic and for anything resembling an extended private key, and asserts that
the process-wide master key slot is empty again afterwards - so "nothing derived
from the seed is ever written" is a build gate rather than a paragraph.

Both checks run twice, for account 0 and account 1. Account 0 alone would not
prove the account index is used at all: it is the one value for which a dropped
or wrongly hardened index still produces the right answer, and the account is
operator-selectable on the screen below.

---

## Exporting keys for words you already have

Signing a PSBT requires a PSBT, building one requires a watch-only wallet, and
building that requires the account xpubs. Producing those only for seeds this
machine generated itself left an obvious hole: someone arriving with an existing
seed could sign transactions that other people's software had built for them,
and could never build one of their own.

**Export watch-only keys** on the home screen closes it. Type the recovery words
and the optional passphrase, and the same
[buildWalletExport()](src/btc_signer_gui/src/core/wallet_export.h) that ends
wallet creation writes the same descriptor file. The words are never written
anywhere, the master key slot is cleared on the way out, and the export is
public keys exactly as before - the derivation does not care where the mnemonic
came from, which is why this is a screen and not a subsystem.

### The entry grid

The same numbered grid wallet creation verifies into, driven the same way -
arrows and clicks move between cells, Space and Enter finish one, a wrong word
is fixed where it stands. Two things differ, and both follow from the seed
having been made somewhere else:

**The word count is chosen here**, 12 / 15 / 18 / 21 / 24, because the device
has no way to know it. That choice is what lets the grid show every cell before
the first keystroke instead of growing as words arrive, which is the whole
reason a cell can be numbered and navigated to at all.

**The words are shown in clear.** Creation masks its grid deliberately: the
operator is meant to be copying from their paper and not from the screen, and a
readable grid would let them do the second while believing they had done the
first. Here the paper *is* the source and there is nothing to enforce - a
transcription you cannot read back is precisely the failure this screen exists
to catch. `Hide` puts it behind blocks for the room without losing a character.

And because the device cannot compare against a reference here, it checks what
it can: `bip39UnknownSlots()` walks the 2048-word list once against every cell
on each keystroke and outlines the ones that are not words in it. That is the
question `bip39Validate()` structurally cannot answer - it knows only that the
whole mnemonic is wrong, which on a 24-word entry means reading all of them back
off the paper to find the one bad letter. What is left for the checksum is the
case a wordlist cannot catch: every word real, one of them in the wrong place.

### Why the review page is the point of it

Creating a wallet cannot produce a wrong export: the machine derived both halves
from bytes it generated. Importing one can, in exactly two ways, and they are
not symmetrical:

| Mistake | Caught? |
|---|---|
| A mistyped **word** | Yes, twice. The cell is outlined as it is typed if the result is not in the wordlist at all, and BIP39's checksum catches the rest - 15 chances in 16 for twelve words, 255 in 256 for twenty-four. `bip39Validate()` refuses and nothing is derived |
| A mistyped **passphrase** | **Never.** Any bytes are a legal passphrase, so the wrong ones produce a different, valid, perfectly empty wallet |

The second one is not a careless failure, it is a routine one: this image reads
every keyboard as US (see [Hardware notes](#hardware-notes)), so a passphrase
typed on a QWERTZ or Turkish-Q layout is captured as different characters and
nothing anywhere will say so. The symptom is a zero balance, which reads as "my
seed is broken", and the danger is the operator who concludes otherwise and
receives coins at addresses their real seed cannot spend from.

So the master fingerprint and the first address of every account type are shown
large, before any file exists, with the instruction to compare them against the
wallet the operator already has. That comparison is to this flow what "type
every word back" is to wallet creation: the only check available to a device
that has no way of knowing the right answer by itself. The passphrase can be
revealed on the previous page for the same reason it can be on the signing
screen - being able to see what was actually captured is what turns a dead end
into a diagnosis.

### The account number

Selectable here, 0 to 9, and fixed at 0 when creating. A new wallet is account 0
by definition; an existing one is whatever it already is, and handing someone on
account 1 a file for account 0 is the failure above wearing a different hat. The
keys and addresses on the page change with the selection, so finding the right
one is a matter of stepping through until the first address matches - which is
the comparison the page is asking for anyway.

`scripts/make_test_data.py wallet-expect --account N` derives the same thing
independently, and `host_selftest.sh` diffs both accounts against it -
`--section cosigners` does the same for the BIP48 keys, which are a level deeper
and are therefore exactly the derivation a wrong path length would still get
plausibly wrong.

---

## How signing works

[psbt_engine.cpp](src/btc_signer_gui/src/core/psbt_engine.cpp) is the whole of it.
No wrapper scripts, no shelling out.

```
load()      wally_psbt_from_bytes / _from_base64, strict parsing first,
            permissive only as a fallback and only with a visible warning.
            Elements/Liquid PSETs are refused outright: this build cannot
            show you what it would be signing.

inspect()   wally_psbt_extract(NON_FINAL) gives one canonical transaction view
            for both PSBT v0 and v2. Input amounts come from witness_utxo or
            non_witness_utxo; addresses from wally_scriptpubkey_to_address /
            wally_addr_segwit_from_bytes; derivation paths from the keypath
            maps. vsize is estimated per input by script type (p2wpkh,
            p2sh-p2wpkh, p2wsh m-of-n, p2tr key-path, p2pkh, bare multisig),
            so the sat/vB figure reflects the *signed* transaction.

key()       bip39_mnemonic_validate → bip39_mnemonic_to_seed512 →
            bip32_key_from_seed. Then, per input,
            wally_psbt_get_input_bip32_key_from_alloc tells us whether this key
            actually covers it, which is what "signs 2 of 3 inputs" is based on.
            Per output, the claimed derivation is *re-derived* and the
            scriptPubKey rebuilt from the result - see below.

sign()      wally_psbt_sign_bip32(psbt, master, EC_FLAG_GRIND_R).
            Nonces are RFC6979-deterministic, so signing needs no entropy and
            a weak system RNG cannot leak a key through a biased k. GRIND_R
            gives low-R (71-byte) signatures, so sizes are predictable.

write()     wally_psbt_to_base64 → open(O_EXCL) → write → fsync.
            O_EXCL, so a previous result is never silently overwritten.
```

### Change is proved, never believed

A PSBT tells the signer which outputs are change by attaching a master
fingerprint and a derivation path to them (`PSBT_OUT_BIP32_DERIVATION`). Those
are bytes the file's creator wrote. Comparing the fingerprint and calling it a
day - the obvious implementation - means anyone who can hand you a PSBT can also
decide which address this device paints green as "coming back to you". The
operator then authorises the loss themselves, having read the screen correctly.

So every output goes through one of five states, and only the third is green:

| state | meaning |
|---|---|
| `ThirdParty` | no derivation information at all: a payment out |
| `Claimed` | a derivation is claimed, nothing is verified yet - **this is what every change output looks like before a key is entered** |
| `Verified` | our master derives along the claimed path, and the resulting public key reconstructs this output's scriptPubKey byte for byte |
| `Unverifiable` | claims our master over a script this device cannot rebuild (a multisig whose script the PSBT omitted, a taproot output with a script tree). A warning, not a refusal |
| `Mismatch` | claims our master, and the derived key does **not** produce this script. **Signing is blocked** |

The reconstruction covers p2pkh, p2wpkh, p2tr (key-path), p2sh-p2wpkh, and the
script-hash forms when the PSBT supplies the script: p2wsh and p2sh-p2wsh are
checked to hash to the output *and* to name our public key, which is what makes
a multisig change output ours rather than a cosigner's.

Two consequences in the interface:

- The inspection screen runs **before** a key exists, so it says "declared as
  your own change (not verified)" rather than either "your change" or "payment
  to someone else". Neither of the confident answers is knowable there, and one
  of them was making correct transactions look like thefts.
- After "Check key" there is a **confirmation page** - the last screen before an
  irreversible act - which restates the transaction in verified terms: what is
  actually leaving the wallet, what is verified change, the fee, the master
  fingerprint. Nothing on the key-entry page signs.

`scripts/make_test_data.py` generates a negative fixture for exactly this attack
(`forged_change.psbt.bad`: our fingerprint, our change path, an address we do not
control). Both `make host-test` and `make test` fail unless the engine refuses
it - see [Verification](#verification).

### The refusal that matters most

If the PSBT does not include the previous output for **every** input, the total
input value is unknown, so the fee is unknown. An attacker who omits one UTXO can
hand you a transaction that looks like it pays a 500 sat fee and actually pays the
rest of your balance to miners.

SignerOS refuses to sign, says exactly why, and tells you what to ask the
creating wallet for. It does not estimate, and it does not let you override.

Other hard refusals: an already-finalised PSBT, outputs exceeding inputs, a PSBT
that cannot be assembled into a transaction. Loud warnings, but signable:
non-`SIGHASH_ALL` flags (with the specific consequence spelled out), a fee above
5% or 25% of input value, fee rates above 100 or 1000 sat/vB, sub-1 sat/vB, no
identifiable change output, scripts that cannot be decoded.

### Key material handling

| | |
|---|---|
| Storage | `SecureString` / `SecureBuffer<N>` / `SecureObject<T>` — capacity fixed at compile time, storage **inline**, never heap-allocated |
| Location | The mnemonic buffer, the passphrase buffer and the BIP32 master key are single **file-scope statics**. At any instant there is exactly one page range in the process that can hold each, and its lifetime is explicit |
| Locked | `mlock()` per object plus `mlockall(MCL_CURRENT\|MCL_FUTURE)`; `signer-session` grants the rlimit before dropping privileges |
| No dumps | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0`, `CONFIG_COREDUMP=n`, `kernel.yama.ptrace_scope=3` |
| Wiped | `wally_bzero` → `explicit_bzero` → volatile store loop → `asm` barrier, in destructors. libwally is built `--disable-builtin-memset` so its inner memset cannot be elided at `-Os` |
| Never in Qt | Keystrokes go character-by-character into the secure buffer. The display shows `...` per completed word plus the word being typed. Physical keys are read from `QKeyEvent::key()`, not `text()`, so the character never enters a `QString` |

The only compromise, and it is deliberate: the word currently being typed and the
BIP39 completion suggestions are dictionary words that appear on screen and
therefore in Qt-managed memory. A signer that will not show you the character you
just pressed is a signer people mistype seeds into. Suggestions can be turned off
(`BR2_PACKAGE_BTC_SIGNER_GUI_WORD_SUGGESTIONS`), and the `QByteArray` a tapped
suggestion travels in is wiped once its word is in the secure buffer.

---

## Privilege model

The kiosk runs as uid 1000, no supplementary groups, `/bin/false` shell, locked
password. There is **no setuid binary anywhere on the image** — `post-build.sh`
fails the build if one appears.

So how does an unprivileged process power the machine off? It exits with status
**42**. `signer-session`, which is root, turns that into
`/usr/sbin/secure-poweroff`. One integer is the entire privileged interface
between the GUI and the system.

## Secure shutdown

Ordering matters, so it is explicit:

1. The kiosk wipes its own key material — in destructors, as it exits, not
   "eventually".
2. `rcK` stops `S99signer`: `SIGTERM` with 8 seconds to run those destructors.
3. `rcK` stops `S01mount-data`: `/mnt/data` synced and unmounted, so a PSBT
   written seconds ago is definitely on the medium.
4. `rcK` stops `S00early` last: `drop_caches`, then
   [signeros-ramwipe](src/btc_signer_gui/src/tools/ramwipe.c) overwrites free
   memory with `0xff` then `0x00`, bounded by re-reading `/proc/meminfo` before
   every 64 MiB chunk and setting its own `oom_score_adj` to 1000 so the kernel
   would kill the wiper rather than init.

`init_on_free=1` means the kernel has already zeroed most of this. The scrub is
the layer that catches what a library we do not control freed without clearing,
and the page cache copy of the PSBT.

---

## Secure Boot and the unified kernel image

SignerOS has no bootloader. The ESP holds one file:

```
EFI/BOOT/bootx64.efi     ← the kernel itself
```

The kernel's EFI stub (`CONFIG_EFI_STUB=y`) makes `bzImage` a PE binary the
firmware executes directly. The root filesystem is linked into it
(`BR2_TARGET_ROOTFS_INITRAMFS=y`) and the command line is compiled into it
(`CONFIG_CMDLINE`), so one file is the entire boot payload — and one signature
covers all of it.

GRUB used to sit in front of this, with a locked menu. That was the wrong shape.
A bootloader that reads a kernel and an initramfs off a FAT partition and
executes them unverified is precisely the gap Secure Boot exists to close: an
attacker who can rewrite the ESP replaces `bzImage`, and the signature on the
bootloader says nothing about what the bootloader then ran.

### Signing

Signing is opt-in through the environment, so no key ever has to live in the
tree:

```bash
./scripts/make_sb_keys.sh                    # → keys/, gitignored
export SIGNEROS_SB_KEY=$PWD/keys/SignerOS_db.key
export SIGNEROS_SB_CERT=$PWD/keys/SignerOS_db.crt
./scripts/build.sh
```

`build.sh` checks the key before it starts building — a wrong path, a key and
certificate that are not a pair, or a missing `sbsign` all fail in the first
second rather than after an hour. Relative paths are resolved against the repo
root, because Buildroot runs post-image scripts with the working directory set to
`buildroot/` and a bare `keys/...` would otherwise be looked up there.

[post-image.sh](buildroot-external/board/signeros/post-image.sh) runs `sbsign`
and then `sbverify` on the result. Set neither variable and the image is built
unsigned with a loud warning: it boots fine with Secure Boot off and under QEMU,
and a machine that enforces Secure Boot rejects it with

```
UEFI device has been blocked by the current security policy
```

### Enrolling the certificate

Signing the image is only half of it. The firmware has to be told to trust that
signature, and that means putting `keys/SignerOS_db.cer` into its **db** — the
list of certificates it will execute code for. Out of the factory, db contains
Microsoft's certificates and nothing else.

**`mokutil` does not do this.** On a Linux host that is the obvious reflex, and it
is the wrong tool here: MOK is *shim's* trust store, read by shim after the
firmware has already launched it. SignerOS has no shim — the firmware launches
`EFI/BOOT/bootx64.efi` itself — so nothing ever consults MOK. The certificate has
to be in db, and db can only be written from firmware setup (unless the machine is
in Setup Mode, which a normally-configured one is not; check with
`cat /sys/firmware/efi/efivars/SetupMode-*  | od -An -tu1 -j4 -N1`).

1. Copy `keys/SignerOS_db.cer` onto any FAT volume the firmware can read — the
   SignerOS stick's own second partition does fine.
2. Enter firmware setup (`F10` on most HP machines, `F2`/`Del` elsewhere).
3. Find Secure Boot key management: usually under `Security` or `Advanced`, as
   *Secure Boot Configuration* → *Secure Boot Key Management*.
4. Switch key management from *Factory Default* to **Custom**.
5. Select **db**, then *Enroll key from file* / *Append*, and pick the `.cer`.
6. Compare the fingerprint the firmware shows against
   `openssl x509 -in keys/SignerOS_db.crt -noout -fingerprint -sha256`.
7. Save and exit, then boot the stick.

**Add, do not clear.** The same menu usually offers *Clear All Secure Boot Keys*
right next to *Enroll*, and taking it removes Microsoft's certificates — which is
what the machine's existing operating system depends on. Windows is the obvious
casualty, but a Linux box is just as exposed: Ubuntu's `shimx64.efi` is signed by
*Microsoft Corporation UEFI CA 2011*, and shim is what then vouches for
`grubx64.efi` with Canonical's key. Empty db and that machine no longer boots
itself. `sbverify --list /boot/efi/EFI/*/shimx64.efi` shows this on any such host.

If it goes wrong, *Restore Factory Keys* / *Restore Secure Boot Defaults* is in
the same menu. Nothing here bricks a machine.

Two things that can block the process: some firmwares accept only a signed
variable update (`.auth`) rather than a raw `.cer`, and some hide key management
until a setup password is set. Neither has a workaround in this repo — on such a
machine the choice is a shim-based chain or Secure Boot off.

### Why the command line is compiled in

Leaving Microsoft's certificates in db has a consequence worth being explicit
about: an MS-signed shim and distro GRUB stay loadable on that machine, and
either can load this kernel with a command line of its own. Secure Boot signs
the *binary*; the command line arrives separately, as the loaded image's
LoadOptions. `rdinit=/bin/sh` on the end of it would walk straight past the
kiosk.

`CONFIG_CMDLINE_OVERRIDE=y` closes that, and it does so twice over:

- `arch/x86/kernel/setup.c` replaces `boot_command_line` with the built-in one.
- `drivers/firmware/efi/libstub/x86-stub.c` skips parsing LoadOptions
  altogether and parses `CONFIG_CMDLINE` instead. This second half is what keeps
  `efi=disable_early_pci_dma` effective — it is handled inside the stub, before
  `ExitBootServices()`.

So the command line is as unforgeable as the kernel it is compiled into.
`post-build.sh` fails the build if `CONFIG_CMDLINE_OVERRIDE` is missing, if the
built-in command line has lost any of its hardening options, or if it contains
`signeros.selftest=1` or a serial console — the two things that would mean a
self-test kernel was about to ship as the appliance.

### What it costs

Everything about this design follows from "the signature must cover the whole
payload", including the awkward parts:

- **The command line cannot be varied at boot by anyone, including the test
  harness.** So `signeros-test.img` is a *second kernel build* whose only
  difference is `CONFIG_CMDLINE`
  ([cmdline-selftest](buildroot-external/board/signeros/cmdline-selftest),
  built by the `signeros-test-image` target in
  [external.mk](buildroot-external/external.mk)). `make test` therefore still
  exercises the same source, the same kernel configuration and the same
  `rootfs.cpio` you ship.
- **There is no  GUI variant to boot into.** `make gui` opens the
  production image and generates a *mainnet* fixture instead, so the addresses on
  screen match what `make_test_data.py` printed. The fixture follows the image
  rather than the other way round.
- **`make app` is no longer a seconds-long loop**, because the rootfs lives
  inside the kernel. `./scripts/build.sh --no-test-image` halves the kernel work
  when you are only iterating on the UI.
- **A signed image is reproducible only per key.** Compare `output/images/bzImage`
  — the unsigned UKI, which is the whole boot payload — not `signeros.img`.

---

## Verification

### What `scripts/test_in_qemu.sh` actually proves

**Run 1 — headless signing, on `signeros-test.img`.** Same kernel source, same
kernel configuration, the same `rootfs.cpio` linked in as the production image;
the only difference is `CONFIG_CMDLINE` (serial console + `signeros.selftest=1`,
from [cmdline-selftest](buildroot-external/board/signeros/cmdline-selftest)).
That has to be a second kernel build rather than a second boot entry, because
the command line is compiled into the signed binary and nothing can vary it at
boot — see [Secure Boot](#secure-boot-and-the-unified-kernel-image). A 64 MiB
FAT32 stick labelled `PSBT_DATA` carrying a fixture PSBT is attached as a second
USB device. The kiosk's `--self-test` runs as the same unprivileged user as the
GUI and prints the inspection it would show a human, then signs, writes and reads
back. The harness checks:

- the VM powered itself off, no kernel panic, no oops/BUG
- **no `error while loading shared libraries`** — the RPATH class of failure
- the data partition mounted, and with `rw,noexec,nodev,nosuid,sync`
- `socket(AF_INET, ...)` fails with `ENOSYS` and `/proc/net` does not exist
- `SELFTEST: change-attack-blocked=yes` — a second PSBT on the same stick
  (`forged_change.psbt.bad`) carries this wallet's fingerprint and change path
  on an output it does not control. The run fails unless the engine identifies
  the mismatch, refuses to sign, and would refuse again if asked directly. Its
  name does not end in `.psbt`, so it is never offered as something to sign
- `SELFTEST: PASS`, plus the internal invariants: the txid did not change while
  signing, the file on the medium re-parses, and it carries the signatures
- then it extracts `signed_*.psbt` from the FAT image and verifies every
  signature with `scripts/make_test_data.py`

**Run 2 — framebuffer rendering, on the untouched production image.** Boots it,
waits for the kiosk, takes a screendump over QMP, and analyses the pixels: the
kiosk background `#0d1117` must cover at least 20% of the screen and some pixels
must be the accent colour `#f7931a`. A blank screen, a text console or a panic
trace all fail that test. The screendump is kept so you can look at it.

### Why the verifier reimplements the crypto

`scripts/make_test_data.py` is pure standard-library Python that implements
RIPEMD-160, secp256k1, BIP32, BIP39, bech32, base58check, PSBT serialisation, the
BIP143 sighash and ECDSA verification from scratch.

That is not duplication for its own sake. Asking libwally-core to confirm
libwally-core's signature proves nothing. Two independent implementations
agreeing is evidence. It also means the harness runs on any machine with
`python3` and nothing installed.

Before it is trusted, it proves itself against published test vectors —
`python3 scripts/make_test_data.py self-check`:

```
  ok    RIPEMD-160 of empty string / 'abc' / 'message digest'
  ok    generator times 1 is G, times 2
  ok    BIP32 test vector 1: m, m/0', m/0'/1 xprv
  ok    BIP84 reference wallet: m/84'/0'/0'/0/0 pubkey, address, WIF
  ok    m/84'/0'/0'/0/1 and m/84'/0'/0'/1/0 addresses
  ok    sign then verify; verify rejects a tampered digest; DER round trip
  ok    generated PSBT re-parses
```

`test_in_qemu.sh` runs that self-check first and refuses to test the signer with
fixtures it does not trust.

The fixture is the published BIP39 reference mnemonic (`abandon ... about`) — a
deliberately worthless wallet, so it can be committed without anyone wondering
whether real funds are involved — and it is a two-input, two-output BIP84
transaction so that multi-input signing and fee arithmetic over several UTXOs are
both exercised.

### Verification status of this tree

Executed in this environment, on this tree:

- the full Buildroot build (`./scripts/build.sh`), producing both
  `signeros.img` and `signeros-test.img`
- `./scripts/test_in_qemu.sh` — both runs pass: the headless signing test under
  UEFI in QEMU, and the framebuffer rendering test on the production image
- `./scripts/host_selftest.sh` — the signing core built against libwally
  **1.5.6**, signing the fixture, with every signature verified independently by
  `make_test_data.py`, and all four exported account keys diffed against its
  derivation
- the change-forgery gate, end to end: `forged_change.psbt.bad` (this wallet's
  fingerprint and change path over an address it does not control) is reported
  as a mismatch and refused, in both the host run and the booted image
- `make_test_data.py self-check` passes every published vector it asserts,
  including BIP32 vector 1, the BIP84/BIP86 reference wallets, the BIP49
  testnet address and BIP341's taproot tweak
- every shell script parses (`make check-scripts`)

Executed on real hardware, from a USB stick, on several different laptops and
desktops with **Secure Boot disabled**:

- the image boots to the kiosk and the input enumeration in `main.cpp` picks the
  machine's devices up without configuration
- **the touchpad path.** `ui/touchpad.cpp` has been driven on several laptops'
  own pads — the one thing QEMU structurally cannot show, since `usb-tablet`
  takes the absolute-pointer path instead
- **the mnemonic grids as an interaction**, by hand: arrow-key movement between
  cells, Tab, click-to-cell, the import screen's word-count selector (**F4**) and
  the live red marking of a cell whose word is not in the wordlist all behave as
  built. That covers the whole Qt half of the entry model, which no automated
  test in this tree can reach
- **wallet creation end to end**, through the current grid entry: seed
  generated, words shown, all of them typed back, passphrase entered, descriptor
  file written to the data partition
- **2-of-2 multisig signing**, end to end in the booted production image

The independent re-derivation of a created wallet's export — its fingerprint,
four account xpubs and four first addresses recomputed from the same words by
`make_test_data.py` and found identical — was done in an earlier booted run,
before the grid rewrite. That evidence still stands for the derivation, which
the rewrite did not touch; what the rewrite changed was how the words reach it,
and that is what the hardware runs above cover.

The xpub diff earned its keep on its first run: it caught the signer handing
`wally_bip32_key_to_address()` a network identifier where the function wants a
raw base58 prefix byte, which produced well-formed, checksummed BIP44 and BIP49
addresses with the wrong prefix. Nothing else in the build noticed.

Still unproven:

- **Secure Boot, in its entirety.** No image has been signed with
  `SIGNEROS_SB_KEY`/`SIGNEROS_SB_CERT` and no certificate has been enrolled into
  `db` — not on real firmware and not on EDK2. Every machine the image has run on
  had Secure Boot switched off. [Secure Boot and the unified kernel image](#secure-boot-and-the-unified-kernel-image)
  describes what the build does and what enrolment requires; none of it has been
  executed.
- **a real touchscreen panel.** Touchscreens take Qt's `evdevtouch` handler
  rather than `touchpad.cpp`, and QEMU's `usb-tablet` is an absolute pointer, so
  neither the hardware runs above nor `make gui` is evidence about them.

What is no longer on that list is the entry UI. It was proven by hand, because
nothing here can prove it otherwise — `test-gui` is a pixel check on the splash,
so no test in this tree presses a key, moves a cursor or clicks a cell. A new
screen that takes typing inherits that: `make gui` first, then a stick.

---

## Versioning

`VERSION` at the repo root holds one line - `0.1.0` - and it is the only place
the release version is written down. Everything that needs it reads it from
there, so cutting a release is that one edit followed by a build:

| Where it ends up | How |
|---|---|
| `output/images/signeros-<version>-x86_64.img` | `post-image.sh` renames what genimage produced, then leaves `signeros.img` as a symlink to it, so every script and every instruction that names the plain file still works. The same for `signeros-test-<version>-x86_64.img`. An image from a previous version is deleted rather than left in the directory next to the new one |
| `/etc/signeros-build` inside the initramfs | `post-build.sh` stamps `SIGNEROS_VERSION=`, so the version is part of what `bzImage` hashes to - the published hash is a hash *of a version*, not of an anonymous build |
| the splash, the home screen and the shutdown screen | compiled in as `SIGNEROS_VERSION_STR`, passed by the package makefile as a `-D`. `btc_signer_gui --version` prints the same string |

`SIGNEROS_VERSION=0.2.0-rc1 make image` overrides the file for a build you do
not want to commit a version bump for. `build.sh` validates the string in its
first second - it becomes a file name, a C string literal and an on-screen
label - and forces the kiosk's configure step when it changes, because a
changed `-D` alone does not invalidate a cmake stamp and the image would
otherwise be named for a version the binary inside it does not report.

`make check-scripts` fails on a malformed `VERSION`, and `make version` prints
what this tree currently builds as.

---

## Reproducibility

`BR2_REPRODUCIBLE=y`, `BR2_OPTIMIZE_2=y`, and every input pinned: the Buildroot
tag in `scripts/build.sh`, the libwally-core git tag (which pins secp256k1-zkp
through its submodule), and fixed disk/partition UUIDs in the genimage configs.

Compare `sha256sum` of **`output/images/bzImage`**. That is the unsigned unified
kernel image, which is the entire boot payload — kernel, root filesystem and
command line — so agreeing on it is agreeing on everything that executes. Two
people on different machines should get the same answer; if they do not, that is
a bug worth reporting.

`signeros.img` deliberately does *not* match between two people: it embeds a
Secure Boot signature, so it differs per signing key. Reproducing the payload and
signing it locally is the intended workflow, the same split Debian and Fedora use.

libwally-core is fetched by git tag with submodules rather than as a tarball with
a recorded hash, because a hash committed here would have to be taken on trust
from whoever committed it. The tag and submodule revision are the pin. Run
`./scripts/build.sh --source-only` once on a networked machine to populate `dl/`,
and every later build is offline.

---

## Threat model, and what is *not* covered

SignerOS is built on the assumption that **the online machine is compromised**.
Everything it shows you is re-derived from the PSBT itself, and it refuses to
sign what it cannot verify.

What it does not defend against, stated plainly:

- **Physical tampering of the stick, if you do not sign.** Signing is opt-in.
  Build without `SIGNEROS_SB_KEY` and an attacker who can rewrite the ESP
  replaces the whole boot payload, and nothing notices. Build with it, enrol your
  certificate in db, and that specific attack is what Secure Boot stops — see
  [Secure Boot](#secure-boot-and-the-unified-kernel-image). Keep the stick
  physically controlled either way.
- **Firmware itself.** Everything above rests on the firmware honouring its own
  key database. A tampered or backdoored firmware, or one whose setup password
  you do not control, verifies nothing you can rely on. `CONFIG_EFI_VARS` and
  `CONFIG_EFIVAR_FS` are off, so SignerOS cannot read or write EFI variables at
  all — it neither depends on them nor becomes a way to attack them.
- **Whoever holds the signing key.** It signs the boot payload of your signer.
  Keep `keys/SignerOS_db.key` offline; `keys/` is gitignored, and
  `make_sb_keys.sh` refuses to overwrite an existing key because regenerating one
  silently invalidates every image already enrolled elsewhere.
- **Cold-boot attacks.** Once the DIMMs are powered, key material is out of
  software's reach. The scrub at shutdown, `init_on_free=1` and `mlock` cover
  software-visible memory, not DRAM remanence.
- **A malicious build host.** Reproducible builds let you *detect* this by
  comparing hashes with someone else; they do not prevent it.
- **Vendor GPU firmware**, if you enable the `gpu-firmware` fragment. That puts
  binary blobs into the trusted boot payload. It is off by default for exactly
  this reason.
- **Shoulder surfing and cameras.** The mnemonic is typed on a screen. The
  in-progress word is visible by design.
- **You, verifying the wrong thing.** The device shows you addresses and amounts;
  it cannot know which address you *meant*. Check the destination against a
  source you trust independently, and check the master fingerprint on the signing
  screen matches your wallet. What it *can* tell you is which outputs come back
  to you — and it proves that by derivation rather than believing the file, so
  the amount on the confirmation page is the amount actually leaving your wallet
  (see [Change is proved, never believed](#change-is-proved-never-believed)).

---

## Configuration

[/etc/signeros.conf](buildroot-external/board/signeros/rootfs-overlay/etc/signeros.conf)
holds the runtime settings, and every one can be overridden as
`signeros.<name>=<value>` on the kernel command line — which, on this image,
means the command line compiled into the kernel by `CONFIG_CMDLINE` in
[linux_hardening_defconfig](buildroot-external/board/signeros/linux_hardening_defconfig)
section 2b. Changing one is a rebuild, not a boot-time edit; that is the point of
[compiling it in](#why-the-command-line-is-compiled-in), and it is the same
mechanism the self-test image uses.

| | |
|---|---|
| `NETWORK` | `mainnet` (default), `testnet`, `signet`, `regtest` |
| `DATA_LABEL` | filesystem label to look for (`PSBT_DATA`) |
| `MOUNT_POINT` | `/mnt/data` |
| `DATA_DEV` | explicit device override, for when several volumes share the label |
| `QPA` | `auto`, `linuxfb`, `eglfs` |
| `WRITE_FINAL_TX` | also write a broadcast-ready raw transaction when the PSBT completes |

Building for testnet: `BR2_PACKAGE_BTC_SIGNER_GUI_NETWORK="testnet"`, or add
`signeros.network=testnet` to `CONFIG_CMDLINE` and rebuild. The status bar shows
the active network in orange for mainnet and amber for anything else, because
signing a mainnet transaction while believing you are on testnet is a way to lose
money.

---

## Hardware notes

Any x86_64 UEFI machine. `simpledrm` drives the UEFI GOP framebuffer, so the
panel works without a native driver; `i915`, `amdgpu` and `nouveau` are compiled
in and take over where they can bind without firmware. Input is a USB or PS/2
keyboard, a mouse, a laptop touchpad or a touchscreen — `main.cpp` enumerates
`/dev/input/event*` itself, classifies each device by its evdev capability bits
and names them to Qt through `QT_QPA_EVDEV_{KEYBOARD,MOUSE,TOUCHSCREEN}_PARAMETERS`,
because there is no udev to do it.

Two things about input are worth knowing before bringing up a new machine.

**The kiosk owns the VT, and it has to be given one.** Qt mutes the framebuffer
console's keyboard (`KDSKBMUTE`, `KDSKBMODE=K_OFF`) only on file descriptor 0 and
only if that descriptor is a tty, and the kernel only accepts those ioctls from an
unprivileged process if the VT is the process's *controlling* terminal. So
`signer-session` opens `/dev/tty1` as fd 0 while it is still root, before
`setuidgid`. Without that the console keeps the keyboard and echoes every
keystroke onto the panel over the GUI — which is what a mnemonic being typed into
a signer must never do. `main.cpp` additionally asks for `EVIOCGRAB` on the
keyboard, so no other reader on the image sees those events at all. One
consequence: while the GUI is up the kernel no longer sees Ctrl-Alt-Del, so the
`::ctrlaltdel` line in `/etc/inittab` applies only before the kiosk starts.

**A laptop touchpad is not on the i8042 controller.** On essentially anything
built in the last decade it is HID-over-I2C, Synaptics RMI4 over SMBus, or an
Elan I2C device, and each needs a host controller, a transport driver and
`PINCTRL`/`GPIOLIB` for its interrupt. Section 5a of
`board/signeros/linux_hardening_defconfig` enables that set; trim it to the one
transport your machine uses if you care about the driver surface.

**And a touchpad is not a touchscreen, even though evdev makes them look alike.**
Both report absolute coordinates and `BTN_TOUCH`. The difference is that a
touchscreen's coordinate *is* the answer — the operator is pointing at the thing
they are touching — while a touchpad's has to become a pointer delta first. The
kernel says which is which through `INPUT_PROP_DIRECT` and `INPUT_PROP_POINTER`,
and [main.cpp](src/btc_signer_gui/src/main.cpp) reads those bits to decide.

Touchscreens go to Qt's `evdevtouch` handler. Touchpads cannot: Qt's evdev stack
has no touchpad support at all — that lives in libinput, which needs udev, which
needs a network stack this kernel does not have. So
[touchpad.cpp](src/btc_signer_gui/src/ui/touchpad.cpp) reads the pad's evdev node
directly and feeds `QWindowSystemInterface`: one finger moves the pointer, two
scroll, a tap or a clickpad press clicks. Pointer gain is expressed as a fraction
of the pad traversed and the axis ranges come from `EVIOCGABS`, so nothing in it
is tuned to one machine's hardware.

Getting that classification wrong is not cosmetic, and it is worth knowing what
it looks like: a touchpad driven as a touchscreen leaves the pointer visible but
motionless — Qt does not move the platform cursor for touch-synthesised events —
and lands every tap at the finger's position *on the pad*. It reads as broken
hardware. QEMU cannot reproduce it either, because `test_in_qemu.sh` attaches a
`usb-tablet`, which has neither `BTN_TOUCH` nor MT slots and so takes the
absolute-pointer path instead. `make gui` is not evidence about touchpads; this
path has been proven the only way it can be, by driving several laptops' own pads
from a booted stick.

A USB mouse always works. On a PS/2 pad, `psmouse.proto=imps` on the kernel
command line is still available as a fallback: it demotes the pad to a plain
relative mouse, which needs none of the above.

Boot with `signeros.inputdebug=1` to have `signer-session` print the kernel's
input device list, the ownership of `/dev/input/*` and the kiosk's own device
classification onto the panel before the GUI starts.

If a specific machine needs native modesetting (wrong panel resolution on a
modern AMD APU, typically), build with `--fragment gpu-firmware` and re-check the
size report.

Legacy BIOS boot is not supported: the image is UEFI-only by design. There is no
bootloader to provide a CSM path, and the boot payload is a PE binary the
firmware executes itself.

Secure Boot is supported by signing the payload with your own key — see
[Secure Boot](#secure-boot-and-the-unified-kernel-image). If the firmware refuses
an *unsigned* image with `UEFI device has been blocked by the current security
policy`, either sign it or turn Secure Boot off. On HP machines note that
"boot from external media" is a separate policy from Secure Boot, and both have to
allow it.

## License

MIT. See [src/btc_signer_gui/LICENSE](src/btc_signer_gui/LICENSE). Buildroot,
Linux, BusyBox, Qt and libwally-core carry their own licences.
