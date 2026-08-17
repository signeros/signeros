#!/usr/bin/env bash
#
# SignerOS post-image hook.
#
# SignerOS has no bootloader. The kernel's EFI stub makes bzImage a PE binary
# that UEFI executes directly, the root filesystem is linked into it as an
# initramfs, and the command line is compiled into it with
# CONFIG_CMDLINE_OVERRIDE=y. So bzImage *is* the unified kernel image, and this
# script's main job is to install it as EFI/BOOT/bootx64.efi - optionally
# Secure Boot signed - and wrap a GPT around it.
#
# Two modes, because the self-test image needs a second kernel build (see the
# signeros-test-image target in external.mk):
#
#   production   invoked by Buildroot as: post-image.sh $BINARIES_DIR
#                installs images/bzImage as the ESP bootloader and produces
#                signeros.img
#
#   self-test    invoked with SIGNEROS_SELFTEST_BZIMAGE=<path> in the
#                environment; installs that kernel instead and produces
#                signeros-test.img, leaving signeros.img alone
#
# Both images carry a kernel built from the same source, the same kernel
# configuration and the same images/rootfs.cpio, so a passing run of
# scripts/test_in_qemu.sh is evidence about the artefact you ship. The only
# difference is CONFIG_CMDLINE.
#
# Secure Boot signing is opt-in through the environment:
#
#   SIGNEROS_SB_KEY    PEM private key
#   SIGNEROS_SB_CERT   matching PEM certificate, enrolled in the firmware's db
#
# Set both and the UKI is signed with sbsign and checked with sbverify. Set
# neither and it is installed unsigned, which boots fine with Secure Boot off
# (and in QEMU) but is rejected by a machine that enforces it. Setting only one
# is an error. scripts/make_sb_keys.sh generates a pair.

set -eu

BINARIES_DIR="${1:?BINARIES_DIR not passed by Buildroot}"
BOARD_DIR="$(cd "$(dirname "$0")" && pwd)"

# shellcheck source=/dev/null
. "$BOARD_DIR/image-layout.conf"

die() { printf 'SignerOS post-image: %s\n' "$*" >&2; exit 1; }
say() { printf 'SignerOS post-image: %s\n' "$*"; }

# Repo root, for resolving relative paths handed to us in the environment.
# BOARD_DIR is <repo>/buildroot-external/board/signeros.
REPO_ROOT="$(cd "$BOARD_DIR/../../.." && pwd)"

# ---------------------------------------------------------------------------
# resolve_in_repo <path>
#
# Buildroot runs a post-image script with the cwd set to the *Buildroot* top
# directory, not the directory the user ran make from. So a relative
# SIGNEROS_SB_KEY=keys/SignerOS_db.key - which is what anyone would naturally
# export from the repo root - would be looked up under buildroot/keys/ and not
# found. Resolve relative paths against the repo root instead, which is where
# scripts/make_sb_keys.sh puts them.
# ---------------------------------------------------------------------------
resolve_in_repo() {
	case "$1" in
	/*) printf '%s\n' "$1" ;;
	*)  printf '%s\n' "$REPO_ROOT/$1" ;;
	esac
}

# The release version, from VERSION at the repo root. scripts/build.sh exports
# it (and validates it there, where the error is cheap); a bare `make` inside
# buildroot/ has no such export, so read the same file rather than inventing a
# different answer. The genimage configs cannot take a variable in an image
# name, so the file is renamed after it is generated - see below.
SIGNEROS_VERSION="${SIGNEROS_VERSION:-}"
if [ -z "$SIGNEROS_VERSION" ] && [ -r "$REPO_ROOT/VERSION" ]; then
	SIGNEROS_VERSION="$(tr -d '[:space:]' < "$REPO_ROOT/VERSION")"
fi
[ -n "$SIGNEROS_VERSION" ] || SIGNEROS_VERSION="0.0.0-dev"

SELFTEST_BZIMAGE="${SIGNEROS_SELFTEST_BZIMAGE:-}"
if [ -n "$SELFTEST_BZIMAGE" ]; then
	MODE="self-test"
	KERNEL="$SELFTEST_BZIMAGE"
	ESP_DIR="$BINARIES_DIR/efi-part-test"
	GENIMAGE_CFG="$BOARD_DIR/genimage-test.cfg"
	IMAGE_NAME="signeros-test.img"
	IMAGE_VERSIONED="signeros-test-$SIGNEROS_VERSION-x86_64.img"
	IMAGE_STALE_GLOB="signeros-test-*-x86_64.img"
else
	MODE="production"
	KERNEL="$BINARIES_DIR/bzImage"
	ESP_DIR="$BINARIES_DIR/efi-part"
	GENIMAGE_CFG="$BOARD_DIR/genimage.cfg"
	IMAGE_NAME="signeros.img"
	IMAGE_VERSIONED="signeros-$SIGNEROS_VERSION-x86_64.img"
	# Deliberately not signeros-*-x86_64.img: that would also match the
	# self-test image, and deleting the other mode's artefact from under it
	# is exactly the kind of confusion between the two builds this tree has
	# already been bitten by once.
	IMAGE_STALE_GLOB="signeros-[0-9]*-x86_64.img"
fi

# ---------------------------------------------------------------------------
# Locate Buildroot's genimage wrapper (cwd is the Buildroot top directory when
# Buildroot runs a post-image script, but do not rely on it).
# ---------------------------------------------------------------------------
GENIMAGE_SH=""
for cand in "support/scripts/genimage.sh" \
            "${BASE_DIR:-}/../support/scripts/genimage.sh" \
            "${O:-}/../support/scripts/genimage.sh"; do
	[ -n "$cand" ] && [ -x "$cand" ] && GENIMAGE_SH="$cand" && break
done
[ -n "$GENIMAGE_SH" ] || die "cannot find support/scripts/genimage.sh"

# ---------------------------------------------------------------------------
# Required inputs
# ---------------------------------------------------------------------------
[ -f "$KERNEL" ] || die "$KERNEL not found"

# The ESP payload must be a PE binary or the firmware has nothing to execute.
# A bzImage built without CONFIG_EFI_STUB is a perfectly valid kernel that
# simply is not bootable this way, and the failure mode on real hardware is an
# unhelpful "no bootable device" - so check the magic here instead.
if [ "$(dd if="$KERNEL" bs=1 count=2 2>/dev/null)" != "MZ" ]; then
	die "$KERNEL is not a PE binary - is CONFIG_EFI_STUB set?
Without the EFI stub there is no bootx64.efi to install and nothing to sign."
fi

# ---------------------------------------------------------------------------
# Is this the kernel we think it is?
#
# post-build.sh checks the kernel *configuration*, which is not the same thing as
# checking the kernel that came out of it. There are two builds in this tree that
# differ only in CONFIG_CMDLINE, and a stale object file or a mistimed
# incremental build is enough to put one where the other belongs. That failure is
# silent and severe: the self-test kernel signs whatever PSBT it finds with a
# mnemonic from a file and powers off, unattended, with no GUI.
#
# So check the artefact. CONFIG_CMDLINE survives as a plain string in the
# uncompressed part of the PE, because the EFI stub parses it before it
# decompresses the kernel - which means grep can see it without unpacking
# anything, and this check needs no tool beyond grep.
# ---------------------------------------------------------------------------
if [ "$MODE" = "production" ]; then
	if grep -aqF 'signeros.selftest=1' "$KERNEL"; then
		die "$KERNEL has signeros.selftest=1 compiled into its command line.
This is the SELF-TEST kernel, not the appliance. Signing and shipping it would
produce a device that signs unattended and powers off instead of showing the GUI.

Most likely the production kernel was never rebuilt after the signeros-test-image
target changed CONFIG_CMDLINE. Force it:
  make -C buildroot O=<output> BR2_EXTERNAL=<external> linux-rebuild"
	fi
	grep -aqF 'lockdown=confidentiality' "$KERNEL" \
		|| die "$KERNEL has no recognisable built-in command line: expected
lockdown=confidentiality to appear in it. Is CONFIG_CMDLINE_BOOL set?"
else
	grep -aqF 'signeros.selftest=1' "$KERNEL" \
		|| die "$KERNEL does not have signeros.selftest=1 compiled in, so it is not
the self-test kernel and scripts/test_in_qemu.sh would never complete. Check the
signeros-test-image target in external.mk."
fi

# ---------------------------------------------------------------------------
# Install the unified kernel image as the removable-media boot path, signing it
# if a key was provided.
# ---------------------------------------------------------------------------
SB_KEY="${SIGNEROS_SB_KEY:-}"
SB_CERT="${SIGNEROS_SB_CERT:-}"

if [ -n "$SB_KEY" ] && [ -z "$SB_CERT" ]; then
	die "SIGNEROS_SB_KEY is set but SIGNEROS_SB_CERT is not; both or neither"
fi
if [ -n "$SB_CERT" ] && [ -z "$SB_KEY" ]; then
	die "SIGNEROS_SB_CERT is set but SIGNEROS_SB_KEY is not; both or neither"
fi

if [ -n "$SB_KEY" ]; then
	SB_KEY="$(resolve_in_repo "$SB_KEY")"
	SB_CERT="$(resolve_in_repo "$SB_CERT")"
fi

rm -rf "$ESP_DIR"
BOOTX64="$ESP_DIR/EFI/BOOT/bootx64.efi"

if [ -n "$SB_KEY" ]; then
	[ -r "$SB_KEY" ] || die "cannot read the signing key: $SB_KEY
SIGNEROS_SB_KEY was '${SIGNEROS_SB_KEY}'. Relative paths are resolved against
the repo root ($REPO_ROOT), because Buildroot runs this script with the cwd set
to the Buildroot directory. Generate a key with: ./scripts/make_sb_keys.sh"
	[ -r "$SB_CERT" ] || die "cannot read the signing certificate: $SB_CERT
SIGNEROS_SB_CERT was '${SIGNEROS_SB_CERT}'."
	command -v sbsign >/dev/null 2>&1 \
		|| die "sbsign not found on PATH but SIGNEROS_SB_KEY is set.
On Debian/Ubuntu: sudo apt install sbsigntool"

	mkdir -p "$(dirname "$BOOTX64")"
	sbsign --key "$SB_KEY" --cert "$SB_CERT" --output "$BOOTX64" "$KERNEL" \
		|| die "sbsign failed on $KERNEL"

	# Verifying against the certificate we just signed with does not prove the
	# firmware will accept it - only that the signature is well-formed and
	# covers this binary. That is still the failure this catches: a truncated
	# or mis-sectioned PE that sbsign accepted and the firmware would refuse.
	if command -v sbverify >/dev/null 2>&1; then
		sbverify --cert "$SB_CERT" "$BOOTX64" >/dev/null \
			|| die "sbverify rejected the image we just signed"
		say "signed and verified bootx64.efi ($(basename "$SB_CERT"))"
	else
		say "signed bootx64.efi ($(basename "$SB_CERT")); sbverify not available to check it"
	fi
	SIGNED=1
else
	install -D -m 0644 "$KERNEL" "$BOOTX64"
	SIGNED=0
fi

# Content for the data partition. genimage resolves a file entry's image= path
# against --inputpath, which Buildroot points at BINARIES_DIR.
install -D -m 0644 "$BOARD_DIR/data-readme.txt" "$BINARIES_DIR/data-readme.txt"

# ---------------------------------------------------------------------------
# Capacity check. The whole root filesystem is RAM-resident, so the unpacked
# size is also the permanent memory cost of the appliance - worth printing
# loudly next to the compressed figure that has to fit on the ESP.
# ---------------------------------------------------------------------------
kib() { du -k "$1" | cut -f1; }
K_UKI=$(kib "$BOOTX64")
K_ESP=$((SIGNEROS_ESP_SIZE_MIB * 1024))

printf '\n'
printf '  %s image, SignerOS %s\n' "$MODE" "$SIGNEROS_VERSION"
printf '  bootx64.efi ......... %6d KiB   ESP payload, %d%% of %d KiB\n' \
	"$K_UKI" "$((K_UKI * 100 / K_ESP))" "$K_ESP"
printf '                                     kernel + initramfs + command line,\n'
printf '                                     one %s PE binary\n' \
	"$([ "$SIGNED" -eq 1 ] && echo signed || echo UNSIGNED)"
if [ -f "$BINARIES_DIR/rootfs.cpio" ]; then
	# Not a subset of the figure above: that one is compressed, this one is what
	# the kernel unpacks into tmpfs and never gives back.
	printf '  rootfs unpacked ..... %6d KiB   permanently resident RAM\n' \
		"$(kib "$BINARIES_DIR/rootfs.cpio")"
fi
printf '\n'

# 6 % headroom for FAT metadata and the directory entries.
if [ "$K_UKI" -gt $((K_ESP - K_ESP / 16)) ]; then
	die "ESP payload does not fit in ${SIGNEROS_ESP_SIZE_MIB} MiB. Raise SIGNEROS_ESP_SIZE_MIB in image-layout.conf and the size= in both genimage configs."
fi

# ---------------------------------------------------------------------------
# Build the image
# ---------------------------------------------------------------------------
# An image from an earlier build of a *different* version is the one artefact in
# this directory that can be mistaken for this one - same shape, same place, and
# nothing in the file says which build it came from. Remove it, and remove the
# symlink too: genimage writes through it otherwise, and the rename below would
# then be a file onto itself.
rm -f "$BINARIES_DIR/$IMAGE_NAME"
for stale in "$BINARIES_DIR"/$IMAGE_STALE_GLOB; do
	if [ -e "$stale" ] && [ "$(basename "$stale")" != "$IMAGE_VERSIONED" ]; then
		say "removing an image from an earlier version: $(basename "$stale")"
		rm -f "$stale"
	fi
done

say "generating $IMAGE_VERSIONED"
"$GENIMAGE_SH" -c "$GENIMAGE_CFG"
[ -f "$BINARIES_DIR/$IMAGE_NAME" ] || die "genimage did not produce $IMAGE_NAME"

# The version belongs in the file name: it is the name that gets uploaded to a
# release, and a downloaded signeros.img says nothing about what it is. The
# plain name stays as a symlink because scripts/test_in_qemu.sh, flash_usb.sh,
# `make flash` and every instruction in the README refer to it - and because a
# symlink is the one form of "both names work" that cannot drift into two
# different images.
mv -f "$BINARIES_DIR/$IMAGE_NAME" "$BINARIES_DIR/$IMAGE_VERSIONED"
ln -sfn "$IMAGE_VERSIONED" "$BINARIES_DIR/$IMAGE_NAME"

# Intermediate filesystem images are not artefacts; drop them so it is obvious
# which files are the deliverables.
rm -f "$BINARIES_DIR"/efi-part.vfat "$BINARIES_DIR"/data-part.vfat \
      "$BINARIES_DIR"/efi-part-test.vfat "$BINARIES_DIR"/data-part-test.vfat \
      "$BINARIES_DIR"/data-readme.txt

say "done"

if [ "$MODE" = "production" ]; then
	if [ "$SIGNED" -eq 0 ]; then
		cat >&2 <<-'EOF'

		  ############################################################
		  ##  bootx64.efi is NOT signed                             ##
		  ############################################################

		  A machine with Secure Boot enabled will refuse to boot this image:

		    UEFI device has been blocked by the current security policy

		  Either turn Secure Boot off in the firmware, or enrol your own key
		  and build with it:

		    ./scripts/make_sb_keys.sh
		    export SIGNEROS_SB_KEY=$PWD/keys/SignerOS_db.key
		    export SIGNEROS_SB_CERT=$PWD/keys/SignerOS_db.crt
		    ./scripts/build.sh

		  Signing is what makes CONFIG_CMDLINE_OVERRIDE meaningful: it is the
		  reason nobody can hand this kernel a command line of their own.

		EOF
	else
		printf '\n  Note: a signed image is reproducible only per key. To compare\n'
		printf '  builds with someone else, compare images/bzImage - the unsigned\n'
		printf '  unified kernel image - not signeros.img.\n'
	fi
	printf '\n  Flash it:   sudo scripts/flash_usb.sh /dev/sdX\n'
	printf '  Test it:    scripts/test_in_qemu.sh\n\n'
fi
