#!/usr/bin/env bash
#
# Write signeros.img to a USB stick.
#
#   sudo ./scripts/flash_usb.sh /dev/sdX [--expand-data]
#   sudo ./scripts/flash_usb.sh /dev/sdX --verify-only    check a stick already
#                                                         written, write nothing
#
# The image is a complete GPT disk: partition 1 is the ESP, holding the single
# unified kernel image (EFI/BOOT/bootx64.efi - kernel, initramfs and command line
# in one PE binary, signed if the build had a key); partition 2 is the empty FAT32
# volume labelled PSBT_DATA where PSBT files live. Writing it replaces everything
# on the target device.
#
# --expand-data grows partition 2 to fill the rest of the stick afterwards, which
# is what you want on anything larger than the 385 MiB the image occupies.
#
# This script is deliberately noisy and asks for confirmation with the device
# model and size spelled out. Getting this wrong destroys a disk.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="${IMAGE:-$REPO_DIR/output/images/signeros.img}"
BOARD_DIR="$REPO_DIR/buildroot-external/board/signeros"
EXPAND=0
WRITE=1

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'; BLD=$'\033[1m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; GRN=; YEL=; BLD=; RST=; }
say()  { printf '%s==>%s %s\n' "$BLD" "$RST" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
warn() { printf '%swarning:%s %s\n' "$YEL" "$RST" "$*"; }
good() { printf '%s%s%s\n' "$GRN" "$*" "$RST"; }

# shellcheck source=../buildroot-external/board/signeros/image-layout.conf
. "$BOARD_DIR/image-layout.conf"

DEVICE="${1:-}"
[ -n "$DEVICE" ] || die "usage: sudo $0 /dev/sdX [--expand-data] [--verify-only]

Candidate removable devices on this machine:
$(lsblk -d -o NAME,SIZE,RM,MODEL 2>/dev/null | awk 'NR==1 || $3==1' | sed 's/^/  /')"

shift
while [ $# -gt 0 ]; do
	case "$1" in
	--expand-data) EXPAND=1; shift ;;
	--verify-only) WRITE=0; shift ;;
	*) die "unknown option '$1'" ;;
	esac
done

[ "$(id -u)" -eq 0 ] || die "this needs root to write to a block device"
[ -f "$IMAGE" ] || die "$IMAGE not found - run scripts/build.sh first"
[ -b "$DEVICE" ] || die "$DEVICE is not a block device"

case "$DEVICE" in
*[0-9]) warn "$DEVICE looks like a partition, not a whole disk. SignerOS needs the
         whole device: the image carries its own partition table." ;;
esac

# ---------------------------------------------------------------------------
# Confirm, loudly
# ---------------------------------------------------------------------------
MODEL="$(lsblk -dno MODEL "$DEVICE" 2>/dev/null | xargs || echo unknown)"
SIZE="$(lsblk -dno SIZE "$DEVICE" 2>/dev/null | xargs || echo unknown)"
REMOVABLE="$(lsblk -dno RM "$DEVICE" 2>/dev/null | xargs || echo '?')"
# -L, because output/images/signeros.img is a symlink to the versioned file the
# build produced; du would otherwise report the size of the link itself.
IMG_SIZE="$(du -hL "$IMAGE" | cut -f1)"

printf '\n'
printf '  image   %s (%s)\n' "$IMAGE" "$IMG_SIZE"
# Which version is about to be written is the one thing the plain name hides,
# and this is the last moment it can still be the wrong one.
if [ -L "$IMAGE" ]; then
	printf '          -> %s\n' "$(readlink "$IMAGE")"
fi
printf '  target  %s\n' "$DEVICE"
printf '  model   %s\n' "$MODEL"
printf '  size    %s\n' "$SIZE"
printf '  removable %s\n' "$REMOVABLE"
printf '\n'
lsblk "$DEVICE" 2>/dev/null | sed 's/^/  /'
printf '\n'

if [ "$REMOVABLE" != "1" ]; then
	warn "$DEVICE is NOT flagged removable. This may be an internal disk."
fi

# Refuse to write to something that is currently mounted: that is almost always
# a mistake, and always a destructive one. Not a reason to refuse to *verify*,
# though - a stick written a minute ago is mounted precisely because the write
# succeeded, and the verification step unmounts it itself.
if [ "$WRITE" -eq 1 ] && mount | grep -q "^$DEVICE"; then
	mount | grep "^$DEVICE" | sed 's/^/  /'
	die "$DEVICE has mounted partitions. Unmount them first if you are certain."
fi

if [ "$WRITE" -eq 1 ]; then
	printf '%sEverything on %s will be destroyed.%s\n' "$RED" "$DEVICE" "$RST"
	printf 'Type the device name to confirm: '
	read -r answer
	[ "$answer" = "$DEVICE" ] || die "not confirmed; nothing written"

	# -----------------------------------------------------------------------
	# Write
	# -----------------------------------------------------------------------
	say "writing (this takes a minute or two)"
	dd if="$IMAGE" of="$DEVICE" bs=4M conv=fsync status=progress
	sync
else
	say "--verify-only: nothing will be written to $DEVICE"
fi

# ---------------------------------------------------------------------------
# Verify the bytes that landed
#
# Two things stand between "the write worked" and "the readback matches", and
# both of them make a perfectly good stick fail:
#
#   1. The desktop mounts the stick before we get to read it. Closing the device
#      after dd makes the kernel re-read the partition table, udisks notices a
#      new FAT32 volume labelled PSBT_DATA, and GNOME mounts it - and mounting a
#      FAT filesystem *writes* to it: bit 0 of the state byte at 0x41 of the boot
#      sector (the "dirty" flag), and the free-cluster counts in the FSInfo
#      sector right behind it. Those bytes are inside the image, so the compare
#      fails every single time, on hardware that is fine.
#
#   2. The page cache answers instead of the medium. Reading the device straight
#      back can be served from what we just wrote rather than from the stick, so
#      a stick that silently dropped the write would pass. That is the failure
#      this check exists for, so the read has to bypass the cache.
#
# Hence: settle udev, unmount anything that appeared, drop the cached buffers,
# and read with O_DIRECT where the kernel allows it.
# ---------------------------------------------------------------------------
say "verifying"

if command -v udevadm >/dev/null 2>&1; then
	udevadm settle --timeout=10 >/dev/null 2>&1 || true
fi
# udevadm settle waits for the kernel's event queue, not for the desktop's
# reaction to it: udisks mounts a moment after the events it was woken by, so a
# check that runs the instant settle returns finds nothing mounted and then gets
# overtaken. Two seconds is enough for that hand-off, and this only ever costs
# two seconds on a job that just spent a minute writing.
sleep 2
for _attempt in 1 2 3 4 5; do
	mounted="$(lsblk -lnpo NAME,MOUNTPOINT "$DEVICE" 2>/dev/null \
	           | awk 'NF > 1 { print $1 }' || true)"
	[ -n "$mounted" ] || break
	for part in $mounted; do
		say "unmounting $part - the desktop mounted it as soon as the write finished"
		umount "$part" 2>/dev/null \
			|| udisksctl unmount -b "$part" >/dev/null 2>&1 \
			|| warn "could not unmount $part; the verification below may fail on
         bytes the mount itself changed rather than on anything you wrote"
	done
	sleep 1
done
sync
blockdev --flushbufs "$DEVICE" 2>/dev/null || true

# -L: stat does NOT follow symlinks by default, and output/images/signeros.img
# is one. Without it this is the length of the *name* it points at - 25 bytes for
# signeros-1.0.1-x86_64.img - and the verification below reads 25 bytes of a
# 385 MiB stick and calls the write a failure.
IMG_BYTES="$(stat -Lc %s "$IMAGE")"
IMG_HASH="$(sha256sum "$IMAGE" | cut -d' ' -f1)"

# O_DIRECT needs both the device to allow it and the length to be aligned to the
# logical block size. A genimage image is always a whole number of MiB, but check
# rather than assume: an unaligned length makes the final read fail with EINVAL,
# which reads as a broken stick and is not one.
IFLAGS="count_bytes"
if [ $((IMG_BYTES % 4096)) -eq 0 ] &&
   dd if="$DEVICE" of=/dev/null bs=4096 count=4096 iflag=direct,count_bytes \
      status=none 2>/dev/null; then
	IFLAGS="direct,count_bytes"
fi
if ! DEV_HASH="$(dd if="$DEVICE" bs=4M count="$IMG_BYTES" iflag="$IFLAGS" status=none \
                 | sha256sum | cut -d' ' -f1)"; then
	die "could not read $IMG_BYTES bytes back from $DEVICE. If the stick is
smaller than the image the write was already truncated; otherwise the device is
failing. Either way, do not boot it."
fi

if [ "$IMG_HASH" != "$DEV_HASH" ]; then
	# Where it differs is the whole diagnosis. The boot half - GPT, then the ESP
	# with the one binary the firmware executes - is what has to be perfect. If
	# that half matches and only PSBT_DATA does not, nothing was written wrongly:
	# something mounted the data volume between the write and this read.
	BOOT_BYTES=$((SIGNEROS_DATA_OFFSET_MIB * 1024 * 1024))
	img_boot="$(dd if="$IMAGE" bs=4M count="$BOOT_BYTES" iflag=count_bytes \
	            status=none | sha256sum | cut -d' ' -f1 || echo unreadable-image)"
	dev_boot="$(dd if="$DEVICE" bs=4M count="$BOOT_BYTES" iflag="$IFLAGS" \
	            status=none | sha256sum | cut -d' ' -f1 || echo unreadable-device)"
	# cmp exits non-zero exactly when it has something to say, and every command
	# in this branch runs under `set -e` with pipefail: without the `|| true` the
	# script dies here, silently, instead of printing the diagnosis it just
	# finished computing.
	first_diff="$(cmp -n "$IMG_BYTES" "$IMAGE" "$DEVICE" 2>/dev/null \
	              | sed -n 's/.*differ: byte \([0-9]*\).*/\1/p' || true)"

	printf '\n'
	printf '  image:  %s\n' "$IMG_HASH"
	printf '  device: %s\n' "$DEV_HASH"
	if [ -n "$first_diff" ]; then
		printf '  first differing byte: %s (%s MiB in)\n' \
			"$first_diff" "$(( (first_diff - 1) / 1024 / 1024 ))"
	fi
	printf '\n'

	if [ "$img_boot" = "$dev_boot" ]; then
		die "verification FAILED, but only in the data partition.

The GPT and the whole ESP - the partition the firmware boots from, and the only
one that matters for what this machine runs - match byte for byte. Every
difference is inside $SIGNEROS_DATA_LABEL, which is what happens when something
mounts that volume between the write and this check: a FAT mount sets a dirty
flag in the boot sector and rewrites the free-cluster counts.

The stick is almost certainly fine and will boot. To get a clean verification,
stop the desktop from mounting it - on GNOME:

  gsettings set org.gnome.desktop.media-handling automount false
  # write the stick, verify, then set it back to true

then re-run this script. If it fails the same way with automounting off, say so:
that would mean the medium really is dropping writes."
	fi

	die "verification FAILED: the stick does not match the image.

The difference reaches the GPT or the ESP, so this is not a mounted-volume
artefact - the boot payload itself did not land. Usual causes, in order: a stick
that is failing or lying about its capacity, a bad USB port or cable, or a write
that was interrupted. Try another stick before trying another explanation.

Do not boot this one."
fi
good "verified: $DEV_HASH"

# ---------------------------------------------------------------------------
# Optionally grow the data partition to fill the stick
# ---------------------------------------------------------------------------
if [ "$EXPAND" -eq 1 ]; then
	if ! command -v sgdisk >/dev/null 2>&1; then
		warn "sgdisk not found (package gdisk); skipping --expand-data.
         The stick works as-is with a ${SIGNEROS_DATA_SIZE_MIB} MiB data partition."
	else
		say "growing partition 2 to fill the device"
		# Move the backup GPT to the real end of the device first, otherwise the
		# new partition end is bounded by the image's idea of where the disk ends.
		sgdisk --move-second-header "$DEVICE" >/dev/null
		sgdisk --delete=2 "$DEVICE" >/dev/null
		sgdisk --new=2:"${SIGNEROS_DATA_OFFSET_MIB}M":0 \
		       --typecode=2:0700 \
		       --change-name=2:"$SIGNEROS_DATA_LABEL" "$DEVICE" >/dev/null
		partprobe "$DEVICE" 2>/dev/null || true
		sleep 2

		# Find the partition 2 node: sdb2, but nvme0n1p2 / mmcblk0p2 elsewhere.
		PART2="${DEVICE}2"
		[ -b "$PART2" ] || PART2="${DEVICE}p2"
		[ -b "$PART2" ] || die "cannot find partition 2 node after repartitioning;
the ESP is intact, so the stick still boots - format partition 2 yourself with
  mkfs.vfat -F 32 -n $SIGNEROS_DATA_LABEL <partition>"

		command -v mkfs.vfat >/dev/null 2>&1 \
			|| die "mkfs.vfat not found (package dosfstools)"
		mkfs.vfat -F 32 -n "$SIGNEROS_DATA_LABEL" "$PART2" >/dev/null
		sync
		good "partition 2 is now $(lsblk -no SIZE "$PART2" | xargs), labelled $SIGNEROS_DATA_LABEL"
	fi
fi

printf '\n'
good "done"
cat <<EOF

  Partition 1  ESP, never touched at runtime: EFI/BOOT/bootx64.efi, which is the
               kernel, the initramfs and the command line in one PE binary
  Partition 2  $SIGNEROS_DATA_LABEL, FAT32 - put unsigned .psbt files in its root

  On the offline machine: boot from this stick. Nothing else is required, and the
  machine's internal disks are invisible to it - there is no driver for them.

EOF
