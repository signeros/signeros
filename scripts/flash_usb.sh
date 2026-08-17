#!/usr/bin/env bash
#
# Write signeros.img to a USB stick.
#
#   sudo ./scripts/flash_usb.sh /dev/sdX [--expand-data]
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

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'; BLD=$'\033[1m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; GRN=; YEL=; BLD=; RST=; }
say()  { printf '%s==>%s %s\n' "$BLD" "$RST" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
warn() { printf '%swarning:%s %s\n' "$YEL" "$RST" "$*"; }
good() { printf '%s%s%s\n' "$GRN" "$*" "$RST"; }

# shellcheck source=../buildroot-external/board/signeros/image-layout.conf
. "$BOARD_DIR/image-layout.conf"

DEVICE="${1:-}"
[ -n "$DEVICE" ] || die "usage: sudo $0 /dev/sdX [--expand-data]

Candidate removable devices on this machine:
$(lsblk -d -o NAME,SIZE,RM,MODEL 2>/dev/null | awk 'NR==1 || $3==1' | sed 's/^/  /')"

shift
while [ $# -gt 0 ]; do
	case "$1" in
	--expand-data) EXPAND=1; shift ;;
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
IMG_SIZE="$(du -h "$IMAGE" | cut -f1)"

printf '\n'
printf '  image   %s (%s)\n' "$IMAGE" "$IMG_SIZE"
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
# a mistake, and always a destructive one.
if mount | grep -q "^$DEVICE"; then
	mount | grep "^$DEVICE" | sed 's/^/  /'
	die "$DEVICE has mounted partitions. Unmount them first if you are certain."
fi

printf '%sEverything on %s will be destroyed.%s\n' "$RED" "$DEVICE" "$RST"
printf 'Type the device name to confirm: '
read -r answer
[ "$answer" = "$DEVICE" ] || die "not confirmed; nothing written"

# ---------------------------------------------------------------------------
# Write
# ---------------------------------------------------------------------------
say "writing (this takes a minute or two)"
dd if="$IMAGE" of="$DEVICE" bs=4M conv=fsync status=progress
sync

# ---------------------------------------------------------------------------
# Verify the bytes that landed
# ---------------------------------------------------------------------------
say "verifying"
IMG_BYTES="$(stat -c %s "$IMAGE")"
IMG_HASH="$(sha256sum "$IMAGE" | cut -d' ' -f1)"
DEV_HASH="$(head -c "$IMG_BYTES" "$DEVICE" | sha256sum | cut -d' ' -f1)"

if [ "$IMG_HASH" != "$DEV_HASH" ]; then
	die "verification FAILED: the stick does not match the image.
  image:  $IMG_HASH
  device: $DEV_HASH
Do not use this stick."
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
