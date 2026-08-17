#!/usr/bin/env bash
#
# Generate a Secure Boot signing key for SignerOS.
#
#   ./scripts/make_sb_keys.sh              write into keys/ (default)
#   ./scripts/make_sb_keys.sh --dir DIR    write somewhere else
#
# Produces three files:
#
#   SignerOS_db.key   private key. This is what signs the boot payload. Anyone
#                     holding it can produce an image your appliance will boot.
#   SignerOS_db.crt   PEM certificate, used by sbsign/sbverify at build time.
#   SignerOS_db.cer   the same certificate in DER form, which is what firmware
#                     key-enrolment screens read off a FAT partition.
#
# Then build with it and enrol the certificate. This script prints the two export
# lines with absolute paths when it finishes - paste those. A relative path works
# too (build.sh and post-image.sh resolve one against the repo root), but it is
# not relative to your shell's cwd, because Buildroot runs post-image scripts from
# inside buildroot/.
#
#   export SIGNEROS_SB_KEY=$PWD/keys/SignerOS_db.key
#   export SIGNEROS_SB_CERT=$PWD/keys/SignerOS_db.crt
#   ./scripts/build.sh
#
#   Copy SignerOS_db.cer onto any FAT volume, enter firmware setup, put Secure
#   Boot key management into custom/setup mode, and enrol it into *db*. ADD it -
#   do not clear the existing keys - unless you are certain you want to stop the
#   machine booting anything signed by Microsoft, which includes Windows and any
#   distro that boots via shim.
#
# On the trade-off of leaving Microsoft's certificates in db: an MS-signed shim
# and distro GRUB stay loadable on that machine, and either can load SignerOS's
# kernel with a command line of its own. That is exactly why the appliance is
# built with CONFIG_CMDLINE_OVERRIDE=y - the command line is compiled into the
# signed binary, so a hostile loader cannot inject one. See section 2b of
# buildroot-external/board/signeros/linux_hardening_defconfig.
#
# This script deliberately never overwrites an existing key. Regenerating one is
# not a recoverable mistake: every image signed with the old key stops booting on
# machines that only trust the new one, and vice versa.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIR="$REPO_DIR/keys"
DAYS="${DAYS:-3650}"
CN="${CN:-SignerOS Secure Boot}"

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'; BLD=$'\033[1m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; GRN=; YEL=; BLD=; RST=; }

say()  { printf '%s==>%s %s\n' "$BLD" "$RST" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
warn() { printf '%swarning:%s %s\n' "$YEL" "$RST" "$*"; }
good() { printf '%s%s%s\n' "$GRN" "$*" "$RST"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--dir)     DIR="${2:?--dir needs a path}"; shift 2 ;;
	--days)    DAYS="${2:?}"; shift 2 ;;
	--cn)      CN="${2:?}"; shift 2 ;;
	-h|--help) sed -n '3,40p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
	*)         die "unknown option '$1' (try --help)" ;;
	esac
done

# Absolute, so the export lines printed at the end can be pasted anywhere. They
# are consumed by a Buildroot post-image script that runs from a different
# directory entirely.
mkdir -p "$DIR"
DIR="$(cd "$DIR" && pwd)"

command -v openssl >/dev/null 2>&1 || die "openssl not found on PATH"
command -v sbsign  >/dev/null 2>&1 \
	|| warn "sbsign not found on PATH; the build cannot sign until it is installed
         On Debian/Ubuntu: sudo apt install sbsigntool"

KEY="$DIR/SignerOS_db.key"
CRT="$DIR/SignerOS_db.crt"
CER="$DIR/SignerOS_db.cer"

for f in "$KEY" "$CRT" "$CER"; do
	[ -e "$f" ] && die "$f already exists.
Refusing to overwrite a Secure Boot key: images signed with the old one would
stop booting on machines that trust only the new one. Move the old key aside
by hand if you really mean to replace it."
done

chmod 0700 "$DIR"

say "generating a ${DAYS}-day RSA-2048 signing key in $DIR"
# RSA-2048 rather than something larger: this key is verified by firmware
# implementations of wildly varying quality, and 2048-bit RSA with SHA-256 is
# the combination every UEFI implementation actually supports.
openssl req -new -x509 -newkey rsa:2048 -nodes -sha256 \
	-days "$DAYS" -subj "/CN=$CN/" \
	-keyout "$KEY" -out "$CRT" 2>/dev/null

openssl x509 -in "$CRT" -outform DER -out "$CER"

chmod 0600 "$KEY"
chmod 0644 "$CRT" "$CER"

printf '\n'
good "created:"
printf '  %s\n' "$KEY" "$CRT" "$CER"
printf '
Fingerprint (compare this against what the firmware shows when you enrol it):
'
openssl x509 -in "$CRT" -noout -fingerprint -sha256 | sed 's/^/  /'

cat <<EOF

Next:
  export SIGNEROS_SB_KEY=$KEY
  export SIGNEROS_SB_CERT=$CRT
  ./scripts/build.sh

Then copy $(basename "$CER") to a FAT volume and enrol it into db from firmware
setup. Back up $(basename "$KEY") somewhere offline: without it you cannot build
another image this machine will boot.

EOF
