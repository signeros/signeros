#!/usr/bin/env bash
#
# SignerOS verification harness.
#
# The device has no network, no shell and no display server, so the only honest
# way to test a build is to boot the actual image under UEFI and observe it. This
# script does that twice:
#
#   Run 1 - HEADLESS SIGNING TEST (signeros-test.img)
#     Boots with signeros.selftest=1 and a 64 MiB FAT32 stick holding a fixture
#     PSBT. The kiosk's self-test parses it, prints the inspection it would show
#     a human, signs it, writes signed_<timestamp>.psbt and reads it back. The
#     harness then extracts that file from the image and verifies every signature
#     with scripts/make_test_data.py - an independent implementation that does
#     not use libwally-core. libwally confirming its own output would prove
#     nothing.
#
#   Run 2 - GUI RENDERING TEST (signeros.img)
#     Boots the production image untouched, waits for the kiosk, and takes a
#     framebuffer screendump over QMP. It then checks the pixels: the dominant
#     colour must be the kiosk background and some pixels must be the accent
#     colour. A black screen, a kernel panic message or a text console all fail.
#
# Both runs also fail on: kernel panic, "error while loading shared libraries"
# (the RPATH class of problem), oops/BUG traces, and a mount that came up
# without noexec/nosuid.
#
# Neither run passes a kernel command line, and there is no way for it to. Both
# images boot a unified kernel image straight from the ESP - no bootloader, no
# boot menu - and CONFIG_CMDLINE_OVERRIDE=y makes the compiled-in command line
# the only one the kernel will ever see. That is why signeros-test.img exists at
# all: it carries a second kernel build whose CONFIG_CMDLINE is
# board/signeros/cmdline-selftest. Same source, same kernel configuration, same
# rootfs.cpio as the image you ship.
#
# Everything it needs is either in the Buildroot host tree (qemu, its bundled
# EDK2 firmware, mtools, dosfstools) or in the standard library. No system
# packages, no root.

set -uo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
O="${O:-$REPO_DIR/output}"
IMAGES="${IMAGES:-$O/images}"
HOST_DIR="${HOST_DIR:-$O/host}"
BOARD_DIR="$REPO_DIR/buildroot-external/board/signeros"
WORK="${WORK:-$O/qemu-test}"

MEM_MIB="${MEM_MIB:-1024}"
# Byte offset of the fixture's data partition, matching offset=1M in
# scripts/genimage-fixture.cfg. mtools addresses a partition inside an image as
# <image>@@<offset>.
FIXTURE_PART_OFFSET=1048576

# Byte offset of the data partition inside signeros.img, from the layout file
# rather than a second copy of the number.
# shellcheck source=../buildroot-external/board/signeros/image-layout.conf
. "$BOARD_DIR/image-layout.conf"
DATA_PART_OFFSET=$((SIGNEROS_DATA_OFFSET_MIB * 1024 * 1024))
SELFTEST_TIMEOUT="${SELFTEST_TIMEOUT:-240}"
GUI_TIMEOUT="${GUI_TIMEOUT:-180}"
GUI_SETTLE="${GUI_SETTLE:-45}"

RUN_SELFTEST=1
RUN_GUI=1
KEEP=0
INTERACTIVE=0
# Interactive mode boots the production image and nothing else. There is no
# alternative boot entry to offer any more: the command line is compiled into
# the signed kernel (CONFIG_CMDLINE_OVERRIDE=y), so signeros-test.img can only
# ever run the headless self-test.
#
# The addresses still match, because the fixture follows the image instead of
# the other way round: interactive runs generate a MAINNET fixture, so the
# production build's bc1... rendering is what make_test_data.py printed. The
# automated runs keep the testnet fixture the self-test kernel expects.
INTERACTIVE_IMAGE="signeros.img"
INTERACTIVE_FIXTURE_NETWORK="mainnet"

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'; BLD=$'\033[1m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; GRN=; YEL=; BLD=; RST=; }

say()  { printf '%s==>%s %s\n' "$BLD" "$RST" "$*"; }
pass() { printf '  %s[pass]%s %s\n' "$GRN" "$RST" "$*"; }
fail() { printf '  %s[FAIL]%s %s\n' "$RED" "$RST" "$*"; FAILURES=$((FAILURES + 1)); }
warn() { printf '  %s[warn]%s %s\n' "$YEL" "$RST" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }

FAILURES=0

usage() {
	cat <<-EOF
	usage: $(basename "$0") [options]

	  --selftest-only   run only the headless signing test
	  --gui-only        run only the framebuffer rendering test
	  --interactive     open a QEMU window on the production image and stay
	                    attached (for looking at the UI yourself). The fixture is
	                    generated on mainnet to match the production build.
	  --keep            keep $WORK afterwards (logs, screendumps, extracted files)
	  --timeout N       seconds to allow the self-test run (default $SELFTEST_TIMEOUT)
	  -h, --help
	EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--selftest-only) RUN_GUI=0; shift ;;
	--gui-only)      RUN_SELFTEST=0; shift ;;
	--interactive)   INTERACTIVE=1; RUN_SELFTEST=0; RUN_GUI=0; shift ;;
	--keep)          KEEP=1; shift ;;
	--timeout)       SELFTEST_TIMEOUT="${2:?}"; shift 2 ;;
	-h|--help)       usage; exit 0 ;;
	*)               die "unknown option '$1'" ;;
	esac
done

# ---------------------------------------------------------------------------
# Locate the tools. Buildroot's host tree first: that way the harness works on a
# machine with no qemu, no OVMF and no mtools installed, which is the normal
# state of a build server.
# ---------------------------------------------------------------------------
pick() {
	# pick <var-name> <candidate>...  - first candidate that exists wins
	local var="$1"; shift
	local out="" c
	for c in "$@"; do
		if [ -x "$c" ]; then out="$c"; break; fi
		if command -v "$c" >/dev/null 2>&1; then out="$(command -v "$c")"; break; fi
	done
	eval "$var=\"\$out\""
}

# genimage shells out to mkdosfs and mcopy by name, so it needs the Buildroot
# host tree on PATH. That prefix is applied ONLY to the genimage command (see
# make_fixture), never exported: $HOST_DIR/bin also contains a minimal host
# python3 without pbkdf2_hmac, and shadowing the system interpreter breaks
# make_test_data.py in a way that looks nothing like a PATH problem.
GENIMAGE_PATH="$HOST_DIR/bin:$HOST_DIR/sbin:$PATH"

# Buildroot's host QEMU is configured for a headless build server: `-display
# help` lists only `none` and `curses`. That is fine for the automated modes,
# which read the framebuffer over QMP and never want a window - but it is the
# whole point of --interactive, which through that binary can do nothing but
# serve VNC. So an interactive run prefers a system QEMU that can actually open
# a window, and falls back to the Buildroot one when there is none.
#
# $QEMU from the environment overrides both.
qemu_can_open_a_window() {
	[ -n "${1:-}" ] && [ -x "$1" ] || return 1
	"$1" -display help 2>&1 | grep -qE '^(gtk|sdl)$'
}

if [ -n "${QEMU:-}" ]; then
	say "QEMU taken from the environment"
elif [ "$INTERACTIVE" -eq 1 ] &&
     qemu_can_open_a_window "$(command -v qemu-system-x86_64 2>/dev/null)"; then
	QEMU="$(command -v qemu-system-x86_64)"
else
	pick QEMU "$HOST_DIR/bin/qemu-system-x86_64" qemu-system-x86_64
fi

pick GENIMAGE "$HOST_DIR/bin/genimage" genimage
pick MKFS_VFAT "$HOST_DIR/sbin/mkfs.vfat" "$HOST_DIR/bin/mkfs.vfat" mkfs.vfat /usr/sbin/mkfs.vfat
pick MCOPY "$HOST_DIR/bin/mcopy" mcopy
pick MMD "$HOST_DIR/bin/mmd" mmd
pick MDIR "$HOST_DIR/bin/mdir" mdir

[ -n "$QEMU" ] || die "qemu-system-x86_64 not found.
Build it as part of the image (BR2_PACKAGE_HOST_QEMU=y is already in the
defconfig) or install it on the host."
[ -n "$MKFS_VFAT" ] || die "mkfs.vfat not found (BR2_PACKAGE_HOST_DOSFSTOOLS=y provides it)"
[ -n "$GENIMAGE" ] || die "genimage not found (BR2_PACKAGE_HOST_GENIMAGE=y provides it)"
[ -n "$MCOPY" ] || die "mcopy not found (BR2_PACKAGE_HOST_MTOOLS=y provides it)"

# UEFI firmware. QEMU ships prebuilt EDK2 images in its pc-bios directory, which
# is why this harness needs no OVMF package.
OVMF_CODE=""
OVMF_VARS=""
for base in "$HOST_DIR/share/qemu" /usr/share/qemu /usr/share/OVMF /usr/share/edk2/x64 \
            /usr/share/edk2-ovmf/x64 /usr/share/qemu-efi-x86_64; do
	for code in edk2-x86_64-code.fd OVMF_CODE.fd OVMF_CODE.4m.fd OVMF.fd; do
		if [ -z "$OVMF_CODE" ] && [ -f "$base/$code" ]; then
			OVMF_CODE="$base/$code"
			for vars in edk2-i386-vars.fd OVMF_VARS.fd OVMF_VARS.4m.fd; do
				[ -f "$base/$vars" ] && OVMF_VARS="$base/$vars" && break
			done
		fi
	done
done
[ -n "$OVMF_CODE" ] || die "no UEFI firmware found.
Looked for edk2-x86_64-code.fd / OVMF_CODE.fd under the Buildroot host tree and
the usual system paths. Building host-qemu provides one in $HOST_DIR/share/qemu."

[ -f "$IMAGES/signeros.img" ] || die "$IMAGES/signeros.img not found - run scripts/build.sh first"
[ -f "$IMAGES/signeros-test.img" ] || die "$IMAGES/signeros-test.img not found - run scripts/build.sh first"

# The two images come from two kernel builds, and only the second is optional
# (build.sh --no-test-image skips it). So they can drift: a run that tests a
# stale signeros-test.img against a fresh signeros.img proves nothing about the
# build you are holding, and says "PASSED" while doing it.
if [ "$IMAGES/signeros.img" -nt "$IMAGES/signeros-test.img" ]; then
	warn "signeros-test.img is OLDER than signeros.img, so run 1 would exercise a
       previous build. Rebuild both with ./scripts/build.sh (without
       --no-test-image) before trusting this result."
fi

ACCEL="tcg"
if [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
	ACCEL="kvm"
else
	warn "/dev/kvm is not usable; falling back to TCG emulation (slower, so the
         timeouts below are generous)"
fi

say "qemu       $QEMU"
say "firmware   $OVMF_CODE"
say "accel      $ACCEL"

rm -rf "$WORK"
mkdir -p "$WORK"
cleanup() {
	if [ "$KEEP" -eq 0 ] && [ "$FAILURES" -eq 0 ]; then
		rm -rf "$WORK"
	else
		printf '\nartefacts kept in %s\n' "$WORK"
	fi
}
trap cleanup EXIT

# Writable copy of the firmware variable store; the code image stays read-only.
VARS="$WORK/efivars.fd"
if [ -n "$OVMF_VARS" ]; then
	cp "$OVMF_VARS" "$VARS"
else
	# Some distributions ship only a combined image; 528 KiB of zeros is a valid
	# empty variable store for the split builds we care about.
	dd if=/dev/zero of="$VARS" bs=1024 count=528 status=none
fi
chmod u+w "$VARS"

# ---------------------------------------------------------------------------
# The fixture stick: 64 MiB FAT32, labelled PSBT_DATA, holding an unsigned PSBT
# and the mnemonic that signs it.
#
# The test image's own second partition is labelled PSBT_SPARE precisely so that
# this stick is the only PSBT_DATA volume in the VM and the mount is
# unambiguous.
# ---------------------------------------------------------------------------
# The network is a parameter because the image can no longer be told which one to
# use: the self-test kernel has signeros.network=testnet compiled in and the
# production kernel has mainnet. So the fixture follows the image. The automated
# runs pass testnet (what the self-test kernel expects, and what
# make_test_data.py verify checks against); interactive runs pass mainnet so the
# production build's addresses match what was printed.
# ---------------------------------------------------------------------------
# generate_fixture_files <dir> <network>
#
# The PSBT, the mnemonic and expected.json, from an implementation that shares
# no code with libwally-core. Split out from make_fixture because the
# interactive run wants the files without a stick to put them on.
# ---------------------------------------------------------------------------
generate_fixture_files() {
	local dir="$1"
	local network="$2"

	mkdir -p "$dir"
	say "generating the PSBT fixture on $network (independent implementation)"
	python3 "$REPO_DIR/scripts/make_test_data.py" self-check >"$WORK/fixture-selfcheck.log" 2>&1 \
		|| { cat "$WORK/fixture-selfcheck.log"; die "the fixture generator failed its own
test vectors; refusing to test the signer with fixtures we do not trust"; }
	pass "fixture generator matches BIP32/BIP84/RIPEMD-160/bech32 test vectors"

	python3 "$REPO_DIR/scripts/make_test_data.py" generate \
		--out-dir "$dir" --network "$network" | sed 's/^/       /'
}

make_fixture() {
	local img="$1"
	local network="${2:-testnet}"
	local dir="$WORK/fixture"

	generate_fixture_files "$dir" "$network"

	# Partitioned, like a stick written by flash_usb.sh - see
	# scripts/genimage-fixture.cfg for why that matters.
	mkdir -p "$WORK/genimage-tmp" "$WORK/genimage-root"
	rm -rf "$WORK/genimage-tmp"/*
	if ! PATH="$GENIMAGE_PATH" "$GENIMAGE" \
			--rootpath "$WORK/genimage-root" \
			--tmppath "$WORK/genimage-tmp" \
			--inputpath "$dir" \
			--outputpath "$WORK" \
			--config "$REPO_DIR/scripts/genimage-fixture.cfg" > "$WORK/fixture-genimage.log" 2>&1; then
		sed 's/^/       /' "$WORK/fixture-genimage.log" | tail -15
		die "could not build the fixture image"
	fi
	[ -f "$img" ] || die "genimage did not produce $img"
	pass "GPT fixture stick built: $(basename "$img"), data volume at offset $((FIXTURE_PART_OFFSET / 1024 / 1024)) MiB"
}

# ---------------------------------------------------------------------------
# Log analysis, shared by both runs.
# ---------------------------------------------------------------------------
check_log_for_disasters() {
	local log="$1"

	if grep -qE 'Kernel panic|end Kernel panic' "$log"; then
		fail "kernel panic:"
		grep -E -A4 'Kernel panic' "$log" | sed 's/^/         /' | head -20
	else
		pass "no kernel panic"
	fi

	if grep -qE 'Oops|BUG: |general protection fault|unable to handle kernel' "$log"; then
		fail "kernel oops/BUG:"
		grep -E -B2 -A6 'Oops|BUG: ' "$log" | sed 's/^/         /' | head -30
	else
		pass "no kernel oops or BUG"
	fi

	# The RPATH / missing-library class of failure this harness exists to catch.
	if grep -qE 'error while loading shared libraries|cannot open shared object|symbol lookup error' "$log"; then
		fail "dynamic linking failure:"
		grep -E 'error while loading shared libraries|cannot open shared object|symbol lookup error' "$log" \
			| sed 's/^/         /' | head -10
	else
		pass "no missing shared libraries"
	fi

	if grep -q 'Qt: Session management' "$log" || grep -qE 'qt\.qpa\.plugin.*could not' "$log"; then
		fail "Qt platform plugin problem:"
		grep -E 'qt\.qpa' "$log" | sed 's/^/         /' | head -10
	fi

	if grep -q 'SECURITY:' "$log"; then
		fail "the init scripts reported a security problem:"
		grep 'SECURITY:' "$log" | sed 's/^/         /'
	fi
}

check_mount_flags() {
	local log="$1"
	local line
	line="$(grep -m1 'SIGNEROS: mounted ' "$log" || true)"
	if [ -z "$line" ]; then
		fail "the data partition was never mounted (no 'SIGNEROS: mounted' line)"
		grep -E 'SIGNEROS:|datawatch' "$log" | sed 's/^/         /' | head -20
		return
	fi
	pass "data partition mounted: ${line#*SIGNEROS: }"

	local missing=""
	for flag in rw noexec nodev nosuid sync; do
		case "$line" in
		*"$flag"*) ;;
		*) missing="$missing $flag" ;;
		esac
	done
	if [ -n "$missing" ]; then
		fail "mount is missing required flag(s):$missing"
	else
		pass "mount flags include rw,noexec,nodev,nosuid,sync"
	fi
}

# ---------------------------------------------------------------------------
# Run 1: headless signing self-test
# ---------------------------------------------------------------------------
run_selftest() {
	printf '\n'
	say "RUN 1 - headless signing test on signeros-test.img"

	local boot="$WORK/boot-test.img"
	local data="$WORK/fixture.img"
	local log="$WORK/selftest-console.log"

	cp "$IMAGES/signeros-test.img" "$boot"
	make_fixture "$data"

	say "booting (timeout ${SELFTEST_TIMEOUT}s)"
	timeout --foreground "$SELFTEST_TIMEOUT" \
		"$QEMU" \
			-machine "q35,accel=$ACCEL" \
			-m "$MEM_MIB" -smp 2 \
			-drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
			-drive "if=pflash,format=raw,unit=1,file=$VARS" \
			-nic none \
			-device qemu-xhci,id=xhci \
			-drive "if=none,id=bootdisk,format=raw,file=$boot" \
			-device usb-storage,drive=bootdisk,bus=xhci.0 \
			-drive "if=none,id=datadisk,format=raw,file=$data" \
			-device usb-storage,drive=datadisk,bus=xhci.0 \
			-display none -vga std \
			-serial "file:$log" \
			-rtc base=utc \
			-no-reboot \
		>/dev/null 2>"$WORK/selftest-qemu.err"
	local rc=$?

	if [ ! -s "$log" ]; then
		fail "the VM produced no serial output at all (qemu exit $rc)"
		sed 's/^/         /' "$WORK/selftest-qemu.err" | head -20
		return
	fi

	if [ "$rc" -eq 124 ]; then
		fail "timed out after ${SELFTEST_TIMEOUT}s without powering off"
	else
		pass "the VM powered itself off (qemu exit $rc)"
	fi

	check_log_for_disasters "$log"
	check_mount_flags "$log"

	# Guardrail 1, proven on the running system rather than inferred from the
	# kernel .config: with CONFIG_NET=n the socket syscall does not exist and
	# /proc/net is absent.
	if grep -q '^SELFTEST: socket-af-inet=unavailable' "$log"; then
		pass "the running system cannot create a socket: $(sed -n 's/^SELFTEST: socket-af-inet=//p' "$log" | head -1)"
	else
		fail "the booted system CAN create an AF_INET socket - it has a network stack"
		grep '^SELFTEST: socket-af-inet' "$log" | sed 's/^/         /'
	fi
	if grep -q '^SELFTEST: proc-net=absent' "$log"; then
		pass "/proc/net does not exist on the booted system"
	else
		fail "/proc/net exists on the booted system"
	fi

	# The change-forgery gate. A PSBT that labels an address we do not control
	# as our own change is the one file that could make this device talk an
	# operator into authorising their own loss, so its refusal is asserted here
	# rather than left to the self-test's overall verdict.
	if grep -q '^SELFTEST: change-attack-blocked=yes' "$log"; then
		pass "a forged change label was rejected: $(sed -n 's/^SELFTEST: change-attack-blocked=yes reason=//p' "$log" | head -1)"
	else
		fail "the forged-change fixture was not rejected (no change-attack-blocked line)"
	fi

	# The watch-only export, checked against a second implementation.
	#
	# The account xpubs the appliance derives decide which wallet its owner's
	# future coins land in, and a wrong one is silent: the file imports cleanly,
	# the coordinator shows a plausible wallet, and the mistake only surfaces
	# once coins have been received at addresses the seed cannot spend from. So
	# the values the booted image actually produced are diffed against
	# make_test_data.py, which derives them with no libwally-core in sight.
	# testnet, because that is what the self-test kernel has compiled into its
	# command line (board/signeros/cmdline-selftest) and therefore what the
	# image derived these keys for.
	#
	# tr -d '\r' first: this log came off an emulated serial console, so every
	# line ends CRLF. Without it the two files differ by one invisible byte per
	# line and the diff shows two identical-looking lists.
	local got="$WORK/export-got.txt" want="$WORK/export-want.txt"
	tr -d '\r' < "$log" \
		| sed -n 's/^SELFTEST: wallet-account=\(.*\) path=\(.*\) xpub=\(.*\) first=\(.*\)$/\1 \2 \3 \4/p' \
		> "$got"
	python3 "$REPO_DIR/scripts/make_test_data.py" wallet-expect --network testnet \
		| tail -n +2 > "$want"
	if [ ! -s "$got" ]; then
		fail "the self-test printed no wallet-account lines"
	elif diff -u "$want" "$got" > "$WORK/export.diff" 2>&1; then
		pass "all $(wc -l < "$got") exported account keys match an independent derivation"
	else
		fail "the exported xpubs do not match the independent derivation"
		sed 's/^/         /' "$WORK/export.diff"
	fi

	# Nothing derived from the seed may reach any medium. The self-test scans
	# the rendered export for the mnemonic's own words and for extended private
	# keys; this is that result, asserted here rather than folded into the
	# overall verdict, because it is the promise the whole creation flow rests
	# on.
	if grep -q '^SELFTEST: wallet-export-has-no-secrets=yes' "$log"; then
		pass "the watch-only export contains no seed words and no private key"
	else
		fail "the watch-only export was not confirmed free of key material"
	fi

	# The self-test's own verdict.
	if grep -q '^SELFTEST: PASS' "$log"; then
		pass "the signer's self-test reported PASS"
	else
		fail "the signer's self-test did not report PASS"
		grep -E '^SELFTEST:|^SIGNEROS:' "$log" | tail -30 | sed 's/^/         /'
	fi

	printf '\n       inspection the signer produced:\n'
	grep -E '^SELFTEST: (psbt-version|txid|inputs|input\[|output\[|output-verified|verified-change|total-in|fee|vsize|finding|finding-verified|signable|fingerprint|change-attack|signatures-added|wrote|readback)' \
		"$log" | sed 's/^SELFTEST: /         /' || true
	printf '\n'

	# Independent verification of the signature that came back.
	local extract="$WORK/extracted"
	mkdir -p "$extract"
	local got_any=0
	# mdir output lists both short and long names; take the long ones that match.
	if [ -n "$MDIR" ]; then
		"$MDIR" -i "$data@@$FIXTURE_PART_OFFSET" "::/" \
			> "$WORK/fixture-listing.txt" 2>/dev/null || true
	fi
	for name in $(grep -oE 'signed_[A-Za-z0-9._-]+\.psbt' "$log" | sort -u); do
		if "$MCOPY" -n -i "$data@@$FIXTURE_PART_OFFSET" "::/$name" \
				"$extract/$name" 2>/dev/null; then
			got_any=1
			pass "extracted $name from the fixture stick"
		fi
	done

	if [ "$got_any" -eq 0 ]; then
		fail "no signed_*.psbt could be extracted from the fixture stick"
		[ -f "$WORK/fixture-listing.txt" ] && sed 's/^/         /' "$WORK/fixture-listing.txt"
		return
	fi

	cp "$extract"/signed_*.psbt "$WORK/fixture/" 2>/dev/null
	if python3 "$REPO_DIR/scripts/make_test_data.py" verify --dir "$WORK/fixture" \
			| sed 's/^/       /'; then
		pass "every signature verified against an independently computed BIP143 sighash"
	else
		fail "independent signature verification rejected the signer's output"
	fi
}

# ---------------------------------------------------------------------------
# Run 2: does the kiosk actually put its own pixels on the framebuffer?
# ---------------------------------------------------------------------------
run_gui() {
	printf '\n'
	say "RUN 2 - framebuffer rendering test on signeros.img (production image)"

	local boot="$WORK/boot-prod.img"
	local log="$WORK/gui-console.log"
	local qmp="$WORK/qmp.sock"
	local shot="$WORK/screen.ppm"

	cp "$IMAGES/signeros.img" "$boot"

	# The production image deliberately has no serial console, so this run is
	# judged on pixels alone and the serial log will normally be empty. That is
	# not a gap: a kernel panic or a failed kiosk leaves a text-mode screen,
	# which fails the colour assertions below just as loudly.
	say "booting, waiting ${GUI_SETTLE}s for the kiosk, then taking a screendump"

	timeout --foreground "$GUI_TIMEOUT" \
		"$QEMU" \
			-machine "q35,accel=$ACCEL" \
			-m "$MEM_MIB" -smp 2 \
			-drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
			-drive "if=pflash,format=raw,unit=1,file=$VARS" \
			-nic none \
			-device qemu-xhci,id=xhci \
			-drive "if=none,id=bootdisk,format=raw,file=$boot" \
			-device usb-storage,drive=bootdisk,bus=xhci.0 \
			-display none -vga std \
			-serial "file:$log" \
			-qmp "unix:$qmp,server,nowait" \
			-rtc base=utc \
			-no-reboot \
		>/dev/null 2>"$WORK/gui-qemu.err" &
	local qemu_pid=$!

	# Wait for the monitor socket, then let the kiosk come up.
	local waited=0
	while [ ! -S "$qmp" ] && [ "$waited" -lt 30 ]; do
		sleep 1
		waited=$((waited + 1))
		kill -0 "$qemu_pid" 2>/dev/null || break
	done

	if [ ! -S "$qmp" ]; then
		fail "QEMU never created its QMP socket"
		sed 's/^/         /' "$WORK/gui-qemu.err" | head -20
		kill "$qemu_pid" 2>/dev/null
		wait "$qemu_pid" 2>/dev/null
		return
	fi

	sleep "$GUI_SETTLE"

	python3 - "$qmp" "$shot" <<-'PY'
		import json, socket, sys, time
		sock_path, out = sys.argv[1], sys.argv[2]
		s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
		s.settimeout(20)
		s.connect(sock_path)
		f = s.makefile("rw", encoding="utf-8", newline="\n")
		f.readline()                                   # greeting
		def cmd(obj):
		    f.write(json.dumps(obj) + "\n"); f.flush()
		    while True:
		        line = f.readline()
		        if not line:
		            raise SystemExit("qmp connection closed")
		        msg = json.loads(line)
		        if "return" in msg or "error" in msg:
		            return msg
		cmd({"execute": "qmp_capabilities"})
		r = cmd({"execute": "screendump", "arguments": {"filename": out}})
		if "error" in r:
		    raise SystemExit("screendump failed: %s" % r["error"])
		time.sleep(1)
		cmd({"execute": "quit"})
	PY
	local shot_rc=$?

	wait "$qemu_pid" 2>/dev/null

	check_log_for_disasters "$log"

	if [ "$shot_rc" -ne 0 ] || [ ! -s "$shot" ]; then
		fail "could not capture a framebuffer screendump"
		return
	fi
	pass "captured a framebuffer screendump ($(du -h "$shot" | cut -f1))"

	# PPM is what QEMU writes and almost nothing opens. Convert it: on a build
	# machine whose QEMU has no GTK or SDL backend, this PNG is the only way to
	# see what the kiosk drew.
	if python3 "$REPO_DIR/scripts/ppm2png.py" "$shot" "${shot%.ppm}.png" --quiet 2>/dev/null; then
		pass "screenshot: ${shot%.ppm}.png"
	fi

	# Pixel analysis. The kiosk's background is #0d1117 and its accent is
	# #f7931a; a text console, a blank screen or a firmware error screen look
	# nothing like that, so this is a real assertion that our UI drew itself.
	python3 - "$shot" <<-'PY'
		import sys
		path = sys.argv[1]
		with open(path, "rb") as f:
		    data = f.read()

		# Parse a binary PPM (P6) header: magic, width, height, maxval.
		def tokens(buf):
		    i, out = 0, []
		    while len(out) < 4:
		        while i < len(buf) and buf[i:i+1].isspace():
		            i += 1
		        if buf[i:i+1] == b"#":
		            while i < len(buf) and buf[i] != 0x0a:
		                i += 1
		            continue
		        j = i
		        while j < len(buf) and not buf[j:j+1].isspace():
		            j += 1
		        out.append(buf[i:j]); i = j
		    return out, i + 1

		tok, off = tokens(data)
		if tok[0] != b"P6":
		    print("  [FAIL] screendump is not a binary PPM"); sys.exit(1)
		w, h = int(tok[1]), int(tok[2])
		px = data[off:off + w * h * 3]
		if len(px) < w * h * 3:
		    print("  [FAIL] screendump is truncated"); sys.exit(1)

		BG = (0x0d, 0x11, 0x17)
		ACCENT = (0xf7, 0x93, 0x1a)

		def near(c, t, tol=26):
		    return all(abs(c[i] - t[i]) <= tol for i in range(3))

		bg = accent = nonblack = 0
		colours = set()
		step = 3 * max(1, (w * h) // 200000)          # sample, do not crawl
		for i in range(0, len(px) - 2, step):
		    c = (px[i], px[i+1], px[i+2])
		    colours.add(c)
		    if sum(c) > 24:
		        nonblack += 1
		    if near(c, BG, 12):
		        bg += 1
		    if near(c, ACCENT):
		        accent += 1
		sampled = len(range(0, len(px) - 2, step))

		print("  [info] %dx%d, %d distinct colours sampled, %.1f%% kiosk background, "
		      "%d accent pixels" % (w, h, len(colours), 100.0 * bg / sampled, accent))

		fails = 0
		if nonblack == 0:
		    print("  [FAIL] the framebuffer is entirely black - nothing rendered")
		    fails += 1
		if len(colours) < 8:
		    print("  [FAIL] only %d distinct colours: this looks like a text console, "
		          "not the kiosk" % len(colours))
		    fails += 1
		if bg * 100 < sampled * 20:
		    print("  [FAIL] the kiosk background colour #0d1117 covers only %.1f%% of "
		          "the screen; the signer UI does not appear to be up"
		          % (100.0 * bg / sampled))
		    fails += 1
		if accent == 0:
		    print("  [FAIL] no pixels in the accent colour #f7931a; the status bar and "
		          "buttons are missing")
		    fails += 1
		if fails == 0:
		    print("  [pass] the framebuffer shows the SignerOS kiosk")
		sys.exit(1 if fails else 0)
	PY
	if [ $? -ne 0 ]; then
		FAILURES=$((FAILURES + 1))
	fi

	printf '       screendump: %s\n' "$shot"
	[ -f "${shot%.ppm}.png" ] && printf '       open this to see the UI: %s\n' "${shot%.ppm}.png"
	KEEP=1     # a picture of the UI is worth keeping either way
}

# ---------------------------------------------------------------------------
# Interactive mode: no assertions, just show the operator the real thing.
# ---------------------------------------------------------------------------
run_interactive() {
	local boot="$WORK/boot-interactive.img"
	local dir="$WORK/fixture"
	[ -f "$IMAGES/$INTERACTIVE_IMAGE" ] || die "$IMAGES/$INTERACTIVE_IMAGE not found"
	cp "$IMAGES/$INTERACTIVE_IMAGE" "$boot"

	# The fixture goes INTO partition 2 of the boot image, not onto a second USB
	# stick.
	#
	# A separate stick would be a second volume labelled PSBT_DATA, because the
	# production image already carries one - and signeros-datawatch is right to
	# refuse to guess between two of them. board/signeros/image-layout.conf keeps
	# the automated runs unambiguous by labelling the test image's spare
	# partition PSBT_SPARE, but interactive mode boots the production image,
	# which claims the real label, so that safeguard does not apply here.
	#
	# Writing into partition 2 is also simply what the operator's stick looks
	# like: one device, boot on p1, data on p2, exactly what flash_usb.sh
	# produces.
	generate_fixture_files "$dir" "$INTERACTIVE_FIXTURE_NETWORK"
	local f
	for f in "$dir"/*.psbt "$dir"/test_mnemonic.txt; do
		[ -f "$f" ] || continue
		"$MCOPY" -o -i "$boot@@$DATA_PART_OFFSET" "$f" "::/" \
			|| die "could not copy $(basename "$f") into the data partition"
	done
	pass "fixture installed on the boot stick's own data partition"

	# The Buildroot host QEMU is built without GTK and SDL, so it has no local
	# window backend at all - it falls back to serving VNC. Say so plainly
	# instead of letting the operator stare at a "VNC server running" line.
	local display_args=()
	if ! "$QEMU" -display help 2>&1 | grep -qE '^(gtk|sdl)$'; then
		# Bind VNC explicitly to loopback rather than letting QEMU fall back to
		# it silently. This is host-side plumbing - QEMU reads the emulated
		# framebuffer from outside the VM - and the guest, having no socket
		# layer, cannot see or reach it. Still worth being deliberate about:
		# anything listening on a port near this project deserves to be there on
		# purpose and no wider than loopback.
		display_args=(-vnc 127.0.0.1:0)
		warn "this QEMU has no gtk/sdl display backend (only: $("$QEMU" -display help 2>&1 | sed -n '2,$p' | tr '\n' ' '))"
		printf '
       It will serve VNC on 127.0.0.1:5900 instead. To interact with it you need
       one of:

         a VNC client        sudo apt install tigervnc-viewer   # then:
                             vncviewer 127.0.0.1:5900
         a QEMU with a GUI   sudo apt install qemu-system-x86
                             (this script prefers a system qemu-system-x86_64
                              over the Buildroot one once it exists)

       To just LOOK at the UI without installing anything, use
         make test-gui
       which boots the image, captures the framebuffer over QMP and writes a
       PNG you can open.

'
	fi
	say "booting $INTERACTIVE_IMAGE; close QEMU or press Ctrl-C to stop"
	[ ${#display_args[@]} -gt 0 ] && say "VNC (host side, loopback only): 127.0.0.1:5900"
	printf '
       The kiosk owns the screen - there is no way out of it by design.
       Drive it with the mouse, or with a keyboard:
         Enter    check the key, then review; Enter again on the
                  confirmation page signs
         Escape   back to the file list
         F12      shutdown screen
       The mnemonic for the fixture is the BIP39 reference one:
         abandon x11 then about
       Typing "ab" and tapping a suggestion is quicker than typing it out.
       After signing, verify the result from the host with:
         %s/scripts/make_test_data.py verify --dir %s

' "$REPO_DIR" "$WORK/fixture"
	# A snap-confined terminal - VS Code's integrated one, notably - exports GTK
	# and GLib module paths that point inside the snap: GTK_PATH, GDK_PIXBUF_*,
	# GIO_MODULE_DIR, LOCPATH. A system QEMU that loads those modules pulls snap
	# libraries into a process linked against the system glibc, and dies before
	# the window ever appears:
	#
	#   symbol lookup error: /snap/core20/current/lib/x86_64-linux-gnu/
	#   libpthread.so.0: undefined symbol: __libc_pthread_init, GLIBC_PRIVATE
	#
	# QEMU needs none of them, so the window is opened with them cleared. This
	# is the only mode that opens one; the automated runs use -display none.
	local clean_env=(env -u GTK_PATH -u GTK_MODULES -u GTK_EXE_PREFIX
		-u GTK_IM_MODULE_FILE -u GDK_PIXBUF_MODULE_FILE -u GDK_PIXBUF_MODULEDIR
		-u GIO_MODULE_DIR -u LOCPATH -u LD_LIBRARY_PATH -u LD_PRELOAD)

	"${clean_env[@]}" "$QEMU" \
		-machine "q35,accel=$ACCEL" \
		-m "$MEM_MIB" -smp 2 \
		-drive "if=pflash,format=raw,unit=0,readonly=on,file=$OVMF_CODE" \
		-drive "if=pflash,format=raw,unit=1,file=$VARS" \
		-nic none \
		-device qemu-xhci,id=xhci \
		-drive "if=none,id=bootdisk,format=raw,file=$boot" \
		-device usb-storage,drive=bootdisk,bus=xhci.0 \
		-vga std -device usb-kbd -device usb-tablet \
		"${display_args[@]}" \
		-rtc base=utc -no-reboot

	KEEP=1

	# Bring back whatever was signed. The files live inside the image now, and
	# the verify command printed above expects to find them in $dir.
	local listing="$WORK/data-listing.txt" name
	[ -n "$MDIR" ] || return 0
	"$MDIR" -i "$boot@@$DATA_PART_OFFSET" "::/" > "$listing" 2>/dev/null || true
	for name in $(grep -oE 'signed_[A-Za-z0-9._-]+\.psbt' "$listing" | sort -u); do
		"$MCOPY" -n -o -i "$boot@@$DATA_PART_OFFSET" "::/$name" "$dir/$name" 2>/dev/null \
			&& pass "recovered $name into $dir"
	done
}

# ---------------------------------------------------------------------------

if [ "$INTERACTIVE" -eq 1 ]; then
	run_interactive
	exit 0
fi

[ "$RUN_SELFTEST" -eq 1 ] && run_selftest
[ "$RUN_GUI" -eq 1 ] && run_gui

printf '\n'
if [ "$FAILURES" -eq 0 ]; then
	printf '%s========================================================%s\n' "$GRN" "$RST"
	printf '%s SignerOS verification PASSED%s\n' "$GRN" "$RST"
	printf '%s========================================================%s\n' "$GRN" "$RST"
	exit 0
fi

printf '%s========================================================%s\n' "$RED" "$RST"
printf '%s SignerOS verification FAILED: %d check(s)%s\n' "$RED" "$FAILURES" "$RST"
printf '%s========================================================%s\n' "$RED" "$RST"
exit 1
