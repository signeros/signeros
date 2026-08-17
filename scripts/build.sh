#!/usr/bin/env bash
#
# SignerOS build driver.
#
#   ./scripts/build.sh                       full build
#   ./scripts/build.sh --fragment eglfs      ... with a config fragment applied
#   ./scripts/build.sh --no-test-image       skip signeros-test.img (one kernel build)
#   ./scripts/build.sh --source-only         download everything, build nothing
#   ./scripts/build.sh --menuconfig          inspect/adjust the configuration
#   ./scripts/build.sh --clean               throw the output tree away
#
# Two Buildroot invocations, not one. The first builds the appliance and
# signeros.img. The second runs the signeros-test-image target, which rebuilds
# the kernel with the self-test command line and produces signeros-test.img -
# necessary because CONFIG_CMDLINE_OVERRIDE=y means the command line is part of
# the signed binary and cannot be varied at boot. See external.mk.
#
# The Buildroot checkout is pinned to an exact LTS tag. Nothing about this build
# floats: the tag here, the git revision in package/libwally-core (which pins
# secp256k1-zkp through its submodule), and BR2_REPRODUCIBLE=y together mean two
# people on different machines should be able to compare hashes and get the same
# answer. Compare images/bzImage - the unsigned unified kernel image, which is
# the entire boot payload. signeros.img embeds a Secure Boot signature and so
# differs per signing key by design.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BR_VERSION="${BR_VERSION:-2026.02.3}"
BR_DIR="${BR_DIR:-$REPO_DIR/buildroot}"
BR_URL="${BR_URL:-https://gitlab.com/buildroot.org/buildroot.git}"
O="${O:-$REPO_DIR/output}"
DEFCONFIG="buildroot_x86_64_defconfig"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

FRAGMENTS=()
DO_CLEAN=0
DO_MENUCONFIG=0
DO_SOURCE_ONLY=0
DO_RECONFIG=0
DO_TEST_IMAGE=1

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; BLD=$'\033[1m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; GRN=; BLD=; RST=; }

say()  { printf '%s==>%s %s\n' "$BLD" "$RST" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
good() { printf '%s%s%s\n' "$GRN" "$*" "$RST"; }

usage() {
	sed -n '3,10p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
	cat <<-EOF

	Options:
	  --fragment NAME     apply configs/fragments/NAME.fragment (repeatable)
	                      available: $(cd "$REPO_DIR/buildroot-external/configs/fragments" 2>/dev/null && ls *.fragment 2>/dev/null | sed 's/\.fragment//' | tr '\n' ' ')
	  --jobs N            parallel jobs (default: $JOBS)
	  --br-version TAG    Buildroot tag to use (default: $BR_VERSION)
	  --reconfigure       regenerate .config from the defconfig, keep downloads
	  --no-test-image     do not build signeros-test.img; saves one kernel
	                      rebuild, but scripts/test_in_qemu.sh needs that image
	  --menuconfig        open Buildroot's menuconfig and exit
	  --source-only       fetch all sources into dl/ and stop (for offline builds)
	  --clean             remove $O and exit
	  -h, --help
	EOF
}

while [ $# -gt 0 ]; do
	case "$1" in
	--fragment)     FRAGMENTS+=("${2:?--fragment needs a name}"); shift 2 ;;
	--jobs|-j)      JOBS="${2:?}"; shift 2 ;;
	--br-version)   BR_VERSION="${2:?}"; shift 2 ;;
	--reconfigure)  DO_RECONFIG=1; shift ;;
	--no-test-image) DO_TEST_IMAGE=0; shift ;;
	--menuconfig)   DO_MENUCONFIG=1; shift ;;
	--source-only)  DO_SOURCE_ONLY=1; shift ;;
	--clean)        DO_CLEAN=1; shift ;;
	-h|--help)      usage; exit 0 ;;
	*)              die "unknown option '$1' (try --help)" ;;
	esac
done

if [ "$DO_CLEAN" -eq 1 ]; then
	say "removing $O"
	rm -rf "$O"
	good "clean"
	exit 0
fi

# ---------------------------------------------------------------------------
# The release version of SignerOS itself, as opposed to Buildroot's.
#
# One line in VERSION at the repo root is the authority, and everything that
# needs it reads it from there: the names the images come out with, the stamp
# post-build.sh writes into /etc/signeros-build, and the version compiled into
# the kiosk. Cutting a release is one edit followed by a build.
#
# Exported rather than passed as an argument, because Buildroot hands its
# environment to post-build.sh and post-image.sh - and to the package makefile
# that turns it into a -D for the compiler. SIGNEROS_VERSION=... in the
# environment overrides the file, for a candidate build you do not want to
# commit a version bump for.
#
# Validated here, in the first second, for the same reason the Secure Boot key
# pair is: it ends up in a file name, a C string literal and an on-screen label,
# and none of those is a good place to discover a stray quote 40 minutes in.
# ---------------------------------------------------------------------------
if [ -z "${SIGNEROS_VERSION:-}" ]; then
	[ -r "$REPO_DIR/VERSION" ] || die "$REPO_DIR/VERSION is missing.
It holds one line - the release version, e.g. 0.1.0 - and every part of the
build reads it from there."
	SIGNEROS_VERSION="$(tr -d '[:space:]' < "$REPO_DIR/VERSION")"
fi
case "$SIGNEROS_VERSION" in
[0-9]*.[0-9]*.[0-9]*) ;;
*) die "SIGNEROS_VERSION is '$SIGNEROS_VERSION', which is not a version.
Expected MAJOR.MINOR.PATCH with an optional suffix, e.g. 0.1.0 or 0.2.0-rc1." ;;
esac
case "$SIGNEROS_VERSION" in
*[!0-9A-Za-z.+-]*) die "SIGNEROS_VERSION contains a character that cannot go in
a file name or a C string: '$SIGNEROS_VERSION'. Letters, digits, '.', '-' and
'+' only." ;;
esac
export SIGNEROS_VERSION

# ---------------------------------------------------------------------------
# Host prerequisites. Buildroot checks most of this itself, but failing here
# with a clear message beats failing thirty minutes into a toolchain build.
# ---------------------------------------------------------------------------
missing=()
for tool in git make gcc g++ cpio unzip rsync bc file perl python3 patch which sed wget; do
	command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
done
if [ ${#missing[@]} -gt 0 ]; then
	die "missing host tools: ${missing[*]}
On Debian/Ubuntu:
  sudo apt install build-essential git cpio unzip rsync bc file wget python3 libncurses-dev"
fi

[ "$(id -u)" -ne 0 ] || die "do not build as root; Buildroot refuses to, and it is right to"

# ---------------------------------------------------------------------------
# Buildroot checkout, pinned
# ---------------------------------------------------------------------------
if [ ! -d "$BR_DIR/.git" ]; then
	say "cloning Buildroot $BR_VERSION into $BR_DIR"
	git clone --depth 1 --branch "$BR_VERSION" "$BR_URL" "$BR_DIR" \
		|| die "could not clone Buildroot at tag $BR_VERSION"
else
	current="$(git -C "$BR_DIR" describe --tags --exact-match 2>/dev/null || echo unknown)"
	if [ "$current" != "$BR_VERSION" ]; then
		say "switching Buildroot from $current to $BR_VERSION"
		git -C "$BR_DIR" fetch --depth 1 origin "refs/tags/$BR_VERSION:refs/tags/$BR_VERSION" \
			|| die "could not fetch Buildroot tag $BR_VERSION"
		git -C "$BR_DIR" checkout -q "$BR_VERSION"
	fi
fi
say "Buildroot: $(git -C "$BR_DIR" describe --tags --always)"

BR_EXTERNAL="$REPO_DIR/buildroot-external"
[ -f "$BR_EXTERNAL/external.desc" ] || die "$BR_EXTERNAL/external.desc is missing"

MAKE_ARGS=(-C "$BR_DIR" "O=$O" "BR2_EXTERNAL=$BR_EXTERNAL")

# ---------------------------------------------------------------------------
# Configure
# ---------------------------------------------------------------------------
if [ ! -f "$O/.config" ] || [ "$DO_RECONFIG" -eq 1 ]; then
	mkdir -p "$O"
	say "generating .config from $DEFCONFIG"
	make "${MAKE_ARGS[@]}" "$DEFCONFIG"

	if [ ${#FRAGMENTS[@]} -gt 0 ]; then
		frag_files=()
		for name in "${FRAGMENTS[@]}"; do
			f="$BR_EXTERNAL/configs/fragments/$name.fragment"
			[ -f "$f" ] || die "no such fragment: $name ($f)"
			frag_files+=("$f")
		done
		say "applying fragment(s): ${FRAGMENTS[*]}"
		# merge_config.sh is Buildroot's copy of the kernel script: -m merges
		# without invoking make, then olddefconfig resolves dependencies.
		"$BR_DIR/support/kconfig/merge_config.sh" -m -O "$O" "$O/.config" "${frag_files[@]}"
		make "${MAKE_ARGS[@]}" olddefconfig
	fi
else
	say "reusing existing $O/.config (use --reconfigure to regenerate)"
fi

if [ "$DO_MENUCONFIG" -eq 1 ]; then
	make "${MAKE_ARGS[@]}" menuconfig
	say "configuration saved; run without --menuconfig to build"
	exit 0
fi

if [ "$DO_SOURCE_ONLY" -eq 1 ]; then
	say "downloading all sources into ${BR2_DL_DIR:-$BR_DIR/dl}"
	make "${MAKE_ARGS[@]}" source
	good "sources fetched. This tree can now build with no network access."
	exit 0
fi

# ---------------------------------------------------------------------------
# Configuration sanity.
#
# Checked against the *generated* .config, not the defconfig: a fragment, a
# menuconfig session or a stale output tree can reintroduce any of this. Each
# check below exists because the failure it prevents is expensive and its cause
# is not obvious from the error message.
# ---------------------------------------------------------------------------
if grep -q '^BR2_OPTIMIZE_S=y' "$O/.config" 2>/dev/null &&
   grep -q '^BR2_PACKAGE_GLIBC=y' "$O/.config" 2>/dev/null; then
	die "this configuration has BR2_OPTIMIZE_S=y (-Os) together with glibc, which
does not link. About two minutes into the build you would get:

  libc_pic.os.clean: in function \`__modf_sse41':
    undefined reference to \`__trunc'

glibc's x86-64 multiarch modf variants call trunc(). GCC folds that to a single
roundsd instruction at -O1 and -O2, but at -Os it emits a call to __trunc - and
__trunc lives in libm while those objects land in libc.

Fix: use BR2_OPTIMIZE_2=y. The signer binary still builds at -Os of its own
accord (CMAKE_BUILD_TYPE=MinSizeRel); Qt and the C library get a few percent
bigger, which post-image.sh reports as the ESP payload size.

If you changed this deliberately in an existing output tree, run
  ./scripts/build.sh --clean
first: Buildroot cannot switch optimisation levels incrementally."
fi

# ---------------------------------------------------------------------------
# Secure Boot key pre-flight.
#
# post-image.sh is the last thing a build runs, so a typo'd key path would
# otherwise surface 30-90 minutes in. Check it here, and normalise the paths to
# absolute while we are at it: Buildroot runs post-image scripts with the cwd
# set to the Buildroot directory, so a relative path exported from the repo root
# would be looked up in the wrong place. post-image.sh resolves relative paths
# against the repo root too, but only one of us should have to.
# ---------------------------------------------------------------------------
if [ -n "${SIGNEROS_SB_KEY:-}" ] || [ -n "${SIGNEROS_SB_CERT:-}" ]; then
	[ -n "${SIGNEROS_SB_KEY:-}" ] \
		|| die "SIGNEROS_SB_CERT is set but SIGNEROS_SB_KEY is not; both or neither"
	[ -n "${SIGNEROS_SB_CERT:-}" ] \
		|| die "SIGNEROS_SB_KEY is set but SIGNEROS_SB_CERT is not; both or neither"

	case "$SIGNEROS_SB_KEY"  in /*) ;; *) SIGNEROS_SB_KEY="$REPO_DIR/$SIGNEROS_SB_KEY" ;; esac
	case "$SIGNEROS_SB_CERT" in /*) ;; *) SIGNEROS_SB_CERT="$REPO_DIR/$SIGNEROS_SB_CERT" ;; esac
	export SIGNEROS_SB_KEY SIGNEROS_SB_CERT

	[ -r "$SIGNEROS_SB_KEY" ] || die "cannot read the Secure Boot signing key:
  $SIGNEROS_SB_KEY
Generate one with ./scripts/make_sb_keys.sh, or unset SIGNEROS_SB_KEY and
SIGNEROS_SB_CERT to build an unsigned image."
	[ -r "$SIGNEROS_SB_CERT" ] || die "cannot read the Secure Boot certificate:
  $SIGNEROS_SB_CERT"
	command -v sbsign >/dev/null 2>&1 || die "sbsign not found on PATH, but
SIGNEROS_SB_KEY is set. On Debian/Ubuntu: sudo apt install sbsigntool"

	# Catch a key and certificate that do not belong together now, rather than
	# after a build that produces an image no firmware will accept.
	if command -v openssl >/dev/null 2>&1; then
		key_mod="$(openssl rsa -in "$SIGNEROS_SB_KEY" -noout -modulus 2>/dev/null || true)"
		crt_mod="$(openssl x509 -in "$SIGNEROS_SB_CERT" -noout -modulus 2>/dev/null || true)"
		if [ -n "$key_mod" ] && [ -n "$crt_mod" ] && [ "$key_mod" != "$crt_mod" ]; then
			die "SIGNEROS_SB_KEY and SIGNEROS_SB_CERT are not a pair - the
certificate's public key does not match the private key. Signing would produce
an image the firmware rejects."
		fi
	fi

	say "Secure Boot: signing with $SIGNEROS_SB_CERT"
else
	say "Secure Boot: no key set, the image will be UNSIGNED (see 'make keys')"
fi

# ---------------------------------------------------------------------------
# A version bump has to reach the binary, not just the file names.
#
# The kiosk gets its version as a -D on the compiler command line, and Buildroot
# will not re-run cmake for a changed -D on its own: the package's configure
# stamp is still valid, so an incremental build after an edit to VERSION would
# produce an image named 0.2.0 around a kiosk that says 0.1.0 on the splash. The
# last version built is remembered next to the configuration and the package's
# configure step is forced when it changes.
# ---------------------------------------------------------------------------
VERSION_STAMP="$O/.signeros-version"
if [ -f "$O/.config" ] && [ -d "$O/build" ] &&
   [ "$(cat "$VERSION_STAMP" 2>/dev/null || true)" != "$SIGNEROS_VERSION" ]; then
	if compgen -G "$O/build/btc-signer-gui-*/.stamp_configured" > /dev/null; then
		say "version is now $SIGNEROS_VERSION; reconfiguring the kiosk so the"
		say "binary carries it too"
		make "${MAKE_ARGS[@]}" btc-signer-gui-reconfigure
	fi
fi

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
say "building SignerOS $SIGNEROS_VERSION with $JOBS job(s) - the first run"
say "builds a toolchain and Qt, so expect 30-90 minutes depending on the machine"
start=$(date +%s)

make "${MAKE_ARGS[@]}" -j"$JOBS"

# The self-test image. A second kernel build, because the self-test command line
# has to be compiled in - see the signeros-test-image target in external.mk.
# Deliberately after the main build, so that whatever `make all` left in
# images/bzImage is the production kernel.
if [ "$DO_TEST_IMAGE" -eq 1 ]; then
	say "building signeros-test.img (rebuilds the kernel with the self-test command line)"
	make "${MAKE_ARGS[@]}" -j"$JOBS" signeros-test-image
fi

elapsed=$(( $(date +%s) - start ))
printf '\n'
good "build finished in $((elapsed / 60))m $((elapsed % 60))s"

# Only now, so that an interrupted or failed build does not claim to have
# produced this version.
printf '%s\n' "$SIGNEROS_VERSION" > "$VERSION_STAMP"

IMAGES="$O/images"
printf '\nArtefacts in %s (SignerOS %s):\n' "$IMAGES" "$SIGNEROS_VERSION"
# The images carry the version in their names - that name is what gets uploaded
# to a release - and signeros.img / signeros-test.img are symlinks to them, so
# every script and every instruction that names the plain file still works.
#
# bzImage is the unsigned unified kernel image: kernel, initramfs and command
# line in one PE binary. It is what the ESP's bootx64.efi is made from, and the
# file to compare hashes on when checking a reproducible build against someone
# else's (signeros.img differs per signing key).
for f in "signeros-$SIGNEROS_VERSION-x86_64.img" \
         "signeros-test-$SIGNEROS_VERSION-x86_64.img" \
         bzImage bzImage-selftest; do
	[ -f "$IMAGES/$f" ] && printf '  %-36s %s\n' "$f" "$(du -h "$IMAGES/$f" | cut -f1)"
done
for f in signeros.img signeros-test.img; do
	[ -L "$IMAGES/$f" ] && printf '  %-36s -> %s\n' "$f" "$(readlink "$IMAGES/$f")"
done

cat <<EOF

Next:
  scripts/test_in_qemu.sh                 boot it under UEFI and verify signing
  sudo scripts/flash_usb.sh /dev/sdX      write it to a stick

EOF
