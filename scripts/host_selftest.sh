#!/usr/bin/env bash
#
# Run the signing core on the build machine, without Qt and without QEMU.
#
# The signing core (src/btc_signer_gui/src/core) has no Qt dependency, which
# makes this possible: build it with -DSIGNEROS_BUILD_GUI=OFF, point it at a
# fixture, and let it parse, inspect, sign, write and read back exactly as it
# would inside the appliance. Then verify the signature with
# scripts/make_test_data.py, which shares no code with libwally-core.
#
# This is the fast inner loop - seconds, not the tens of minutes a full Buildroot
# build takes - and it catches essentially every logic error in the part of the
# system that touches money. scripts/test_in_qemu.sh is still what proves the
# *image* works.
#
#   ./scripts/host_selftest.sh                 use an installed libwally-core
#   ./scripts/host_selftest.sh --build-wally   fetch and build libwally-core first

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${WORK:-$REPO_DIR/output/host-selftest}"
WALLY_VERSION="release_1.5.6"
WALLY_PREFIX="$WORK/wally-prefix"
BUILD_WALLY=0
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; BLD=$'\033[1m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; GRN=; BLD=; RST=; }
say()  { printf '%s==>%s %s\n' "$BLD" "$RST" "$*"; }
die()  { printf '%serror:%s %s\n' "$RED" "$RST" "$*" >&2; exit 1; }
good() { printf '%s%s%s\n' "$GRN" "$*" "$RST"; }

while [ $# -gt 0 ]; do
	case "$1" in
	--build-wally) BUILD_WALLY=1; shift ;;
	--clean) rm -rf "$WORK"; good "removed $WORK"; exit 0 ;;
	-h|--help) sed -n '3,17p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'; exit 0 ;;
	*) die "unknown option '$1'" ;;
	esac
done

mkdir -p "$WORK"

# ---------------------------------------------------------------------------
# libwally-core
# ---------------------------------------------------------------------------
CMAKE_PREFIX_ARG=()
if [ "$BUILD_WALLY" -eq 1 ]; then
	if [ ! -f "$WALLY_PREFIX/lib/libwallycore.a" ]; then
		for t in autoreconf automake libtool; do
			command -v "$t" >/dev/null 2>&1 || die "--build-wally needs autotools.
On Debian/Ubuntu:  sudo apt install autoconf automake libtool pkg-config"
		done

		say "cloning libwally-core $WALLY_VERSION (with its secp256k1-zkp submodule)"
		rm -rf "$WORK/libwally-core"
		git clone --depth 1 --branch "$WALLY_VERSION" --recurse-submodules \
			https://github.com/ElementsProject/libwally-core.git "$WORK/libwally-core"

		say "building libwally-core"
		(
			cd "$WORK/libwally-core"
			./tools/autogen.sh
			./configure --prefix="$WALLY_PREFIX" \
				--enable-static --disable-shared \
				--disable-swig-python --disable-swig-java \
				--disable-tests --disable-secp256k1-tests --disable-clear-tests \
				--disable-elements --disable-builtin-memset
			make -j"$JOBS"
			make install
		) > "$WORK/wally-build.log" 2>&1 || {
			tail -40 "$WORK/wally-build.log"
			die "libwally-core failed to build; full log in $WORK/wally-build.log"
		}
	fi
	good "libwally-core: $WALLY_PREFIX/lib/libwallycore.a"
	CMAKE_PREFIX_ARG=(-DCMAKE_PREFIX_PATH="$WALLY_PREFIX")
fi

# ---------------------------------------------------------------------------
# Build the core (no Qt)
# ---------------------------------------------------------------------------
say "configuring the signing core without a GUI"
cmake -S "$REPO_DIR/src/btc_signer_gui" -B "$WORK/build" \
	-DSIGNEROS_BUILD_GUI=OFF \
	-DSIGNEROS_NETWORK=testnet \
	-DCMAKE_BUILD_TYPE=RelWithDebInfo \
	"${CMAKE_PREFIX_ARG[@]}" \
	> "$WORK/cmake.log" 2>&1 || {
		tail -30 "$WORK/cmake.log"
		die "cmake could not configure. If libwally-core is not installed system
wide, re-run with --build-wally. Full log: $WORK/cmake.log"
	}

say "compiling"
cmake --build "$WORK/build" -j"$JOBS" > "$WORK/compile.log" 2>&1 || {
	tail -40 "$WORK/compile.log"
	die "compilation failed; full log in $WORK/compile.log"
}
good "built $WORK/build/btc_signer_gui"

# ---------------------------------------------------------------------------
# Fixture, sign, verify
# ---------------------------------------------------------------------------
say "checking the fixture generator against published test vectors"
python3 "$REPO_DIR/scripts/make_test_data.py" self-check | sed 's/^/    /'

DATA="$WORK/data"
rm -rf "$DATA"
python3 "$REPO_DIR/scripts/make_test_data.py" generate \
	--out-dir "$DATA" --network testnet | sed 's/^/    /'

say "running the signer's self-test"
set +e
"$WORK/build/btc_signer_gui" --self-test \
	--data-dir "$DATA" \
	--mnemonic-file "$DATA/test_mnemonic.txt" \
	--expect-blocked "$DATA/forged_change.psbt.bad" \
	--network testnet | sed 's/^/    /'
rc=${PIPESTATUS[0]}
set -e
[ "$rc" -eq 0 ] || die "the signer's self-test failed (exit $rc)"

say "verifying the signature independently"
python3 "$REPO_DIR/scripts/make_test_data.py" verify --dir "$DATA" | sed 's/^/    /'

# ---------------------------------------------------------------------------
# The watch-only export
#
# The self-test above printed the account xpub and first address for each of
# the four script types SignerOS exports. Re-derive all of them with
# make_test_data.py - a pure-stdlib implementation that shares no code with
# libwally-core - and require the two lists to be identical.
#
# This is not ceremony. A wrong xpub is invisible: the file imports cleanly, the
# coordinator shows a plausible wallet, and the mistake only surfaces when coins
# have been received at addresses the owner's seed cannot spend from. It already
# caught one - libwally's wally_bip32_key_to_address() takes a base58 prefix
# byte where its neighbours take a network identifier, and it accepts the wrong
# one without complaint.
# ---------------------------------------------------------------------------
say "checking the watch-only export against an independent derivation"
"$WORK/build/btc_signer_gui" --self-test \
	--data-dir "$DATA" \
	--mnemonic-file "$DATA/test_mnemonic.txt" \
	--network testnet --discard-output 2>/dev/null \
	> "$WORK/selftest-out.txt"

# Both accounts the self-test derives. Account 0 alone would not prove the
# index is used at all: it is the one value a dropped or wrongly hardened
# account index still gets right, and the import screen lets the operator pick
# any of ten.
for acct in 0 1; do
	if [ "$acct" = 0 ]; then tag=""; else tag="-acct$acct"; fi
	sed -n "s/^SELFTEST: wallet-account$tag=\(.*\) path=\(.*\) xpub=\(.*\) first=\(.*\)$/\1 \2 \3 \4/p" \
		"$WORK/selftest-out.txt" > "$WORK/export-got-$acct.txt"

	python3 "$REPO_DIR/scripts/make_test_data.py" wallet-expect \
		--network testnet --account "$acct" \
		| tail -n +2 > "$WORK/export-want-$acct.txt"

	[ -s "$WORK/export-got-$acct.txt" ] ||
		die "the self-test printed no wallet-account$tag lines"
	diff -u "$WORK/export-want-$acct.txt" "$WORK/export-got-$acct.txt" \
		> "$WORK/export-$acct.diff" || {
		cat "$WORK/export-$acct.diff"
		die "the account $acct xpubs do not match the independent derivation"
	}
	sed 's/^/    /' "$WORK/export-got-$acct.txt"
	good "all $(wc -l < "$WORK/export-got-$acct.txt") account $acct keys match the independent derivation"

	# The BIP48 cosigner keys, diffed the same way and separately: they are a
	# level deeper than the accounts above, so they are exactly the derivation
	# an off-by-one in the path length would still get plausibly wrong. Three
	# fields, not four - a multisig key has no address to compare.
	sed -n "s/^SELFTEST: wallet-cosigner$tag=\(.*\) path=\(.*\) xpub=\(.*\)$/\1 \2 \3/p" \
		"$WORK/selftest-out.txt" > "$WORK/cosigner-got-$acct.txt"

	python3 "$REPO_DIR/scripts/make_test_data.py" wallet-expect \
		--section cosigners --network testnet --account "$acct" \
		| tail -n +2 > "$WORK/cosigner-want-$acct.txt"

	[ -s "$WORK/cosigner-got-$acct.txt" ] ||
		die "the self-test printed no wallet-cosigner$tag lines"
	diff -u "$WORK/cosigner-want-$acct.txt" "$WORK/cosigner-got-$acct.txt" \
		> "$WORK/cosigner-$acct.diff" || {
		cat "$WORK/cosigner-$acct.diff"
		die "the account $acct cosigner keys do not match the independent derivation"
	}
	sed 's/^/    /' "$WORK/cosigner-got-$acct.txt"
	good "all $(wc -l < "$WORK/cosigner-got-$acct.txt") account $acct BIP48 cosigner keys match the independent derivation"
done

printf '\n'
good "host self-test PASSED"
printf 'Artefacts kept in %s\n' "$WORK"
