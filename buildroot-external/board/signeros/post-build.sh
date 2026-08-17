#!/usr/bin/env bash
#
# SignerOS post-build hook.
#
# Two jobs:
#   1. Final touches on the target tree (permissions, files that must not
#      ship, runtime configuration stamped with the actual build).
#   2. Assert the architectural guardrails against the *generated* build
#      artefacts, and fail the build if any of them was silently lost.
#
# (2) is the important half. A hardening fragment that kconfig quietly dropped
# because of an unmet dependency looks exactly like a hardening fragment that
# worked, right up until someone plugs an Ethernet dongle into the signer.
#
# Invoked by Buildroot as: post-build.sh $TARGET_DIR [BR2_ROOTFS_POST_SCRIPT_ARGS]

set -u

TARGET_DIR="${1:?TARGET_DIR not passed by Buildroot}"
BOARD_DIR="$(cd "$(dirname "$0")" && pwd)"

RED=$'\033[1;31m'; GRN=$'\033[1;32m'; YEL=$'\033[1;33m'; RST=$'\033[0m'
[ -t 1 ] || { RED=; GRN=; YEL=; RST=; }

failures=0
fail()  { printf '%s[GUARDRAIL FAIL]%s %s\n' "$RED" "$RST" "$*" >&2; failures=$((failures + 1)); }
warn()  { printf '%s[warn]%s %s\n' "$YEL" "$RST" "$*" >&2; }
ok()    { printf '%s[ok]%s %s\n' "$GRN" "$RST" "$*"; }
info()  { printf '  %s\n' "$*"; }

echo "=== SignerOS post-build ==================================================="

# ---------------------------------------------------------------------------
# 1. Target tree fixups
# ---------------------------------------------------------------------------

# Init scripts and helpers must be executable regardless of the umask or VCS
# the overlay came out of.
for f in "$TARGET_DIR"/etc/init.d/S* \
         "$TARGET_DIR"/usr/bin/signer-session \
         "$TARGET_DIR"/usr/sbin/signeros-datawatch \
         "$TARGET_DIR"/usr/sbin/secure-poweroff; do
	[ -e "$f" ] && chmod 0755 "$f"
done
[ -e "$TARGET_DIR/etc/inittab" ] && chmod 0644 "$TARGET_DIR/etc/inittab"

# The mount point for the untrusted partition. Root-owned, mode 0755: the
# kiosk user gets its access from the mount's uid=/gid= options, not from the
# directory, so a failed mount can never be silently written to in RAM.
mkdir -p "$TARGET_DIR/mnt/data"
chmod 0755 "$TARGET_DIR/mnt/data"

# Runtime home for the kiosk user lives on tmpfs (rootfs is remounted
# read-only), so only the placeholder is needed here.
mkdir -p "$TARGET_DIR/home/signer"

# Nothing on an air-gapped, network-less device should carry network config.
rm -f "$TARGET_DIR"/etc/resolv.conf \
      "$TARGET_DIR"/etc/hosts.deny \
      "$TARGET_DIR"/etc/hosts.allow
rm -rf "$TARGET_DIR"/etc/network \
       "$TARGET_DIR"/etc/dhcp \
       "$TARGET_DIR"/usr/share/udhcpc

# Documentation, examples and Qt developer tooling are pure RAM cost.
rm -rf "$TARGET_DIR"/usr/share/doc \
       "$TARGET_DIR"/usr/share/man \
       "$TARGET_DIR"/usr/share/info \
       "$TARGET_DIR"/usr/lib/cmake \
       "$TARGET_DIR"/usr/lib/pkgconfig \
       "$TARGET_DIR"/usr/lib/qt/examples \
       "$TARGET_DIR"/usr/lib/qt5/examples \
       "$TARGET_DIR"/usr/share/qt5/examples
find "$TARGET_DIR/usr/lib" -maxdepth 1 -name '*.a' -delete 2>/dev/null
find "$TARGET_DIR/usr/lib" -maxdepth 1 -name '*.la' -delete 2>/dev/null

# Stamp the build so the GUI's shutdown screen can show what is running.
#
# The version comes from VERSION at the repo root, the same line the image file
# names and the compiled-in string come from; scripts/build.sh exports it, and a
# bare `make` inside buildroot/ falls back to reading the file. It lands inside
# the initramfs, so it is part of what bzImage hashes to - which is what makes
# the published hash a hash *of a version* rather than of an anonymous build.
SIGNEROS_VERSION="${SIGNEROS_VERSION:-}"
if [ -z "$SIGNEROS_VERSION" ] && [ -r "$BOARD_DIR/../../../VERSION" ]; then
	SIGNEROS_VERSION="$(tr -d '[:space:]' < "$BOARD_DIR/../../../VERSION")"
fi
# Removed first, not truncated: the previous build left this file mode 0444, and
# a redirect into a read-only file fails - silently enough that the stamp inside
# every incremental image was whatever the first build wrote. Harmless while it
# only carried a timestamp; not harmless now that it names the version.
rm -f "$TARGET_DIR/etc/signeros-build"
{
	echo "SIGNEROS_VERSION=${SIGNEROS_VERSION:-0.0.0-dev}"
	echo "SIGNEROS_BUILD_ID=${SOURCE_DATE_EPOCH:-unknown}"
	echo "SIGNEROS_KERNEL=$(basename "$(ls -d "${BUILD_DIR:-/nonexistent}"/linux-* 2>/dev/null | head -1)" 2>/dev/null || echo unknown)"
} > "$TARGET_DIR/etc/signeros-build" \
	|| fail "could not write $TARGET_DIR/etc/signeros-build"
chmod 0444 "$TARGET_DIR/etc/signeros-build"

ok "target tree fixups applied"

# ---------------------------------------------------------------------------
# 2. GUARDRAIL 1 - zero network attack surface
# ---------------------------------------------------------------------------
echo "--- guardrail: kernel matches the hardening fragment --------------------"

KCONFIG="$(ls -d "${BUILD_DIR:?}"/linux-*/.config 2>/dev/null | head -1)"
FRAGMENT="$BOARD_DIR/linux_hardening_defconfig"

if [ -z "$KCONFIG" ] || [ ! -f "$KCONFIG" ]; then
	fail "cannot locate the generated kernel .config under $BUILD_DIR/linux-*"
elif [ ! -f "$FRAGMENT" ]; then
	fail "cannot locate $FRAGMENT"
else
	info "comparing $FRAGMENT"
	info "     against $KCONFIG"

	# Verify EVERY directive in the fragment, not a hand-picked subset.
	#
	# This matters more than it looks. kconfig silently discards a
	# `# CONFIG_X is not set` line when the symbol's prompt is invisible (the
	# `bool "..." if EXPERT` pattern), when something still selects it, or when
	# Buildroot's own KCONFIG_FIXUP_CMDS re-enable it after the merge - and the
	# fragment looks identical either way. A curated list of "important" symbols
	# once caught 3 of 18 real discrepancies here; the fragment itself is the
	# specification, so the fragment itself is what gets checked.
	frag_checked=0
	frag_bad=0

	while IFS= read -r line; do
		case "$line" in
		"# CONFIG_"*" is not set")
			sym="${line#\# }"
			sym="${sym% is not set}"
			# Anything other than absence means it is on.
			if actual="$(grep -m1 -E "^${sym}=" "$KCONFIG")"; then
				fail "kernel: asked for '$sym' to be unset, got '$actual'"
				frag_bad=$((frag_bad + 1))
			fi
			frag_checked=$((frag_checked + 1))
			;;
		CONFIG_*=*)
			sym="${line%%=*}"
			if ! grep -qxF "$line" "$KCONFIG"; then
				actual="$(grep -m1 -E "^${sym}=" "$KCONFIG" || echo "not set")"
				fail "kernel: asked for '$line', got '$actual'"
				frag_bad=$((frag_bad + 1))
			fi
			frag_checked=$((frag_checked + 1))
			;;
		esac
	done < "$FRAGMENT"

	if [ "$frag_bad" -eq 0 ]; then
		ok "all $frag_checked directives in the hardening fragment took effect"
	else
		info "$frag_bad of $frag_checked fragment directives did not take effect"
		info "a fragment line can be silently dropped when the symbol's prompt is"
		info "hidden behind EXPERT, when something still selects it, or when"
		info "Buildroot's kernel fixups re-enable it after the merge"
	fi

	# The handful of invariants that define the product, restated explicitly so
	# the intent survives someone editing the fragment.
	grep -qE '^CONFIG_NET=y' "$KCONFIG" \
		&& fail "CONFIG_NET=y - the device would have a network stack"
	for sym in CONFIG_MODULES CONFIG_DEVMEM CONFIG_ATA CONFIG_BLK_DEV_NVME; do
		grep -qE "^${sym}=y" "$KCONFIG" && fail "$sym=y (must be disabled)"
	done
	for sym in CONFIG_INTEL_IOMMU_DEFAULT_ON CONFIG_AMD_IOMMU \
	           CONFIG_IOMMU_DEFAULT_DMA_STRICT CONFIG_BLK_DEV_INITRD \
	           CONFIG_DRM_SIMPLEDRM CONFIG_VFAT_FS CONFIG_EXFAT_FS; do
		grep -qE "^${sym}=y" "$KCONFIG" || fail "$sym is not enabled (required)"
	done

	# -----------------------------------------------------------------------
	# GUARDRAIL - the boot payload is a single self-contained binary
	#
	# See the README section "Secure Boot and the unified kernel image".
	#
	# Everything boot depends on has to be inside the one PE file that Secure
	# Boot signs. Each check below corresponds to a way of silently ending up
	# with a payload that is only partly covered by that signature.
	# -----------------------------------------------------------------------
	echo "--- guardrail: unified kernel image --------------------------------------"
	uki_bad=0

	# No EFI stub, no bootx64.efi at all.
	grep -qE '^CONFIG_EFI_STUB=y' "$KCONFIG" \
		|| { fail "CONFIG_EFI_STUB is not set - bzImage would not be a bootable PE binary"; uki_bad=1; }

	# The initramfs has to be linked in, not loaded from the ESP. An empty
	# INITRAMFS_SOURCE means Buildroot's BR2_TARGET_ROOTFS_INITRAMFS fixup did
	# not run, and the kernel would come up with no root filesystem at all.
	if grep -qE '^CONFIG_INITRAMFS_SOURCE=""$' "$KCONFIG"; then
		fail "CONFIG_INITRAMFS_SOURCE is empty - is BR2_TARGET_ROOTFS_INITRAMFS set?"
		uki_bad=1
	elif ! grep -qE '^CONFIG_INITRAMFS_SOURCE=' "$KCONFIG"; then
		fail "CONFIG_INITRAMFS_SOURCE is absent - is BR2_TARGET_ROOTFS_INITRAMFS set?"
		uki_bad=1
	fi

	# See section 2a of linux_hardening_defconfig: the built-in compression mode
	# is a kconfig choice that only becomes visible after Buildroot's fixup, so
	# it lands on whichever member is visible first. Every CONFIG_RD_* is off to
	# make NONE the only candidate. If a kernel bump reorders that choice we
	# want to hear about it here, not discover a gzip-in-xz initramfs later.
	grep -qE '^CONFIG_INITRAMFS_COMPRESSION_NONE=y' "$KCONFIG" \
		|| { fail "CONFIG_INITRAMFS_COMPRESSION_NONE is not set - the built-in initramfs
       would be double-compressed. Check that every CONFIG_RD_* is still off."; uki_bad=1; }
	while IFS= read -r rd; do
		fail "kernel: $rd - initrd decompressors must all be off (see section 2a)"
		uki_bad=1
	done < <(grep -E '^CONFIG_RD_[A-Z0-9]+=y' "$KCONFIG")

	# The command line has to be compiled in AND override whatever the firmware
	# passes. Without OVERRIDE, an MS-signed third-party bootloader on the same
	# machine can hand this kernel rdinit=/bin/sh and walk past the kiosk - the
	# signature covers the binary, never the command line.
	grep -qE '^CONFIG_CMDLINE_BOOL=y' "$KCONFIG" \
		|| { fail "CONFIG_CMDLINE_BOOL is not set - the kernel would take its command line from the firmware"; uki_bad=1; }
	grep -qE '^CONFIG_CMDLINE_OVERRIDE=y' "$KCONFIG" \
		|| { fail "CONFIG_CMDLINE_OVERRIDE is not set - a firmware-supplied command line could
       add rdinit=/bin/sh. This is the invariant the whole UKI design rests on."; uki_bad=1; }

	# And the compiled-in command line has to be the *production* one, with the
	# hardening options actually present. This is the check that catches a
	# self-test kernel being shipped as the appliance.
	CMDLINE="$(sed -n 's/^CONFIG_CMDLINE="\(.*\)"$/\1/p' "$KCONFIG" | head -1)"
	if [ -z "$CMDLINE" ]; then
		fail "CONFIG_CMDLINE is empty"
		uki_bad=1
	else
		info "built-in command line:"
		printf '    %s\n' "$CMDLINE"
		for tok in rdinit=/sbin/init lockdown=confidentiality iommu.strict=1 \
		           iommu.passthrough=0 init_on_alloc=1 init_on_free=1 \
		           signeros.data_label=; do
			case " $CMDLINE " in
			*" $tok"*) ;;
			*) fail "built-in command line is missing '$tok'"; uki_bad=1 ;;
			esac
		done
		# Both of these are self-test-only and must never reach the appliance:
		# one turns the signer into an unattended auto-signer, the other puts
		# the kernel log and the signer's output on a serial line.
		case " $CMDLINE " in
		*" signeros.selftest=1"*)
			fail "built-in command line has signeros.selftest=1 - this is a SELF-TEST
       kernel, not a production one. It would sign unattended and power off."
			uki_bad=1 ;;
		esac
		case " $CMDLINE " in
		*" console=ttyS"*)
			fail "built-in command line has a serial console - self-test only"
			uki_bad=1 ;;
		esac
	fi

	[ "$uki_bad" -eq 0 ] && ok "kernel is a self-contained UKI with a locked-down command line"
fi

# BusyBox must not even contain a networking applet.
BBCONFIG="$(ls -d "${BUILD_DIR}"/busybox-*/.config 2>/dev/null | head -1)"
if [ -n "$BBCONFIG" ] && [ -f "$BBCONFIG" ]; then
	for sym in CONFIG_IFCONFIG CONFIG_IP CONFIG_PING CONFIG_WGET CONFIG_NC \
	           CONFIG_TELNET CONFIG_TELNETD CONFIG_UDHCPC CONFIG_HTTPD \
	           CONFIG_NSLOOKUP CONFIG_ROUTE CONFIG_TFTP; do
		grep -qE "^${sym}=y" "$BBCONFIG" && fail "busybox: $sym=y (network applet must be removed)"
	done
	for sym in CONFIG_BLKID CONFIG_SETUIDGID CONFIG_MDEV; do
		grep -qE "^${sym}=y" "$BBCONFIG" || fail "busybox: $sym is required by the SignerOS init scripts"
	done
	ok "busybox contains no networking applets, has blkid/setuidgid/mdev"
else
	warn "busybox .config not found; skipped applet audit"
fi

# ---------------------------------------------------------------------------
# 3. GUARDRAIL 3 - no display server on the image
# ---------------------------------------------------------------------------
echo "--- guardrail: no X11 / Wayland / display manager -------------------------"
forbidden=0
for pat in 'libX11.so*' 'libxcb.so*' 'libwayland-client.so*' 'libwayland-server.so*'; do
	while IFS= read -r hit; do
		fail "display-server library on the image: ${hit#$TARGET_DIR}"
		forbidden=1
	done < <(find "$TARGET_DIR/usr/lib" "$TARGET_DIR/lib" -maxdepth 2 -name "$pat" 2>/dev/null)
done
for bin in Xorg X weston sway gdm sddm lightdm xinit startx; do
	if [ -e "$TARGET_DIR/usr/bin/$bin" ] || [ -e "$TARGET_DIR/usr/sbin/$bin" ]; then
		fail "display server/manager on the image: $bin"
		forbidden=1
	fi
done
[ "$forbidden" -eq 0 ] && ok "no X11, Wayland or display manager present"

# ---------------------------------------------------------------------------
# 4. No setuid/setgid binaries anywhere on the image
#
# The kiosk deliberately has no way to escalate: shutdown goes through an exit
# code, not a setuid helper. If something introduces one, that assumption is
# broken and the build should stop.
# ---------------------------------------------------------------------------
echo "--- guardrail: no setuid/setgid binaries ----------------------------------"
suid_found=0
while IFS= read -r f; do
	fail "setuid/setgid file: ${f#$TARGET_DIR} ($(stat -c '%A %U:%G' "$f"))"
	suid_found=1
done < <(find "$TARGET_DIR" -type f -perm /6000 2>/dev/null)
[ "$suid_found" -eq 0 ] && ok "no setuid or setgid files on the image"

# ---------------------------------------------------------------------------
# 5. Dynamic-linking audit (the "missing shared library / RPATH" check)
#
# This is the host-side half of what scripts/test_in_qemu.sh confirms at
# runtime: every DT_NEEDED of every ELF on the image resolves to a library
# that is actually on the image, and no RUNPATH points into the build host.
# ---------------------------------------------------------------------------
echo "--- audit: shared library resolution --------------------------------------"

READELF="readelf"
for cand in "${HOST_DIR:-/nonexistent}"/bin/*-readelf; do
	[ -x "$cand" ] && READELF="$cand" && break
done
if ! command -v "$READELF" >/dev/null 2>&1; then
	warn "no readelf available; skipped linking audit"
else
	# Every shared object present on the target, by basename.
	avail_file="$(mktemp)"; trap 'rm -f "$avail_file"' EXIT
	find "$TARGET_DIR/lib" "$TARGET_DIR/usr/lib" -name '*.so*' -printf '%f\n' 2>/dev/null \
		| sort -u > "$avail_file"

	missing=0
	while IFS= read -r elf; do
		file "$elf" 2>/dev/null | grep -q 'ELF .* \(executable\|shared object\)' || continue

		while IFS= read -r lib; do
			grep -qxF "$lib" "$avail_file" || {
				fail "${elf#$TARGET_DIR} needs $lib, which is not on the image"
				missing=1
			}
		done < <("$READELF" -d "$elf" 2>/dev/null \
			| sed -n 's/.*(NEEDED).*Shared library: \[\(.*\)\].*/\1/p')

		while IFS= read -r rpath; do
			case "$rpath" in
			*"${HOST_DIR:-@@nope@@}"*|*/output/host/*|*"$TARGET_DIR"*)
				fail "${elf#$TARGET_DIR} has a build-host RUNPATH: $rpath"
				missing=1
				;;
			esac
		done < <("$READELF" -d "$elf" 2>/dev/null \
			| sed -n 's/.*(R\(UN\)\?PATH).*\[\(.*\)\].*/\2/p')
	done < <(find "$TARGET_DIR/bin" "$TARGET_DIR/sbin" "$TARGET_DIR/usr/bin" \
	              "$TARGET_DIR/usr/sbin" "$TARGET_DIR/usr/lib" \
	              -type f 2>/dev/null)

	[ "$missing" -eq 0 ] && ok "every DT_NEEDED resolves on-image; no host RUNPATHs"
fi

# ---------------------------------------------------------------------------
# 6. The signer itself
# ---------------------------------------------------------------------------
echo "--- audit: signer binary --------------------------------------------------"
SIGNER="$TARGET_DIR/usr/bin/btc_signer_gui"
if [ ! -x "$SIGNER" ]; then
	fail "/usr/bin/btc_signer_gui is missing from the image"
else
	if "$READELF" -d "$SIGNER" 2>/dev/null | grep -q 'libwallycore'; then
		fail "btc_signer_gui links libwallycore dynamically; it must be the static archive"
	else
		ok "btc_signer_gui links libwally-core statically"
	fi
	# Qt platform plugin must be present or the kiosk cannot start a screen.
	if ! find "$TARGET_DIR/usr/lib" \( -name 'libqlinuxfb.so' -o -name 'libqeglfs.so' \) 2>/dev/null | grep -q .; then
		fail "no Qt platform plugin (linuxfb/eglfs) found on the image"
	else
		ok "Qt platform plugin present: $(find "$TARGET_DIR/usr/lib" \( -name 'libqlinuxfb.so' -o -name 'libqeglfs.so' \) -printf '%f ' 2>/dev/null)"
	fi
	if ! find "$TARGET_DIR/usr/share/fonts" -name '*.ttf' 2>/dev/null | grep -q .; then
		fail "no TrueType font on the image; the kiosk would render no text"
	else
		ok "fonts present in /usr/share/fonts"
	fi
fi

[ -x "$TARGET_DIR/usr/bin/signeros-ramwipe" ] \
	|| fail "/usr/bin/signeros-ramwipe missing (needed by the secure shutdown hook)"
[ -x "$TARGET_DIR/etc/init.d/S01mount-data" ] \
	|| fail "/etc/init.d/S01mount-data missing or not executable"
[ -x "$TARGET_DIR/etc/init.d/S99signer" ] \
	|| fail "/etc/init.d/S99signer missing or not executable"

# ---------------------------------------------------------------------------
echo "=========================================================================="
if [ "$failures" -gt 0 ]; then
	printf '%sSignerOS post-build: %d guardrail failure(s). Build stopped.%s\n' \
		"$RED" "$failures" "$RST" >&2
	exit 1
fi
printf '%sSignerOS post-build: all guardrails satisfied.%s\n' "$GRN" "$RST"
exit 0
