# /usr/lib/signeros/functions.sh
#
# Shared helpers for the SignerOS init scripts. POSIX sh (BusyBox ash) only.
# Sourced, never executed.

SIGNEROS_CONF=/etc/signeros.conf
SIGNEROS_PANEL=/dev/tty1

# Where the init scripts leave a warning for the kiosk to display. Written by
# root, world-readable, polled by the GUI once a second.
#
# This exists because SIGNEROS_PANEL stops being usable the moment Qt owns the
# framebuffer: a write to the VT after that paints raw console text over the
# running application instead of informing anyone. Anything discovered while the
# kiosk is up has to reach the operator through the kiosk.
SIGNEROS_WARN_FILE=/run/signeros-warning

# ---------------------------------------------------------------------------
# log <message...>
#
# Goes to /dev/console, which is the serial line in the self-test image and the
# panel on real hardware. Prefixed so scripts/test_in_qemu.sh can match on it.
#
# On stderr, deliberately. A shell function returns its value on stdout, so a
# log call inside one is captured by the surrounding $(...) and handed to the
# caller as data. That is not hypothetical: signeros-datawatch's find_data_dev
# logs when it sees two volumes with the same label, and every one of those
# lines used to be prepended to the device path it returned. mount_data was then
# asked to mount a two-line string, blkid reported no filesystem type, and the
# appliance refused to mount anything at all - silently, once per second, for as
# long as the second stick was plugged in. Logging must never share a channel
# with return values.
# ---------------------------------------------------------------------------
log() {
	echo "SIGNEROS: $*" >&2
}

# ---------------------------------------------------------------------------
# warn_user <message...>   raise the warning the kiosk shows in its status bar
# warn_user_clear          drop it
#
# Idempotent: the file is only rewritten when the text actually changes, so a
# condition that is re-detected on every poll is announced once rather than
# every second. Safe to call from inside a command substitution - nothing here
# writes to stdout.
# ---------------------------------------------------------------------------
warn_user() {
	_text="$*"
	[ "$(cat "$SIGNEROS_WARN_FILE" 2>/dev/null)" = "$_text" ] && return 0
	printf '%s\n' "$_text" > "$SIGNEROS_WARN_FILE" 2>/dev/null || return 0
	chmod 0644 "$SIGNEROS_WARN_FILE" 2>/dev/null
	log "WARNING: $_text"
	return 0
}

warn_user_clear() {
	[ -f "$SIGNEROS_WARN_FILE" ] || return 0
	rm -f "$SIGNEROS_WARN_FILE" 2>/dev/null
	return 0
}

# ---------------------------------------------------------------------------
# cmdline_get <key> [default]
#
# Reads signeros.<key>=<value> from /proc/cmdline. Values may not contain
# whitespace, which is fine for the labels, paths and enums we pass this way.
#
# One token per line, then an anchored match: no word-boundary escapes (a GNU
# sed extension BusyBox does not promise) and no chance of a partial token like
# "notsigneros.network=" matching.
# ---------------------------------------------------------------------------
cmdline_get() {
	_key="$1"
	_default="${2:-}"
	_val=$(tr ' ' '\n' < /proc/cmdline 2>/dev/null \
		| sed -n "s/^signeros\.${_key}=//p" | head -n1)
	if [ -n "$_val" ]; then
		echo "$_val"
	else
		echo "$_default"
	fi
}

# ---------------------------------------------------------------------------
# signeros_load_config
#
# /etc/signeros.conf first, then kernel command line overrides on top.
# Everything is exported: signer-session passes the environment to the kiosk.
# ---------------------------------------------------------------------------
signeros_load_config() {
	# Defaults, in case the config file is ever incomplete.
	NETWORK=mainnet
	DATA_LABEL=PSBT_DATA
	MOUNT_POINT=/mnt/data
	DATA_DEV=
	DATA_WAIT_SECS=8
	QPA=auto
	FONT_DIR=/usr/share/fonts/dejavu
	WRITE_FINAL_TX=0

	# shellcheck source=/dev/null
	[ -r "$SIGNEROS_CONF" ] && . "$SIGNEROS_CONF"

	NETWORK=$(cmdline_get network "$NETWORK")
	DATA_LABEL=$(cmdline_get data_label "$DATA_LABEL")
	MOUNT_POINT=$(cmdline_get mount_point "$MOUNT_POINT")
	DATA_DEV=$(cmdline_get data_dev "$DATA_DEV")
	DATA_WAIT_SECS=$(cmdline_get data_wait_secs "$DATA_WAIT_SECS")
	QPA=$(cmdline_get qpa "$QPA")
	WRITE_FINAL_TX=$(cmdline_get write_final_tx "$WRITE_FINAL_TX")

	SELFTEST=$(cmdline_get selftest 0)
	MNEMONIC_FILE=$(cmdline_get mnemonic_file "")

	export NETWORK DATA_LABEL MOUNT_POINT DATA_DEV DATA_WAIT_SECS QPA \
	       FONT_DIR WRITE_FINAL_TX SELFTEST MNEMONIC_FILE
}

# ---------------------------------------------------------------------------
# panel_clear / panel_msg <lines...>
#
# Writes directly to the framebuffer console. This is the only way to talk to
# the user before (or instead of) the GUI - there is no display server to
# start, and a mount failure has to be visible on a machine with no network,
# no serial cable and no shell.
#
# Guarded: on a machine where tty1 does not exist, these must not abort the
# init script.
# ---------------------------------------------------------------------------
panel_clear() {
	[ -w "$SIGNEROS_PANEL" ] && printf '\033[2J\033[H' > "$SIGNEROS_PANEL" 2>/dev/null
	return 0
}

panel_msg() {
	[ -w "$SIGNEROS_PANEL" ] || return 0
	for _line in "$@"; do
		printf '%s\r\n' "$_line" > "$SIGNEROS_PANEL" 2>/dev/null
	done
	return 0
}

# ---------------------------------------------------------------------------
# panel_error <title> <detail...>
#
# Big, unmissable, and it stays on screen: a signer that silently fails to find
# its data partition is worse than one that says so.
# ---------------------------------------------------------------------------
panel_error() {
	_title="$1"; shift
	panel_clear
	panel_msg \
		"" \
		"  ############################################################" \
		"  ##                                                        ##" \
		"  ##   SignerOS                                             ##" \
		"  ##   $_title" \
		"  ##                                                        ##" \
		"  ############################################################" \
		""
	for _line in "$@"; do
		panel_msg "    $_line"
	done
	panel_msg ""
	log "ERROR: $_title"
	return 0
}
