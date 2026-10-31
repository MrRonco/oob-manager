# shellcheck shell=bash
# fan-lease-reader.sh — lease reader for a host fan-control script (oob-manager host-lease mode).
#
# Source this file from your fan script; it only defines functions and reads no input by
# itself. It treats the lease file as untrusted: strict format, size cap, no symlinks,
# expiry and a maximum duration enforced here, the floor clamped to this host's own safe
# minimum, and it can only RAISE the speed your curve computed, never lower it.
# See deploy/host/README.md for the file formats and the integration steps.
#
# Settings (set before calling; FAN_LEASE_DIR and FAN_LEASE_SERVER are required):
#   FAN_LEASE_DIR        directory the app writes <server>.lease into
#   FAN_LEASE_SERVER     this server's id in the app config ([a-z0-9][a-z0-9-]*)
#   FAN_LEASE_SAFE_MIN   lowest floor ever applied, percent           (default 30)
#   FAN_LEASE_MAX_SECS   longest lease honoured, seconds              (default 7200)
#   FAN_LEASE_MAX_BYTES  lease file size cap, bytes                   (default 512)
#   FAN_LEASE_OWNER_UID  if set, the lease file must be owned by this uid
#   FAN_LEASE_NOW        current unix time (tests only; default: date +%s)
#
# Functions:
#   fan_lease_read            sets FAN_LEASE_STATE (ok|none|expired|invalid), FAN_LEASE_ID, FAN_LEASE_FLOOR
#   fan_lease_apply <curve%>  calls fan_lease_read, sets FAN_LEASE_TARGET = max(curve, floor) and FAN_LEASE_OWNER
#   fan_lease_ack <applied%>  writes <server>.ack for the app (after the fans were set)
#   fan_lease_ack_guard       writes the ack when a thermal guard put the BMC in automatic mode

fan_lease__now() {
	if [ -n "${FAN_LEASE_NOW:-}" ]; then
		printf '%s\n' "$FAN_LEASE_NOW"
	else
		date +%s
	fi
}

fan_lease__owner_ok() {
	[ -z "${FAN_LEASE_OWNER_UID:-}" ] && return 0
	local uid
	uid=$(stat -c %u -- "$1" 2>/dev/null || stat -f %u -- "$1" 2>/dev/null) || return 1
	[ "$uid" = "$FAN_LEASE_OWNER_UID" ]
}

# fan_lease__parse <file>: prints "ok <id> <floor>", "expired <id>" or "invalid".
# Reads at most FAN_LEASE_MAX_BYTES+1 bytes; awk validates every line.
fan_lease__parse() {
	local max=${FAN_LEASE_MAX_BYTES:-512}
	# tr maps every byte outside the format's alphabet (NUL included) to "#", which no line accepts.
	head -c "$((max + 1))" -- "$1" 2>/dev/null | LC_ALL=C tr -c 'a-z0-9_=\n-' '#' | LC_ALL=C awk \
		-v max="$max" -v srv="$FAN_LEASE_SERVER" -v now="$(fan_lease__now)" \
		-v safe="${FAN_LEASE_SAFE_MIN:-30}" -v maxsecs="${FAN_LEASE_MAX_SECS:-7200}" '
	function num(v, digits) { return v ~ /^[0-9]+$/ && length(v) <= digits }
	{
		bytes += length($0) + 1
		if (++n > 16 || $0 !~ /^[a-z_]+=[0-9a-z-]+$/) { bad = 1; next }
		i = index($0, "="); k = substr($0, 1, i - 1); v = substr($0, i + 1)
		if (k in kv) bad = 1
		kv[k] = v
	}
	END {
		if (bad || n == 0 || bytes > max) { print "invalid"; exit }
		for (k in kv) if (k !~ /^(version|server|lease_id|pct|issued_at|expires_at)$/) { print "invalid"; exit }
		id = kv["lease_id"]; pct = kv["pct"]; is = kv["issued_at"]; ex = kv["expires_at"]
		if (kv["version"] != "1" || kv["server"] != srv || length(id) != 32 || id !~ /^[0-9a-f]+$/ ||
		    !num(pct, 3) || pct + 0 > 100 || !num(is, 12) || !num(ex, 12) ||
		    ex + 0 <= is + 0 || ex - is > maxsecs + 0 || is + 0 > now + 60) { print "invalid"; exit }
		if (now + 0 >= ex + 0) { print "expired " id; exit }
		f = pct + 0; if (f < safe + 0) f = safe + 0; if (f > 100) f = 100
		print "ok " id " " f
	}'
}

fan_lease_read() {
	FAN_LEASE_STATE=none FAN_LEASE_ID="" FAN_LEASE_FLOOR=""
	local f="${FAN_LEASE_DIR:?}/${FAN_LEASE_SERVER:?}.lease" out state id floor
	case "$FAN_LEASE_SERVER" in
	*[!a-z0-9-]* | -*) FAN_LEASE_STATE=invalid; return 0 ;;
	esac
	if [ -L "$f" ]; then
		FAN_LEASE_STATE=invalid; return 0
	fi
	[ -e "$f" ] || return 0
	if [ ! -f "$f" ] || ! fan_lease__owner_ok "$f"; then
		FAN_LEASE_STATE=invalid; return 0
	fi
	out=$(fan_lease__parse "$f")
	read -r state id floor <<<"$out"
	case "$state" in
	ok) FAN_LEASE_STATE=ok FAN_LEASE_ID=$id FAN_LEASE_FLOOR=$floor ;;
	expired) FAN_LEASE_STATE=expired ;;
	*) FAN_LEASE_STATE=invalid ;;
	esac
	return 0
}

# fan_lease_apply <curve%>: never lowers the curve. A non-numeric curve (for example
# AUTO) is passed through untouched and the lease is not applied.
fan_lease_apply() {
	local curve=$1
	fan_lease_read
	FAN_LEASE_TARGET=$curve FAN_LEASE_OWNER=curve
	case "$curve" in
	'' | *[!0-9]*) return 0 ;;
	esac
	if [ "$FAN_LEASE_STATE" = ok ] && [ "$FAN_LEASE_FLOOR" -gt "$curve" ]; then
		FAN_LEASE_TARGET=$FAN_LEASE_FLOOR FAN_LEASE_OWNER=lease
	fi
	return 0
}

fan_lease__write_ack() {
	local owner=$1 applied=$2 reason=$3 id=none tmp dir=${FAN_LEASE_DIR:?}
	[ "${FAN_LEASE_STATE:-none}" = ok ] && [ "$owner" != guard ] && id=$FAN_LEASE_ID
	[ -d "$dir" ] && [ ! -L "$dir" ] || return 1
	tmp=$(mktemp "$dir/.${FAN_LEASE_SERVER:?}.ack.XXXXXX") || return 1
	if printf 'version=1\nserver=%s\nlease_id=%s\nowner=%s\napplied_pct=%s\nreported_at=%s\nreason=%s\n' \
		"$FAN_LEASE_SERVER" "$id" "$owner" "$applied" "$(fan_lease__now)" "$reason" >"$tmp" &&
		chmod 0644 "$tmp" && mv -f "$tmp" "$dir/$FAN_LEASE_SERVER.ack"; then
		return 0
	fi
	rm -f "$tmp"
	return 1
}

# fan_lease_ack <applied%>: call after setting the fans to FAN_LEASE_TARGET.
fan_lease_ack() {
	local applied=$1
	case "$applied" in
	'' | *[!0-9]*) applied=auto ;;
	esac
	fan_lease__write_ack "${FAN_LEASE_OWNER:-curve}" "$applied" "${FAN_LEASE_STATE:-none}"
}

# fan_lease_ack_guard: call when a thermal guard handed the fans to the BMC (AUTO).
fan_lease_ack_guard() {
	fan_lease__write_ack guard auto guard
}
