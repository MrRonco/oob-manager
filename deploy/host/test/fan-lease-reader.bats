#!/usr/bin/env bats
# Tests for deploy/host/fan-lease-reader.sh. Run: make host-test (bats 1.13.0 via npx).
# Nothing here touches fans: the reader only reads/writes files in a temp directory.

ID=0123456789abcdef0123456789abcdef
NOW=1800000100

setup() {
	# shellcheck source=../fan-lease-reader.sh
	source "$BATS_TEST_DIRNAME/../fan-lease-reader.sh"
	FAN_LEASE_DIR=$(mktemp -d)
	FAN_LEASE_SERVER=node-a
	FAN_LEASE_SAFE_MIN=30
	FAN_LEASE_NOW=$NOW
	GOLDEN="$BATS_TEST_DIRNAME/../../../internal/fan/hostlease/testdata/golden.lease"
}

teardown() {
	rm -rf "$FAN_LEASE_DIR"
}

lease() { # lease <pct> <issued> <expires> [extra line]
	{
		printf 'version=1\nserver=node-a\nlease_id=%s\npct=%s\nissued_at=%s\nexpires_at=%s\n' "$ID" "$1" "$2" "$3"
		[ $# -ge 4 ] && printf '%s\n' "$4"
	} >"$FAN_LEASE_DIR/node-a.lease"
	return 0
}

@test "the app's golden lease file is accepted" {
	cp "$GOLDEN" "$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = ok ]
	[ "$FAN_LEASE_ID" = "$ID" ]
	[ "$FAN_LEASE_FLOOR" = 55 ]
}

@test "no lease file is state none" {
	fan_lease_read
	[ "$FAN_LEASE_STATE" = none ]
	[ -z "$FAN_LEASE_FLOOR" ]
}

@test "valid lease raises the curve" {
	lease 55 1800000000 1800001800
	fan_lease_apply 35
	[ "$FAN_LEASE_TARGET" = 55 ]
	[ "$FAN_LEASE_OWNER" = lease ]
}

@test "a lease never lowers the curve" {
	lease 55 1800000000 1800001800
	fan_lease_apply 70
	[ "$FAN_LEASE_TARGET" = 70 ]
	[ "$FAN_LEASE_OWNER" = curve ]
	[ "$FAN_LEASE_STATE" = ok ]
}

@test "a floor below the host's safe minimum is clamped up" {
	lease 5 1800000000 1800001800
	fan_lease_apply 25
	[ "$FAN_LEASE_TARGET" = 30 ]
	FAN_LEASE_SAFE_MIN=40
	fan_lease_apply 25
	[ "$FAN_LEASE_TARGET" = 40 ]
}

@test "a non-numeric curve (AUTO) passes through untouched" {
	lease 55 1800000000 1800001800
	fan_lease_apply AUTO
	[ "$FAN_LEASE_TARGET" = AUTO ]
	[ "$FAN_LEASE_OWNER" = curve ]
}

@test "expired lease is ignored" {
	lease 55 1800000000 1800000100
	fan_lease_apply 35
	[ "$FAN_LEASE_STATE" = expired ]
	[ "$FAN_LEASE_TARGET" = 35 ]
}

@test "lease longer than the maximum is invalid" {
	lease 55 1800000000 1800007201
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
	FAN_LEASE_MAX_SECS=10000
	fan_lease_read
	[ "$FAN_LEASE_STATE" = ok ]
}

@test "lease issued in the future is invalid" {
	lease 55 1800000200 1800001800
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
}

@test "oversized lease file is invalid" {
	lease 55 1800000000 1800001800
	head -c 600 /dev/zero | tr '\0' 'a' >>"$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
}

@test "garbage and hostile content is invalid" {
	local bad=(
		"pct=55; rm -rf /"
		"unknown=1"
		"pct=60"
		"PCT=55"
		"pct = 55"
		""
		"x"
	)
	for extra in "${bad[@]}"; do
		lease 55 1800000000 1800001800 "$extra"
		fan_lease_read
		[ "$FAN_LEASE_STATE" = invalid ] || { echo "accepted extra line: '$extra'"; return 1; }
	done
	for args in "101 1800000000 1800001800" "-5 1800000000 1800001800" "55 soon 1800001800" \
		"55 1800001800 1800000000" "1e2 1800000000 1800001800" "0055 1800000000 1800001800"; do
		# shellcheck disable=SC2086
		lease $args
		fan_lease_read
		[ "$FAN_LEASE_STATE" = invalid ] || { echo "accepted: $args"; return 1; }
	done
	printf 'version=1\nserver=node-a\x00\nlease_id=%s\npct=55\nissued_at=1800000000\nexpires_at=1800001800\n' "$ID" \
		>"$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
	printf 'version=1\r\nserver=node-a\r\n' >"$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
	: >"$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
}

@test "lease for another server, wrong version or short id is invalid" {
	sed 's/server=node-a/server=node-b/' "$GOLDEN" >"$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
	sed 's/version=1/version=2/' "$GOLDEN" >"$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
	sed 's/lease_id=0123/lease_id=/' "$GOLDEN" >"$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
	FAN_LEASE_SERVER='../x'
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
}

@test "duplicate keys are invalid" {
	lease 55 1800000000 1800001800 "pct=99"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
}

@test "symlinked lease file is invalid even when its target is valid" {
	local target
	target=$(mktemp)
	cp "$GOLDEN" "$target"
	ln -s "$target" "$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
	rm -f "$target"
}

@test "a directory in place of the lease is invalid" {
	mkdir "$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
}

@test "owner uid check (guard)" {
	cp "$GOLDEN" "$FAN_LEASE_DIR/node-a.lease"
	FAN_LEASE_OWNER_UID=$(id -u)
	fan_lease_read
	[ "$FAN_LEASE_STATE" = ok ]
	FAN_LEASE_OWNER_UID=$(($(id -u) + 1))
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
}

@test "ack after applying a lease names the lease" {
	lease 55 1800000000 1800001800
	fan_lease_apply 35
	fan_lease_ack "$FAN_LEASE_TARGET"
	run cat "$FAN_LEASE_DIR/node-a.ack"
	[ "$output" = "$(printf 'version=1\nserver=node-a\nlease_id=%s\nowner=lease\napplied_pct=55\nreported_at=%s\nreason=ok' "$ID" "$NOW")" ]
	[ -z "$(find "$FAN_LEASE_DIR" -name '.node-a.ack.*')" ]
}

@test "ack without a lease reports the curve" {
	fan_lease_apply 35
	fan_lease_ack 35
	grep -qx 'lease_id=none' "$FAN_LEASE_DIR/node-a.ack"
	grep -qx 'owner=curve' "$FAN_LEASE_DIR/node-a.ack"
	grep -qx 'reason=none' "$FAN_LEASE_DIR/node-a.ack"
}

@test "ack for an invalid lease says so" {
	lease 55 1800000000 1800001800 "bogus=1"
	fan_lease_apply 35
	fan_lease_ack "$FAN_LEASE_TARGET"
	grep -qx 'reason=invalid' "$FAN_LEASE_DIR/node-a.ack"
	grep -qx 'lease_id=none' "$FAN_LEASE_DIR/node-a.ack"
}

@test "guard ack hands the fans to the BMC" {
	lease 55 1800000000 1800001800
	fan_lease_read
	fan_lease_ack_guard
	grep -qx 'owner=guard' "$FAN_LEASE_DIR/node-a.ack"
	grep -qx 'applied_pct=auto' "$FAN_LEASE_DIR/node-a.ack"
	grep -qx 'lease_id=none' "$FAN_LEASE_DIR/node-a.ack"
}

@test "ack replaces a planted symlink instead of writing through it" {
	local victim
	victim=$(mktemp)
	echo "precious" >"$victim"
	ln -s "$victim" "$FAN_LEASE_DIR/node-a.ack"
	fan_lease_apply 35
	fan_lease_ack 35
	[ "$(cat "$victim")" = precious ]
	[ ! -L "$FAN_LEASE_DIR/node-a.ack" ]
	rm -f "$victim"
}

@test "race: readers see either lease, never a torn file" {
	local i a b
	a=$(printf 'version=1\nserver=node-a\nlease_id=%s\npct=40\nissued_at=1800000000\nexpires_at=1800001800\n' "$ID")
	b=$(printf 'version=1\nserver=node-a\nlease_id=%s\npct=60\nissued_at=1800000000\nexpires_at=1800001800\n' "$ID")
	printf '%s\n' "$a" >"$FAN_LEASE_DIR/node-a.lease"
	(
		for i in $(seq 1 300); do
			printf '%s\n' "$a" >"$FAN_LEASE_DIR/.w" && mv -f "$FAN_LEASE_DIR/.w" "$FAN_LEASE_DIR/node-a.lease"
			printf '%s\n' "$b" >"$FAN_LEASE_DIR/.w" && mv -f "$FAN_LEASE_DIR/.w" "$FAN_LEASE_DIR/node-a.lease"
		done
	) &
	local writer=$!
	for i in $(seq 1 150); do
		fan_lease_read
		[ "$FAN_LEASE_STATE" = ok ] || { kill "$writer"; echo "state $FAN_LEASE_STATE at $i"; return 1; }
		case "$FAN_LEASE_FLOOR" in 40 | 60) ;; *) kill "$writer"; echo "floor $FAN_LEASE_FLOOR"; return 1 ;; esac
	done
	wait "$writer"
}

@test "race: a torn (non-atomic) write is rejected, not half-applied" {
	printf 'version=1\nserver=node-a\nlease_id=%s\npct=9' "$ID" >"$FAN_LEASE_DIR/node-a.lease"
	fan_lease_read
	[ "$FAN_LEASE_STATE" = invalid ]
}
