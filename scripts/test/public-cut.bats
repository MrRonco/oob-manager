#!/usr/bin/env bats
# Tests for scripts/public-cut.sh. Run: make cut-test (bats 1.13.0 via npx).
# Everything runs in a temp git repository with stub scanners on a sandboxed PATH: no
# real tag, no Docker, no network. The identifier list here is synthetic.
# Assertions with [[ ]] end in "|| false": bash 3.2 (macOS) does not apply errexit to [[ ]].
# Inline suppression markers are built with printf (GL_ALLOW below), so this file does
# not itself carry one into a real cut.

bats_require_minimum_version 1.5.0

GL_ALLOW=$(printf 'gitleaks%sallow' ':')

setup() {
	SCRIPT="$BATS_TEST_DIRNAME/../public-cut.sh"
	TMP=$(cd "$(mktemp -d)" && pwd -P)
	REPO="$TMP/repo"
	OUT="$TMP/out"
	IDS="$TMP/private/ids.txt"
	export TMPDIR="$TMP/tmpdir"
	mkdir -p "$REPO/internal/repopolicy" "$TMP/private" "$TMPDIR"
	printf '# synthetic identifiers, one ERE per line\n\nzorbulon\nqx-[0-9]+-lab\n' >"$IDS"

	cd "$REPO" || return 1
	git init -q .
	git config user.email t@t.example
	git config user.name test
	git config commit.gpgsign false
	git config tag.gpgsign false
	printf 'hello\n' >README.md
	printf 'package repopolicy\n' >internal/repopolicy/doc.go
	commit_and_tag v1.0.0 annotated

	make_stubs
	make_sandbox
}

teardown() {
	chmod -R u+rwX "$TMP" 2>/dev/null || true
	rm -rf "$TMP"
}

commit_and_tag() { # commit_and_tag <tag> [annotated]
	git add -A
	git commit -q -m "commit for $1"
	if [ "${2:-}" = annotated ]; then git tag -a "$1" -m "$1"; else git tag "$1"; fi
}

# tag_tree <tag> <mktree input>: commit a hand-made tree on HEAD (for entries git add refuses).
tag_tree() {
	local tree commit
	tree=$(printf '%b' "$2" | git mktree)
	commit=$(git commit-tree "$tree" -p HEAD -m "crafted $1")
	git update-ref "refs/heads/$(git rev-parse --abbrev-ref HEAD)" "$commit"
	git tag "$1" "$commit"
}

# The stubs answer --version like the pinned releases, print what the STUB_* variables
# say, and log their arguments to $STUB_LOG when it is set.
make_stubs() {
	STUBS="$TMP/stubs"
	mkdir -p "$STUBS"
	cat >"$STUBS/gitleaks" <<'EOF'
#!/bin/sh
[ "$1" = version ] && { echo "${STUB_GITLEAKS_VERSION:-8.30.1}"; exit 0; }
[ -n "${STUB_LOG:-}" ] && echo "gitleaks $*" >>"$STUB_LOG"
[ -n "${STUB_GITLEAKS_CHMOD:-}" ] && chmod 755 README.md
# STUB_PS: TERM the topmost ancestor running public-cut.sh (the script itself, not a subshell)
if [ -n "${STUB_PS:-}" ]; then
	p=$PPID top=""
	while [ "$p" -gt 1 ] && "$STUB_PS" -o args= -p "$p" | grep -q 'public-cut[.]sh'; do
		top=$p p=$("$STUB_PS" -o ppid= -p "$p" | tr -d ' ')
	done
	[ -n "$top" ] && kill -TERM "$top"
fi
case " $* " in
*" --ignore-gitleaks-allow "*)
	if [ -n "${STUB_STRICT_UNLESS_IGNOREFILE:-}" ]; then
		[ ! -e .gitleaksignore ] || { echo "strict pass saw .gitleaksignore" >&2; exit 2; }
		printf '%b\n' "$STUB_STRICT_UNLESS_IGNOREFILE"; exit 99
	fi
	[ -n "${STUB_GITLEAKS_STRICT:-}" ] && { printf '%b\n' "$STUB_GITLEAKS_STRICT"; exit 99; }
	exit 0 ;;
esac
[ -n "${STUB_GITLEAKS_OUT:-}" ] && printf '%b\n' "$STUB_GITLEAKS_OUT"
exit "${STUB_GITLEAKS_RC:-0}"
EOF
	cat >"$STUBS/trufflehog" <<'EOF'
#!/bin/sh
[ "$1" = --version ] && { echo "trufflehog 3.99.2" >&2; exit 0; }
[ -n "${STUB_LOG:-}" ] && echo "trufflehog $*" >>"$STUB_LOG"
exit 0
EOF
	cat >"$STUBS/go" <<'EOF'
#!/bin/sh
for f in "$TMPDIR"/public-cut.*/ids "$TMPDIR"/public-cut.*/*/ids; do [ -r "$f" ] && { echo "--- FAIL: LEAK identifier copy readable"; exit 1; }; done
if [ -n "${STUB_GO_EXPECT:-}" ] && ! grep -q "$STUB_GO_EXPECT" internal/repopolicy/doc.go; then
	echo "--- FAIL: TestPublicTreeHasNoNetworkDetails (wrong repopolicy copy)"; exit 1
fi
[ -n "${STUB_GO_FAIL:-}" ] && { printf '%b\n' "$STUB_GO_FAIL"; exit 1; }
[ -n "${STUB_GO_NOTREE:-}" ] && { echo ok; exit 0; }
echo "--- PASS: TestPublicTreeHasNoNetworkDetails (0.01s)"
echo ok
EOF
	# exiftool: -p prints one line per input path with every tag = STUB_EXIF_VALUE ("-" is
	# absent); the -G1 dump prints STUB_EXIF_DUMP as each file's Comment; strip succeeds.
	cat >"$STUBS/exiftool" <<'EOF'
#!/bin/sh
[ "$1" = -ver ] && { echo "${STUB_EXIF_VERSION:-13.59}"; exit 0; }
fmt="" dump="" quiet=""
while [ $# -gt 0 ]; do
	case $1 in -p) fmt=$2; shift ;; -G1) dump=1 ;; -q) quiet=1 ;; esac
	shift
done
if [ -n "$fmt" ]; then
	n=$(printf "%s" "$fmt" | awk -F"\t" "{print NF}")
	exec awk -v n="$n" -v v="${STUB_EXIF_VALUE:--}" '{ l = $0; for (i = 2; i <= n; i++) l = l "\t" v; print l }'
fi
# like exiftool: no "======== file" headers under -q; STUB_EXIF_DUMP_FILE limits the comment
[ -n "$dump" ] && exec awk -v c="${STUB_EXIF_DUMP:-plain}" -v q="$quiet" -v only="${STUB_EXIF_DUMP_FILE:-}" '
	{ if (q == "") print "======== " $0; v = (only == "" || $0 == only) ? c : "plain"
	  print "[PNG]           Comment                         : " v }'
exit 0
EOF
	chmod +x "$STUBS"/*
}

# A PATH with only the system tools the script needs, so a missing scanner is really missing.
make_sandbox() {
	SANDBOX="$TMP/sandbox"
	mkdir -p "$SANDBOX"
	local t p
	for t in bash env git tar find grep sed awk sort cut wc tr xargs ls head tail cmp mktemp \
		mkdir rm mv cp chmod stat locale comm cat dirname basename id sha256sum shasum perl uname; do
		p=$(command -v "$t" 2>/dev/null) && ln -s "$p" "$SANDBOX/$t"
	done
	return 0
}

# grep_fails_on <flag>: put a grep first on PATH that exits 2 (an I/O error) whenever it is
# called with that exact argument, after doing the real work.
grep_fails_on() {
	mkdir -p "$TMP/badgrep"
	cat >"$TMP/badgrep/grep" <<EOF
#!/bin/sh
for a in "\$@"; do [ "\$a" = "$1" ] && { "$(command -v grep)" "\$@"; exit 2; }; done
exec "$(command -v grep)" "\$@"
EOF
	chmod +x "$TMP/badgrep/grep"
	PREPATH="$TMP/badgrep:"
}

cut_local() { # cut_local <args...>: run the script with the stubs and the sandbox only
	run env PATH="${PREPATH:-}$STUBS:$SANDBOX" "$SCRIPT" "$@"
}

@test "no arguments is a usage error" {
	cut_local
	[ "$status" -eq 2 ]
	[[ $output == *"expected <tag> and <outdir>"* ]] || false
}

@test "--help prints the usage and exits 0" {
	cut_local --help
	[ "$status" -eq 0 ]
	[[ $output == *"--identifiers"* ]] || false
}

@test "missing --identifiers is refused" {
	cut_local v1.0.0 "$OUT" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"--identifiers <file> is required"* ]] || false
}

@test "unknown option and bad --scanners value are refused" {
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --push
	[ "$status" -eq 2 ]
	[[ $output == *"unknown option: --push"* ]] || false
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=podman
	[ "$status" -eq 2 ]
	[[ $output == *"--scanners must be docker or local"* ]] || false
}

@test "a tag that does not exist is refused" {
	cut_local v9.9.9 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"no such tag: v9.9.9"* ]] || false
	[ ! -e "$OUT" ]
}

@test "a tag name that looks like an option or a range is refused" {
	cut_local -- "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 2 ]
	cut_local 'v1..v2' "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"not a plain tag name"* ]] || false
}

@test "a tag not reachable from HEAD is refused" {
	git checkout -q -b side
	printf 'side\n' >side.txt
	commit_and_tag v-side
	git checkout -q -
	cut_local v-side "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"not reachable from HEAD"* ]] || false
}

@test "an identifiers file inside the repository is refused" {
	cp "$IDS" "$REPO/ids.txt"
	cut_local v1.0.0 "$OUT" --identifiers "$REPO/ids.txt" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"identifiers file is inside the repository"* ]] || false
	[ ! -e "$OUT" ]
}

@test "an identifiers file without patterns, or with an everything-pattern, is refused" {
	printf '# only a comment\n\n' >"$TMP/private/empty.txt"
	cut_local v1.0.0 "$OUT" --identifiers "$TMP/private/empty.txt" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"has no patterns"* ]] || false
	printf 'zorbulon\n.*\n' >"$TMP/private/all.txt"
	cut_local v1.0.0 "$OUT" --identifiers "$TMP/private/all.txt" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"pattern #2 matches an empty line"* ]] || false
}

@test "an existing non-empty outdir is refused and left alone" {
	mkdir -p "$OUT"
	printf 'keep\n' >"$OUT/keep.txt"
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"outdir exists and is not empty"* ]] || false
	[ "$(ls -A "$OUT")" = keep.txt ]
}

@test "an outdir inside the repository is refused" {
	cut_local v1.0.0 "$REPO/cut" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"outdir must be outside the repository"* ]] || false
}

@test "a clean tag passes, exports without .git and prints the manual next steps" {
	mkdir -p "$OUT" # an existing EMPTY outdir is fine
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 0 ]
	[ -f "$OUT/README.md" ]
	[ ! -e "$OUT/.git" ]
	[[ $output == *"All checks passed"* ]] || false
	[[ $output == *"git commit -s -m 'Initial public release'"* ]] || false
	[[ $output != *FAIL* ]] || false
	[ ! -e "$OUT/.git" ] # the script printed git init; it did not run it
}

@test "a lightweight tag works too" {
	git tag v1.0.0-lw
	cut_local v1.0.0-lw "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 0 ]
}

@test "a planted identifier is reported as file:line and pattern number, never as text" {
	printf 'first line\ncontact the Zorbulon box\nthird\nalso qx-42-lab here\n' >notes.txt
	mkdir -p docs/zorbulon-photos && printf 'by zorbulon\n' >docs/zorbulon-photos/a.txt
	commit_and_tag v1.1.0
	cut_local v1.1.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"pattern #1: notes.txt:2"* ]] || false
	[[ $output == *"pattern #2: notes.txt:4"* ]] || false
	[[ $output == *"pattern #1: 2 file or directory name(s) match (paths withheld"* ]] || false
	[[ $output == *"<path withheld: its name matches an identifier>:1"* ]] || false
	[[ $output == *"private identifiers (2 patterns)"*FAIL* ]] || false
	shopt -s nocasematch
	[[ $output != *zorbulon* ]] || false
	[[ $output != *qx-42-lab* ]] || false
}

@test "a file over 5 MiB fails the cut" {
	dd if=/dev/zero of=blob.bin bs=1048576 count=6 2>/dev/null
	commit_and_tag v1.2.0
	cut_local v1.2.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"blob.bin (6291456 bytes)"* ]] || false
	[[ $output == *"no file over 5 MiB"*FAIL* ]] || false
}

@test "a missing scanner fails closed before anything is exported" {
	rm "$STUBS/gitleaks"
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 3 ]
	[[ $output == *"MISSING: gitleaks"* ]] || false
	[[ $output == *"github.com/gitleaks/gitleaks/releases/tag/v8.30.1"* ]] || false
	[ ! -e "$OUT" ]
}

@test "docker mode without docker fails closed" {
	cut_local v1.0.0 "$OUT" --identifiers "$IDS"
	[ "$status" -eq 3 ]
	[[ $output == *"MISSING: docker"* ]] || false
}

@test "a scanner that reports findings fails the cut" {
	STUB_GITLEAKS_RC=99 cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"gitleaks found leaks"* ]] || false
}

@test "a scanner that crashes fails the cut" {
	STUB_GITLEAKS_RC=2 cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"gitleaks did not complete (exit 2)"* ]] || false
}

@test "repopolicy that did not run its tree test fails the cut" {
	STUB_GO_NOTREE=1 cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"TestPublicTreeHasNoNetworkDetails did not run"* ]] || false
}

@test "image metadata naming a person fails, reported by tag name without the value" {
	printf 'not really a png\n' >shot.png
	commit_and_tag v1.3.0
	STUB_EXIF_VALUE="Jane Example" cut_local v1.3.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"shot.png: Artist, Author"* ]] || false
	[[ $output == *"re-run with --strip-metadata"* ]] || false
	[[ $output != *"Jane Example"* ]] || false
}

@test "an invalid identifier regex is refused without echoing the pattern" {
	printf 'zorb(ulon\n' >"$TMP/private/bad.txt"
	cut_local v1.0.0 "$OUT" --identifiers "$TMP/private/bad.txt" --scanners=local
	[ "$status" -eq 2 ]
	[[ $output == *"pattern #1 is not a valid extended regex"* ]] || false
	[[ $output != *zorb* ]] || false
}

# --- review fixes (M1-M4, L1-L9) -------------------------------------------------------

@test "M1: an anchored pattern matches a bare file or directory name" {
	printf '^exact-name$\n' >"$TMP/private/anchored.txt"
	mkdir -p docs/exact-name && printf 'x\n' >docs/exact-name/a.txt
	commit_and_tag v2.0.0
	cut_local v2.0.0 "$OUT" --identifiers "$TMP/private/anchored.txt" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"pattern #1: 1 file or directory name(s) match"* ]] || false
	[[ $output != *exact-name* ]] || false
}

@test "M2: a grep error in the content scan fails the check" {
	grep_fails_on -rlaEi
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"grep failed while scanning file contents (exit 2)"* ]] || false
}

@test "M2: a grep error in the name scan fails the check" {
	grep_fails_on -Ein
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"grep failed while scanning names (exit 2)"* ]] || false
}

@test "M3: a suppression missing from --suppressions-baseline fails, a listed one passes" {
	printf 'key = 1 # %s\n' "$GL_ALLOW" >conf.toml
	commit_and_tag v2.2.0
	printf '# reviewed\n' >"$TMP/private/baseline.txt"
	cut_local v2.2.0 "$OUT" --identifiers "$IDS" --scanners=local --suppressions-baseline "$TMP/private/baseline.txt"
	[ "$status" -eq 1 ]
	[[ $output == *"not in the baseline:"* ]] || false
	[[ $output == *"in-tree suppressions (1)"*FAIL* ]] || false
	printf '%s\n' "$output" | sed -n 's/^  key: //p' >>"$TMP/private/baseline.txt"
	cut_local v2.2.0 "$TMP/out2" --identifiers "$IDS" --scanners=local --suppressions-baseline "$TMP/private/baseline.txt"
	[ "$status" -eq 0 ]
	[[ $output == *"in-tree suppressions (1)"*PASS* ]] || false
}

@test "M3: a suppressions baseline inside the repository is refused" {
	printf '# x\n' >baseline.txt
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local --suppressions-baseline "$REPO/baseline.txt"
	[ "$status" -eq 2 ]
	[[ $output == *"suppressions baseline is inside the repository"* ]] || false
}

@test "M3: repopolicy runs HEAD's internal/repopolicy against the tag's tree" {
	printf 'package repopolicy // newer at HEAD\n' >internal/repopolicy/doc.go
	git commit -q -am "newer policy"
	STUB_GO_EXPECT="newer at HEAD" cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 0 ]
	[ "$(cat "$OUT/internal/repopolicy/doc.go")" = "package repopolicy" ]
}

@test "M4: a symlink in the tag aborts before anything is exported" {
	ln -s /etc/passwd link
	commit_and_tag v3.0.0
	cut_local v3.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"unsafe tree entry (symlink): link"* ]] || false
	[ ! -e "$OUT" ]
}

@test "M4: a submodule in the tag aborts" {
	git update-index --add --cacheinfo "160000,$(git rev-parse HEAD),sub"
	git commit -q -m submodule
	git tag v3.1.0
	cut_local v3.1.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"unsafe tree entry (submodule): sub"* ]] || false
}

@test "M4: a newline or CR in a path aborts" {
	printf 'x\n' >"$(printf 'bad\nname')"
	commit_and_tag v3.2.0
	cut_local v3.2.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"unsafe tree entry (control character)"* ]] || false
	[ ! -e "$OUT" ]
}

@test "M4: a .git or .. path component aborts" {
	blob=$(printf 'x\n' | git hash-object -w --stdin)
	tag_tree v3.3.0 "100644 blob $blob\t.GIT\n"
	cut_local v3.3.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"unsafe tree entry (.git or .. component): .GIT"* ]] || false
	tag_tree v3.3.1 "100644 blob $blob\t..\n"
	cut_local v3.3.1 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"unsafe tree entry (.git or .. component): .."* ]] || false
	[ ! -e "$OUT" ]
}

@test "L2: --no-verify runs trufflehog without verification" {
	STUB_LOG="$TMP/log" cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local --no-verify
	[ "$status" -eq 0 ]
	grep -q -- '--no-verification' "$TMP/log"
	grep -q -- '--results=unverified,unknown' "$TMP/log"
	STUB_LOG="$TMP/log2" cut_local v1.0.0 "$TMP/out2" --identifiers "$IDS" --scanners=local
	grep -q -- '--results=verified,unknown' "$TMP/log2"
	run ! grep -q -- '--no-verification' "$TMP/log2"
}

@test "L3: a PDF and a video are checked for metadata too" {
	printf '%%PDF-1.4\n' >doc.pdf
	printf 'x\n' >clip.webm
	commit_and_tag v4.0.0
	STUB_EXIF_VALUE="Jane Example" cut_local v4.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"doc.pdf: Artist"* ]] || false
	[[ $output == *"clip.webm: Artist"* ]] || false
}

@test "L3: an identifier inside image metadata text is found and redacted" {
	printf 'png\n' >shot.png
	commit_and_tag v4.1.0
	STUB_EXIF_DUMP="made by Zorbulon" cut_local v4.1.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"pattern #1: shot.png (in its metadata)"* ]] || false
	shopt -s nocasematch
	[[ $output != *zorbulon* ]] || false
}

@test "L4: local repopolicy runs while the identifier copy is unreadable" {
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 0 ]
	[[ $output != *LEAK* ]] || false
}

@test "L5: a scanner that changes a file mode fails the manifest check" {
	STUB_GITLEAKS_CHMOD=1 cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"scans left the tree unchanged"*FAIL* ]] || false
}

@test "L6: a local scanner version that differs from the pin fails unless --allow-unpinned" {
	STUB_GITLEAKS_VERSION=8.0.0 cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 3 ]
	[[ $output == *"gitleaks is 8.0.0, the pin is 8.30.1"* ]] || false
	[ ! -e "$OUT" ]
	STUB_GITLEAKS_VERSION=8.0.0 cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local --allow-unpinned
	[ "$status" -eq 0 ]
	[[ $output == *"WARNING: gitleaks is 8.0.0"* ]] || false
}

@test "L7: a BOM in the identifiers file is ignored; unmatched patterns are listed as info" {
	printf '\357\273\277zorbulon\nnever-there\n' >"$TMP/private/bom.txt"
	printf 'a zorbulon line\n' >notes.txt
	commit_and_tag v5.0.0
	cut_local v5.0.0 "$OUT" --identifiers "$TMP/private/bom.txt" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"pattern #1: notes.txt:1"* ]] || false
	[[ $output == *"info: patterns that matched nothing in the tree: #2"* ]] || false
}

@test "L8: a failed cut leaves CUT-FAILED with the summary; a passing one does not" {
	STUB_GITLEAKS_RC=99 cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"do not publish"* ]] || false
	grep -q 'gitleaks *FAIL' "$OUT/CUT-FAILED"
	grep -q 'do not publish' "$OUT/CUT-FAILED"
	cut_local v1.0.0 "$TMP/out2" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 0 ]
	[ ! -e "$TMP/out2/CUT-FAILED" ]
	[ -z "$(ls -A "$TMPDIR")" ] # the private work directory is gone
}

@test "L9: gitleaks findings are printed by the script, identifier paths withheld" {
	STUB_GITLEAKS_RC=99 STUB_GITLEAKS_OUT='generic-api-key\tdocs/zorbulon.txt\t3\ngeneric-api-key\tok.txt\t4' \
		cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"generic-api-key <path withheld: its name matches an identifier>:3"* ]] || false
	[[ $output == *"generic-api-key ok.txt:4"* ]] || false
	shopt -s nocasematch
	[[ $output != *zorbulon* ]] || false
}

@test "L9: repopolicy failure output withholds lines that match an identifier" {
	STUB_GO_FAIL='--- FAIL: TestX\n    x_test.go:3: host zorbulon seen\n    x_test.go:4: other' \
		cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"x_test.go:4: other"* ]] || false
	[[ $output == *"1 line(s) withheld: they match an identifier"* ]] || false
	shopt -s nocasematch
	[[ $output != *zorbulon* ]] || false
}

@test "L9: a comma in outdir is refused in docker mode (bind mounts cannot carry it)" {
	cut_local v1.0.0 "$TMP/a,b" --identifiers "$IDS"
	[ "$status" -eq 2 ]
	[[ $output == *"comma"* ]] || false
}

@test "an identifier in a binary file is reported with its line number" {
	printf '\377\376\000 the zorbulon box\n' >blob.dat
	commit_and_tag v6.0.0
	cut_local v6.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"pattern #1: blob.dat:1"* ]] || false
	[[ $output != *"Illegal byte sequence"* ]] || false
}

@test "an identifier in metadata text is attributed to the right one of several files" {
	printf 'png\n' >a.png
	printf 'png\n' >b.png
	commit_and_tag v6.1.0
	STUB_EXIF_DUMP="made by Zorbulon" STUB_EXIF_DUMP_FILE=./b.png \
		cut_local v6.1.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"pattern #1: b.png (in its metadata)"* ]] || false
	[[ $output != *"a.png (in its metadata)"* ]] || false
}

@test "M3/N1: in-tree suppressions are listed, and without a baseline they fail the cut" {
	printf 'line\nkey = 1 # %s\n' "$GL_ALLOW" >conf.toml
	printf 'fp\n' >.gitleaksignore
	commit_and_tag v2.1.0
	cut_local v2.1.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"  conf.toml:2 $GL_ALLOW"* ]] || false
	[[ $output == *"  key: $GL_ALLOW conf.toml "* ]] || false
	[[ $output == *"  key: file .gitleaksignore "* ]] || false
	[[ $output == *"in-tree suppressions (2)"*FAIL* ]] || false
	[[ $output == *"in-tree suppressions need review: pass --suppressions-baseline"* ]] || false
	[[ $output != *"All checks passed"* ]] || false
}

@test "M3/N1: gitleaks findings hidden in-tree fail unless the baseline covers them" {
	printf 'line\nkey = 1 # %s\n' "$GL_ALLOW" >conf.toml
	commit_and_tag v2.3.0
	printf '# nothing reviewed yet\n' >"$TMP/private/baseline.txt"
	STUB_GITLEAKS_STRICT='generic-api-key\tconf.toml\t2' cut_local v2.3.0 "$OUT" --identifiers "$IDS" \
		--scanners=local --suppressions-baseline "$TMP/private/baseline.txt"
	[ "$status" -eq 1 ]
	[[ $output == *"suppressed in-tree (review): generic-api-key conf.toml:2"* ]] || false
	[[ $output == *"not covered by the baseline"* ]] || false
	[[ $output == *"gitleaks"*FAIL* ]] || false
	printf '%s\n' "$output" | sed -n 's/^  key: //p' >>"$TMP/private/baseline.txt"
	STUB_GITLEAKS_STRICT='generic-api-key\tconf.toml\t2' cut_local v2.3.0 "$TMP/out2" --identifiers "$IDS" \
		--scanners=local --suppressions-baseline "$TMP/private/baseline.txt"
	[ "$status" -eq 0 ]
	[[ $output == *"suppressed in-tree (review): generic-api-key conf.toml:2"* ]] || false
}

@test "N1: a finding hidden by a baselined in-tree .gitleaksignore is covered; the strict pass never sees that file" {
	printf 'creds:\n  password: x\n' >a.yaml
	printf 'a.yaml:generic-api-key:2\n' >.gitleaksignore
	commit_and_tag v2.4.0
	printf '# reviewed\n' >"$TMP/private/baseline.txt"
	cut_local v2.4.0 "$OUT" --identifiers "$IDS" --scanners=local --suppressions-baseline "$TMP/private/baseline.txt"
	printf '%s\n' "$output" | sed -n 's/^  key: //p' >>"$TMP/private/baseline.txt"
	STUB_STRICT_UNLESS_IGNOREFILE='generic-api-key\ta.yaml\t2' cut_local v2.4.0 "$TMP/out2" --identifiers "$IDS" \
		--scanners=local --suppressions-baseline "$TMP/private/baseline.txt"
	[ "$status" -eq 0 ]
	[[ $output == *"suppressed in-tree (review): generic-api-key a.yaml:2"* ]] || false
}

@test "N2: CUT-FAILED is there from the moment outdir is created (a tar failure leaves it)" {
	real_tar=$(command -v tar)
	printf '#!/bin/sh\ncase " $* " in *" -x "*) exit 1 ;; esac\nexec %s "$@"\n' "$real_tar" >"$STUBS/tar"
	chmod +x "$STUBS/tar"
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -ne 0 ]
	[ -f "$OUT/CUT-FAILED" ]
	[ -z "$(ls -A "$TMPDIR")" ]
}

@test "N2: TERM during a scan leaves CUT-FAILED and removes the private work directory" {
	STUB_PS="$(command -v ps)" cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 143 ]
	[ -f "$OUT/CUT-FAILED" ]
	[ -z "$(ls -A "$TMPDIR")" ]
}

@test "N2: a tag that carries its own CUT-FAILED is refused" {
	printf 'x\n' >CUT-FAILED
	commit_and_tag v7.0.0
	cut_local v7.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"unsafe tree entry (reserved name): CUT-FAILED"* ]] || false
}

@test "N3: export-ignore or export-subst in the tag's .gitattributes aborts" {
	printf 'README.md export-ignore\n' >.gitattributes
	commit_and_tag v7.1.0
	cut_local v7.1.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 1 ]
	[[ $output == *"unsafe tree entry (export-ignore or export-subst): .gitattributes"* ]] || false
	[ ! -e "$OUT" ]
}

@test "N3: the local core.attributesFile cannot change the export" {
	printf 'README.md export-ignore\n' >"$TMP/attrs"
	git config core.attributesFile "$TMP/attrs"
	cut_local v1.0.0 "$OUT" --identifiers "$IDS" --scanners=local
	[ "$status" -eq 0 ]
	[ -f "$OUT/README.md" ]
}

@test "N4: docker mode downloads Go modules from the proxy with the checksum DB on, and tests offline" {
	cat >"$STUBS/docker" <<'STUB'
#!/bin/sh
[ "$1" = info ] && exit 0
echo "docker $*" >>"$STUB_LOG"
case " $* " in *" go test "*) echo "--- PASS: TestPublicTreeHasNoNetworkDetails (0.01s)" ;; esac
exit 0
STUB
	printf '#!/bin/sh\nexit 1\n' >"$STUBS/curl"
	chmod +x "$STUBS/docker" "$STUBS/curl"
	STUB_LOG="$TMP/dlog" cut_local v1.0.0 "$OUT" --identifiers "$IDS"
	[ "$status" -eq 0 ]
	grep ' go mod download' "$TMP/dlog" | grep -q -- '-e GOPROXY=https://proxy.golang.org '
	run ! grep -E 'GOSUMDB|GONOSUMDB|GOFLAGS=-insecure|proxy.golang.org,direct' "$TMP/dlog"
	grep ' go test ' "$TMP/dlog" | grep -q -- '--network=none'
	grep ' go test ' "$TMP/dlog" | grep -q -- '-e GOPROXY=off'
	grep -q "type=bind,src=$OUT,dst=/src,readonly" "$TMP/dlog"
}

@test "N5: a suppression key with a spaced path is parsed whole (redaction and round trip)" {
	mkdir -p "my dir" "x y"
	printf 'k = 1 # %s\n' "$GL_ALLOW" >"my dir/a b.toml"
	printf 'k = 2 # %s\n' "$GL_ALLOW" >"x y/the zorbulon.toml"
	commit_and_tag v7.2.0
	printf '# reviewed\n' >"$TMP/private/baseline.txt"
	cut_local v7.2.0 "$OUT" --identifiers "$IDS" --scanners=local --suppressions-baseline "$TMP/private/baseline.txt"
	[[ $output == *"  key: $GL_ALLOW my dir/a b.toml "* ]] || false
	[[ $output == *"  key: $GL_ALLOW <path withheld: its name matches an identifier> "* ]] || false
	shopt -s nocasematch
	[[ $output != *zorbulon* ]] || false
	shopt -u nocasematch
	sed -n 's/^  key: //p' <<<"$output" | grep -v withheld >>"$TMP/private/baseline.txt"
	cut_local v7.2.0 "$TMP/out2" --identifiers "$IDS" --scanners=local --suppressions-baseline "$TMP/private/baseline.txt"
	[[ $output == *"not in the baseline:"* ]] || false
	new=$(sed -n '/^not in the baseline:/,/^$/p' <<<"$output" | grep -c '^  key:')
	[ "$new" -eq 1 ] # only the withheld one; the spaced path matched its baseline line
}
