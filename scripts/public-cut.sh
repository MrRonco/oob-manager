#!/usr/bin/env bash
# public-cut.sh: export a release tag as a history-free tree and scan exactly that tree
# before it becomes the first commit of the public repository (plan 07 §4.6).
#
#   scripts/public-cut.sh <tag> <outdir> --identifiers <file> [--strip-metadata]
#       [--scanners=docker|local] [--suppressions-baseline <file>] [--no-verify]
#       [--allow-unpinned]
#
# Run it inside the repository. It first refuses a tag whose tree holds a symlink, a
# submodule, a ".", ".." or ".git" component, a control character in a path, a top-level
# CUT-FAILED, or export-ignore/export-subst attributes. It exports <tag> with git archive
# (local attribute files ignored) into <outdir> (new or empty, outside the repository) and
# checks that tree: .git/symlinks, files over 5 MiB, media metadata, the private
# identifiers, in-tree suppressions, repopolicy, gitleaks, trufflehog, and that the scans
# left every byte and mode alone. <outdir>/CUT-FAILED exists until every check passes. It
# never runs git init, commits or pushes.
#
# --identifiers: private extended regexes (one per line, case-insensitive; blanks, #
#   comments and a BOM ignored), outside the repository, never copied into it. Contents,
#   each path name on its own (so ^name$ works) and metadata text are searched; hits show
#   file:line and pattern number only. The private copy is removed on exit, INT and TERM
#   (SIGKILL can leave it in $TMPDIR).
# --suppressions-baseline: inline allow/ignore comments (gitleaks, trufflehog, repopolicy)
#   and scanner config/ignore files are listed as "key:" lines. Any suppression fails the
#   cut unless its key is in this reviewed file (outside the repository); so do findings
#   that only a second gitleaks pass, which ignores every in-tree suppression, reports.
# repopolicy: HEAD's internal/repopolicy runs on a copy of the export (cut from the tag's
#   commit so HEAD's tests suit it). Docker mode: pinned golang image, modules from
#   proxy.golang.org with sum.golang.org, tests offline, no identifier file mounted. Local
#   mode: `go` runs as you with the private copy chmod 000; your own file stays readable.
# --scanners=docker (default) uses the images pinned below; --scanners=local uses PATH,
#   with versions equal to the pins unless --allow-unpinned.
# trufflehog verifies candidates, which SENDS THEM TO THE PROVIDERS' APIs, and fails on
#   verified or unverifiable ones; --no-verify sends nothing and fails on any detection.
# --strip-metadata strips the flagged media (exiftool -all=, ICC kept) and checks again;
#   the cut then no longer matches the tag.
#
# Exit: 0 all passed; 1 a check failed or the tree is unsafe (do not publish); 2 invalid
# or unsafe input; 3 a required tool is missing or not the pinned one.
# shellcheck disable=SC2329 # the check_* functions are called through run_check
set -euo pipefail

# --- pins (CLAUDE.md rule 10: >= 14 days old when pinned; bump by hand) ---------------
readonly GITLEAKS_VERSION="8.30.1" # 2026-03-21, multi-arch index digest from ghcr.io
readonly GITLEAKS_IMAGE="ghcr.io/gitleaks/gitleaks:v${GITLEAKS_VERSION}@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f"
readonly TRUFFLEHOG_VERSION="3.99.2" # 2026-10-08, multi-arch index digest from Docker Hub
readonly TRUFFLEHOG_IMAGE="docker.io/trufflesecurity/trufflehog:${TRUFFLEHOG_VERSION}@sha256:47a84bc18a0d04a165498bbbd3bacfd84176661cbc91f8e0f85467f6a771e99a"
# ExifTool has no official image: the pure-Perl release (GitHub tag archive, SHA-256
# pinned) runs in the official perl image (tag built 2026-09-19).
readonly EXIFTOOL_VERSION="13.59" # 2026-05-27
readonly EXIFTOOL_URL="https://github.com/exiftool/exiftool/archive/refs/tags/${EXIFTOOL_VERSION}.tar.gz"
readonly EXIFTOOL_SHA256="87d3317882fdae9cb4dcfe57a96a378d0132ffc02c731315bf128b19ddcf7aac"
readonly PERL_IMAGE="docker.io/library/perl:5.45.2-slim-bookworm@sha256:3cbdaaaa93727fb8df67ca1519748874094749450f1aa2e4e332d2477a7f1ba5"
# The Dockerfile's build image: repopolicy runs with the toolchain the release builds with.
readonly GOLANG_IMAGE="golang:1.27.3@sha256:957861185dbf29d93668ace41e011d091c6e779953d47f0316ef2cc58e28fe2b"

readonly MAX_FILE_BYTES=$((5 * 1024 * 1024))
readonly MAX_LINES_SHOWN=10
readonly MEDIA_EXT="png jpg jpeg gif webp svg ico pdf tif tiff bmp avif heic mp4 mov webm"
# Metadata that names a person, place, device or host: any value fails.
readonly EXIF_ALWAYS="Artist Author Creator By-line OwnerName CameraOwnerName XPAuthor
  Copyright Rights LastModifiedBy Source Make Model LensModel SerialNumber
  InternalSerialNumber GPSLatitude GPSLongitude GPSAltitude HostComputer"
# Free-text metadata: fails only when the value looks like a host, user, path or address.
readonly EXIF_TEXT="Software CreatorTool Comment UserComment ImageDescription Description
  Title DocumentName"
readonly HOSTISH_RE='[a-z0-9-]+\.(local|lan|home|internal|home\.arpa)([^a-z0-9-]|$)|@|/users/|/home/|\\users\\|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+'
# Inline suppressions, spelled so that this file does not carry one itself.
MARKERS=("gitleaks"":allow" "trufflehog"":ignore" "repopolicy"":allow")
readonly SUPPRESS_RE='(gitleaks[:]allow|trufflehog[:]ignore|repopolicy[:]allow)'
readonly SUPPRESS_FILES=".gitleaks.toml .gitleaksignore .trufflehogignore"

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
TAG="" OUT="" IDS="" BASELINE="" STRIP=0 SCANNERS=docker NOVERIFY=0 ALLOW_UNPINNED=0
WORK="" PRIV="" REPO_TOP="" MAIN_TOP="" COMMIT=""
FAILED=0 STRIPPED=0 ID_COUNT=0 SUPP_COUNT=0 NEED_REVIEW=0
readonly REVIEW_MSG="in-tree suppressions need review: pass --suppressions-baseline <file> holding the reviewed key lines"
SHA_CMD=() STAT_CMD=() NAMES=() RESULTS=()

# --- small helpers ----------------------------------------------------------------------
die_usage() { printf 'public-cut: %s\n' "$1" >&2; printf 'Run with --help for usage.\n' >&2; exit 2; }
die_tool() { printf 'public-cut: %s\n' "$1" >&2; exit 3; }
have() { command -v "$1" >/dev/null 2>&1; }
abs_dir() { (cd "$1" && pwd -P); }
is_within() { case "$1/" in "$2"/*) return 0 ;; *) return 1 ;; esac; }
inside_repo() { is_within "$1" "$REPO_TOP" || is_within "$1" "$MAIN_TOP"; }
first_line() { awk 'NR == 1'; } # reads all input, so no SIGPIPE under pipefail
count_lines() { wc -l <"$1" | tr -d ' '; }
hash16() { "${SHA_CMD[@]}" | cut -c1-16; }
# line_hash <text>: the key hash of one line, trimmed (so re-indenting keeps the key).
line_hash() { printf '%s\n' "$1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' | awk '{ printf "%s", $0 }' | hash16; }

set_locale() {
	local l
	for l in C.UTF-8 en_US.UTF-8; do
		if have locale && [ "$(LC_ALL=$l locale charmap 2>/dev/null)" = UTF-8 ]; then
			export LC_ALL=$l
			return 0
		fi
	done
	export LC_ALL=C
}

cleanup() {
	[ -n "$WORK" ] || return 0
	chmod -R u+rwx "$WORK" 2>/dev/null || true
	rm -rf "$WORK"
}

hint() {
	local how
	case $1 in
	gitleaks) how="https://github.com/gitleaks/gitleaks/releases/tag/v${GITLEAKS_VERSION} (or --scanners=docker)" ;;
	trufflehog) how="https://github.com/trufflesecurity/trufflehog/releases/tag/v${TRUFFLEHOG_VERSION} (or --scanners=docker)" ;;
	exiftool) how="ExifTool ${EXIFTOOL_VERSION} from https://exiftool.org or your package manager (or --scanners=docker)" ;;
	docker) how="https://docs.docker.com/engine/install/ (or --scanners=local with the scanners on PATH)" ;;
	go) how="https://go.dev/dl/ (the version in go.mod; or --scanners=docker)" ;;
	curl) how="your package manager (docker mode downloads the pinned ExifTool release)" ;;
	*) how="your package manager" ;;
	esac
	printf 'MISSING: %-10s install: %s\n' "$1" "$how" >&2
}

# clean_patterns <in> <out>: drop a BOM, CRs, comments, blank lines and surrounding blanks.
clean_patterns() {
	local bom
	bom=$(printf '\357\273\277')
	(umask 077 && tr -d '\r' <"$1" | LC_ALL=C sed -e "1s/^${bom}//" -e 's/^[[:space:]]*//' \
		-e 's/[[:space:]]*$//' | grep -v -e '^#' -e '^$' >"$2") || true
}

# pattern_to <n>: write pattern n alone to $PRIV/p (never to argv or stdout).
pattern_to() { (umask 077 && sed -n "${1}p" "$PRIV/ids" >"$PRIV/p"); }
matches_any_identifier() { printf '%s\n' "$1" | grep -Eiq -f "$PRIV/ids"; }

shown_path() {
	if matches_any_identifier "$1"; then echo "<path withheld: its name matches an identifier>"; else echo "$1"; fi
}

# redact_lines <file>: print the file without lines that match an identifier.
redact_lines() {
	local n
	grep -Evi -f "$PRIV/ids" "$1" || true
	n=$(grep -Eci -f "$PRIV/ids" "$1") || true
	[ "${n:-0}" -eq 0 ] || echo "($n line(s) withheld: they match an identifier)"
}

# mnt <src> <dst> [ro]: a --mount value (validate_outdir refuses commas in our paths).
mnt() { printf 'type=bind,src=%s,dst=%s%s' "$1" "$2" "${3:+,readonly}"; }

docker_run() { # a locked-down, throwaway container
	docker run --rm -i --cap-drop=ALL --security-opt=no-new-privileges --read-only \
		--tmpfs /tmp:rw,nosuid,nodev,size=2g -e HOME=/tmp --user "$(id -u):$(id -g)" "$@"
}

# exiftool_dir: the verified, unpacked ExifTool release for docker mode (private, per run).
exiftool_dir() {
	local tgz="$WORK/cache/exiftool.tar.gz" got
	if [ ! -f "$tgz" ]; then
		(umask 077 && mkdir -p "$WORK/cache") || return 1
		curl -fsSL --proto '=https' --tlsv1.2 -o "$tgz" "$EXIFTOOL_URL" || return 1
	fi
	got=$("${SHA_CMD[@]}" "$tgz" | cut -d' ' -f1)
	[ "$got" = "$EXIFTOOL_SHA256" ] || { echo "ExifTool archive SHA-256 $got, want $EXIFTOOL_SHA256" >&2; return 1; }
	[ -d "$WORK/cache/exiftool-${EXIFTOOL_VERSION}" ] || tar -xzf "$tgz" -C "$WORK/cache" || return 1
	echo "$WORK/cache/exiftool-${EXIFTOOL_VERSION}"
}

run_exiftool() { # run_exiftool <ro|rw> <args...>: run in $OUT, paths relative to it
	local mode=$1 dir
	shift
	if [ "$SCANNERS" = local ]; then
		(cd "$OUT" && exiftool "$@")
		return
	fi
	dir=$(exiftool_dir) || return 1
	docker_run --network=none --mount "$(mnt "$dir" /opt/exiftool ro)" \
		--mount "$(mnt "$OUT" /src "$([ "$mode" = ro ] && echo ro)")" -w /src \
		"$PERL_IMAGE" perl /opt/exiftool/exiftool "$@"
}

# --- arguments and input validation --------------------------------------------------
parse_args() {
	local positional=() a
	while [ $# -gt 0 ]; do
		case $1 in --*=*) a=$1 && shift && set -- "${a%%=*}" "${a#*=}" ${1+"$@"} ;; esac # --opt=value
		case $1 in
		-h | --help) usage; exit 0 ;;
		--identifiers | --suppressions-baseline | --scanners)
			[ $# -ge 2 ] || die_usage "$1 needs a value"
			case $1 in --identifiers) IDS=$2 ;; --scanners) SCANNERS=$2 ;; *) BASELINE=$2 ;; esac
			shift ;;
		--strip-metadata) STRIP=1 ;;
		--no-verify) NOVERIFY=1 ;;
		--allow-unpinned) ALLOW_UNPINNED=1 ;;
		-*) die_usage "unknown option: $1" ;;
		*) positional+=("$1") ;;
		esac
		shift
	done
	[ "${#positional[@]}" -eq 2 ] || die_usage "expected <tag> and <outdir>"
	TAG=${positional[0]} OUT=${positional[1]}
	[ -n "$IDS" ] || die_usage "--identifiers <file> is required"
	case $SCANNERS in docker | local) ;; *) die_usage "--scanners must be docker or local" ;; esac
}

usage() { sed -n '2,/^set -euo/{/^set -euo/d;/shellcheck/d;s/^# \{0,1\}//;p;}' "${script_dir}/public-cut.sh"; }

validate_repo_and_tag() {
	REPO_TOP=$(git rev-parse --show-toplevel 2>/dev/null) || die_usage "run this inside the repository"
	REPO_TOP=$(abs_dir "$REPO_TOP")
	MAIN_TOP=$(dirname "$(abs_dir "$(git rev-parse --git-common-dir)")") # main worktree
	[[ $TAG =~ ^[A-Za-z0-9][A-Za-z0-9._+/-]*$ && $TAG != *..* ]] || die_usage "not a plain tag name: $TAG"
	git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null || die_usage "no such tag: $TAG"
	COMMIT=$(git rev-parse "refs/tags/${TAG}^{commit}")
	git merge-base --is-ancestor "$COMMIT" HEAD || die_usage "tag $TAG is not reachable from HEAD"
}

validate_outdir() {
	[ ! -L "$OUT" ] || die_usage "outdir is a symlink: $OUT"
	if [ -e "$OUT" ]; then
		[ -d "$OUT" ] || die_usage "outdir exists and is not a directory: $OUT"
		[ -z "$(ls -A "$OUT")" ] || die_usage "outdir exists and is not empty: $OUT"
		OUT=$(abs_dir "$OUT")
	else
		[ -d "$(dirname "$OUT")" ] || die_usage "parent of outdir does not exist: $(dirname "$OUT")"
		OUT="$(abs_dir "$(dirname "$OUT")")/$(basename "$OUT")"
	fi
	! inside_repo "$OUT" || die_usage "outdir must be outside the repository: $OUT"
	if [ "$SCANNERS" = docker ] && [[ $OUT == *,* || $WORK == *,* ]]; then
		die_usage "docker bind mounts cannot carry a comma: use an outdir and TMPDIR without one"
	fi
}

# private_file <path> <label>: absolute path of a readable file outside repo and outdir.
private_file() {
	[ -f "$1" ] && [ -r "$1" ] || die_usage "$2 missing or unreadable: $1"
	local abs
	abs="$(abs_dir "$(dirname "$1")")/$(basename "$1")"
	! inside_repo "$abs" || die_usage "the $2 is inside the repository; keep it outside: $abs"
	! is_within "$abs" "$OUT" || die_usage "the $2 is inside outdir: $abs"
	echo "$abs"
}

validate_identifiers() {
	local i=0 rc
	IDS=$(private_file "$IDS" "identifiers file")
	clean_patterns "$IDS" "$PRIV/ids"
	ID_COUNT=$(count_lines "$PRIV/ids")
	[ "$ID_COUNT" -gt 0 ] || die_usage "the identifiers file has no patterns: $IDS"
	while [ "$i" -lt "$ID_COUNT" ]; do
		i=$((i + 1))
		pattern_to "$i"
		rc=0
		grep -Eiq -f "$PRIV/p" </dev/null 2>/dev/null || rc=$? # quiet: some greps echo it
		[ "$rc" -ne 2 ] || die_usage "identifier pattern #$i is not a valid extended regex"
		if printf '\n' | grep -Eiq -f "$PRIV/p" 2>/dev/null; then
			die_usage "identifier pattern #$i matches an empty line (it would match everything)"
		fi
	done
	if [ -n "$BASELINE" ]; then
		BASELINE=$(private_file "$BASELINE" "suppressions baseline")
		clean_patterns "$BASELINE" "$WORK/baseline.raw"
		LC_ALL=C sort -u "$WORK/baseline.raw" >"$WORK/baseline"
	fi
}

# --- tools ----------------------------------------------------------------------------
preflight() {
	local missing=0 t
	for t in git tar find grep sed awk sort comm cut wc tr xargs ls cmp cp chmod stat mktemp env; do
		have "$t" || { hint "$t"; missing=1; }
	done
	have sha256sum || have shasum || { hint sha256sum; missing=1; }
	if [ "$SCANNERS" = local ]; then
		for t in gitleaks trufflehog exiftool go; do have "$t" || { hint "$t"; missing=1; }; done
	else
		if ! have docker; then
			hint docker; missing=1
		elif ! docker info >/dev/null 2>&1; then
			echo "MISSING: a running Docker daemon (docker info failed); or use --scanners=local" >&2
			missing=1
		fi
		have curl || { hint curl; missing=1; }
	fi
	[ "$missing" -eq 0 ] || die_tool "required tools are missing (see above); nothing was exported"
	if have sha256sum; then SHA_CMD=(sha256sum); else SHA_CMD=(shasum -a 256); fi
	if stat -c %a . >/dev/null 2>&1; then STAT_CMD=(stat -c '%a %F %n'); else STAT_CMD=(stat -f '%Lp %HT %N'); fi
	[ "$SCANNERS" = docker ] || check_versions
}

check_versions() { # local scanners must be the pinned releases
	local t got want bad=0
	for t in gitleaks trufflehog exiftool; do
		case $t in
		gitleaks) got=$(gitleaks version 2>&1) want=$GITLEAKS_VERSION ;;
		trufflehog) got=$(trufflehog --version 2>&1) want=$TRUFFLEHOG_VERSION ;;
		exiftool) got=$(exiftool -ver 2>&1) want=$EXIFTOOL_VERSION ;;
		esac
		got=$(printf '%s\n' "$got" | grep -Eo '[0-9]+(\.[0-9]+)+' | first_line) || got=""
		[ "$got" != "$want" ] || continue
		if [ "$ALLOW_UNPINNED" -eq 1 ]; then
			echo "WARNING: $t is ${got:-unknown}, the pin is $want (--allow-unpinned)" >&2
		else
			echo "VERSION: $t is ${got:-unknown}, the pin is $want; install it or pass --allow-unpinned" >&2
			bad=1
		fi
	done
	[ "$bad" -eq 0 ] || die_tool "local scanners differ from the pins; nothing was exported"
}

# inspect_tree: refuse entries git archive would write somewhere unexpected (before export).
inspect_tree() {
	local entry mode path oid why bad=0 ia re='export-(subst|ignore)'
	git ls-tree -r -z --full-tree "$COMMIT" >"$WORK/tree" || return 1
	shopt -s nocasematch
	while IFS= read -r -d '' entry; do
		mode=${entry%% *} path=${entry#*$'\t'} oid=${entry%%$'\t'*} why=""
		case $mode in 120000) why=symlink ;; 160000) why=submodule ;; esac
		case "/$path/" in */../* | */./* | */.git/*) why=".git or .. component" ;; esac
		[ "$path" != CUT-FAILED ] || why="reserved name"
		case $path in .gitattributes | */.gitattributes) # export must equal the inspected tree
			[[ $(git cat-file blob "${oid##* }") =~ $re ]] && why="export-ignore or export-subst" ;;
		esac
		if [[ $path == *[[:cntrl:]]* ]]; then
			echo "unsafe tree entry (control character): path not printed"
			bad=1
		elif [ -n "$why" ]; then
			echo "unsafe tree entry ($why): $(shown_path "$path")"
			bad=1
		fi
	done <"$WORK/tree"
	shopt -u nocasematch
	ia=$(git rev-parse --git-path info/attributes)
	if [ -f "$ia" ] && grep -Eq "$re" "$ia"; then
		echo "unsafe: $ia sets export-ignore or export-subst, which git archive would apply"
		bad=1
	fi
	return "$bad"
}

# --- checks (each returns non-zero on failure; errexit is off inside `if`) ------------
check_export() {
	local bad
	bad=$(cd "$OUT" && find . \( -name .git -o -type l \) -print) || return 1
	[ -z "$bad" ] || { echo "unexpected .git or symlink entries in the export"; return 1; }
	echo "ok: no .git, no symlinks"
}

check_large_files() {
	local f
	(cd "$OUT" && find . -type f -size +"${MAX_FILE_BYTES}"c -print0) >"$WORK/big" || return 1
	[ -s "$WORK/big" ] || { echo "ok: largest allowed is $MAX_FILE_BYTES bytes"; return 0; }
	echo "files over $MAX_FILE_BYTES bytes (build output or data that does not belong in the tree):"
	while IFS= read -r -d '' f; do
		printf '  %s (%s bytes)\n' "$(shown_path "${f#./}")" "$(wc -c <"$OUT/$f" | tr -d ' ')"
	done <"$WORK/big"
	return 1
}

list_media() { # one ./path per line; inspect_tree ruled out newlines in names
	local e expr=()
	for e in $MEDIA_EXT; do expr+=(-o -iname "*.$e"); done
	(cd "$OUT" && find . -type f \( "${expr[@]:1}" \) -print | LC_ALL=C sort)
}

exif_scan() { # exif_scan <list> <out>: per file: path, then each tag (or "-" if absent)
	local tab fmt t
	tab=$(printf '\t')
	# shellcheck disable=SC2016 # exiftool's own $Tag syntax, not shell
	fmt='$Directory/$FileName'
	for t in $EXIF_ALWAYS $EXIF_TEXT; do fmt="${fmt}${tab}\${${t};tr/\\t\\r\\n/   /}"; done
	run_exiftool ro -q -q -m -f -p "$fmt" -@ - <"$1" >"$2"
}

exif_flagged() { # exif_flagged <scan> <list>: offending files with tag names (no values)
	ALWAYS="$EXIF_ALWAYS" TEXT="$EXIF_TEXT" HOSTISH="$HOSTISH_RE" LIST="$2" awk -F'\t' '
		BEGIN { hostish = ENVIRON["HOSTISH"]; list = ENVIRON["LIST"]; k = 0
			n = split(ENVIRON["ALWAYS"], a, /[ \n]+/)
			for (i = 1; i <= n; i++) if (a[i] != "") { name[++k] = a[i]; strict[k] = 1 }
			n = split(ENVIRON["TEXT"], b, /[ \n]+/)
			for (i = 1; i <= n; i++) if (b[i] != "") { name[++k] = b[i]; strict[k] = 0 } }
		{ bad = ""
		  for (j = 1; j <= k; j++) { v = $(j + 1)
		    if (v == "-" || v == "") continue
		    if (strict[j] || tolower(v) ~ hostish) bad = bad (bad == "" ? "" : ", ") name[j] }
		  if (bad != "") { sub(/^\.\//, "", $1); print $1 ": " bad; print "./" $1 > list } }' "$1"
}

# exif_text_dump: every metadata value (zTXt/iTXt inflated by exiftool), one per line in
# meta.vals with its file in meta.paths, for the identifier grep.
exif_text_dump() {
	: >"$WORK/meta.vals"
	: >"$WORK/meta.paths"
	[ -s "$WORK/media" ] || return 0
	# No -q: it would also drop the "======== <file>" headers this parses.
	run_exiftool ro -m -a -s -G1 -@ - <"$WORK/media" >"$WORK/meta.dump" 2>/dev/null || return 1
	FIRST=$(first_line <"$WORK/media") VALS="$WORK/meta.vals" PATHS="$WORK/meta.paths" awk '
		BEGIN { cur = ENVIRON["FIRST"] }
		/^======== / { cur = substr($0, 10); next }
		!/^\[/ || /^\[(System|ExifTool|File)\]/ { next }
		{ i = index($0, ": "); if (!i) next; p = cur; sub(/^\.\//, "", p)
		  print substr($0, i + 2) > ENVIRON["VALS"]; print p > ENVIRON["PATHS"] }' "$WORK/meta.dump"
}

check_image_metadata() {
	local n report
	list_media >"$WORK/media" || return 1
	n=$(count_lines "$WORK/media")
	[ "$n" -gt 0 ] || { exif_text_dump; echo "ok: no media files in the tree"; return 0; }
	exif_scan "$WORK/media" "$WORK/exif" || { echo "exiftool failed (see above)"; return 1; }
	[ "$(count_lines "$WORK/exif")" -eq "$n" ] || { echo "exiftool did not report every file"; return 1; }
	: >"$WORK/flagged"
	report=$(exif_flagged "$WORK/exif" "$WORK/flagged") || return 1
	if [ -n "$report" ]; then
		printf 'media with identifying metadata (tag names only):\n%s\n' "$report"
		[ "$STRIP" -eq 1 ] || { echo "fix them in the source and re-tag, or re-run with --strip-metadata"; return 1; }
		STRIPPED=$(count_lines "$WORK/flagged")
		echo "--strip-metadata: stripping $STRIPPED file(s), then checking again"
		run_exiftool rw -q -m -all= --icc_profile:all -overwrite_original -@ - <"$WORK/flagged" || return 1
		exif_scan "$WORK/media" "$WORK/exif" || return 1
		report=$(exif_flagged "$WORK/exif" "$WORK/flagged") || return 1
		[ -z "$report" ] || { printf 'still flagged after stripping:\n%s\n' "$report"; return 1; }
	fi
	exif_text_dump || { echo "exiftool failed to dump metadata text"; return 1; }
	echo "ok: $n media files, no personal, device, location or host metadata"
}

# grep_status <rc> <what>: grep exits 1 for "no match"; anything above is a failure.
grep_status() { [ "$1" -le 1 ] || { echo "grep failed while scanning $2 (exit $1)"; return 2; }; }

identifier_hits() { # identifier_hits <n>: 0 no hit, 1 hits, 2 error; never the text
	local i=$1 rc=0 n f lines hit=0
	pattern_to "$i"
	grep -Ein -f "$PRIV/p" "$WORK/names" >"$PRIV/m" || rc=$?
	grep_status "$rc" names || return 2
	LC_ALL=C cut -d: -f1 "$PRIV/m" >"$WORK/namehits"
	# count entries, not lines: each entry is listed as its path and as its own name
	n=$(awk 'NR == FNR { want[$1] = 1; next } FNR in want' "$WORK/namehits" "$WORK/names.idx" | LC_ALL=C sort -u | wc -l | tr -d ' ')
	if [ "$n" -gt 0 ]; then
		echo "pattern #$i: $n file or directory name(s) match (paths withheld; list them with: find <outdir> | grep -Eif <identifiers>)"
		hit=1
	fi
	rc=0
	(cd "$OUT" && grep -rlaEi --null -f "$PRIV/p" .) >"$WORK/files" || rc=$?
	grep_status "$rc" "file contents" || return 2
	while IFS= read -r -d '' f; do
		rc=0
		grep -naEi -f "$PRIV/p" -- "$OUT/$f" >"$PRIV/m" || rc=$? # the matched text stays in PRIV
		grep_status "$rc" "file contents" || return 2
		lines=$(LC_ALL=C awk -F: -v n="$MAX_LINES_SHOWN" 'NR <= n { printf "%s%s", (NR > 1 ? "," : ""), $1 }' "$PRIV/m")
		echo "pattern #$i: $(shown_path "${f#./}"):${lines}"
		hit=1
	done <"$WORK/files"
	rc=0
	grep -naEi -f "$PRIV/p" "$WORK/meta.vals" >"$PRIV/m" || rc=$?
	grep_status "$rc" "metadata text" || return 2
	LC_ALL=C cut -d: -f1 "$PRIV/m" >"$WORK/metahits"
	if [ -s "$WORK/metahits" ]; then
		awk 'NR == FNR { want[$1] = 1; next } FNR in want' "$WORK/metahits" "$WORK/meta.paths" | LC_ALL=C sort -u >"$WORK/metafiles"
		while IFS= read -r f; do echo "pattern #$i: $(shown_path "$f") (in its metadata)"; done <"$WORK/metafiles"
		hit=1
	fi
	return "$hit"
}

check_identifiers() {
	local i=0 failed=0 none="" rc
	(cd "$OUT" && find . -mindepth 1 -print) | sed 's|^\./||' |
		IDX="$WORK/names.idx" awk -F/ '{ print; print NR > ENVIRON["IDX"]; if (NF > 1) { print $NF; print NR > ENVIRON["IDX"] } }' >"$WORK/names" || return 1
	while [ "$i" -lt "$ID_COUNT" ]; do
		i=$((i + 1))
		rc=0
		identifier_hits "$i" || rc=$?
		case $rc in 0) none="$none #$i" ;; *) failed=1 ;; esac
	done
	rm -f "$PRIV/p" "$PRIV/m"
	[ -z "$none" ] || echo "info: patterns that matched nothing in the tree:$none"
	[ "$failed" -eq 0 ] || { echo "(matched text is never printed; up to $MAX_LINES_SHOWN line numbers per file)"; return 1; }
	echo "ok: no file content, name or metadata text matches any of the $ID_COUNT patterns"
}

# collect_suppressions: supp.list (path:line marker, for people) and supp.keys (the
# baseline form: marker path hash-of-trimmed-line, or file path hash-of-file).
collect_suppressions() {
	local rc=0 path rest text m f h
	: >"$WORK/supp.list"
	: >"$WORK/supp.keys.raw"
	(cd "$OUT" && grep -rnaE --null "$SUPPRESS_RE" .) >"$WORK/supp.raw" || rc=$?
	grep_status "$rc" "for suppressions" || return 1
	while IFS= read -r -d '' path && IFS= read -r rest; do
		path=${path#./} text=${rest#*:}
		h=$(line_hash "$text")
		for m in "${MARKERS[@]}"; do
			case $text in *"$m"*)
				echo "  $(shown_path "$path"):${rest%%:*} $m" >>"$WORK/supp.list"
				echo "$m $path $h" >>"$WORK/supp.keys.raw" ;;
			esac
		done
	done <"$WORK/supp.raw"
	for f in $SUPPRESS_FILES; do
		(cd "$OUT" && find . -type f -name "$f" -print) | while IFS= read -r path; do
			echo "  $(shown_path "${path#./}") (scanner config or ignore file)" >>"$WORK/supp.list"
			echo "file ${path#./} $(hash16 <"$OUT/$path")" >>"$WORK/supp.keys.raw"
		done
	done
	LC_ALL=C sort -u "$WORK/supp.keys.raw" >"$WORK/supp.keys"
	SUPP_COUNT=$(count_lines "$WORK/supp.keys")
}

print_keys() { # print_keys <file>: "  key: marker path hash", path withheld if it matches
	local k m rest # the marker has no blank and the hash comes last, so the path may have some
	while IFS= read -r k; do
		m=${k%% *} rest=${k#* }
		echo "  key: $m $(shown_path "${rest% *}") ${rest##* }"
	done <"$1"
}

check_suppressions() {
	[ "$SUPP_COUNT" -gt 0 ] || { echo "ok: none in the tree"; return 0; }
	echo "in-tree suppressions (review each; reviewed key lines go into --suppressions-baseline):"
	cat "$WORK/supp.list"
	print_keys "$WORK/supp.keys"
	if [ -z "$BASELINE" ]; then
		NEED_REVIEW=1
		echo "$REVIEW_MSG"
		return 1
	fi
	LC_ALL=C comm -23 "$WORK/supp.keys" "$WORK/baseline" >"$WORK/supp.new"
	[ -s "$WORK/supp.new" ] || { echo "ok: every suppression is in the baseline"; return 0; }
	echo "not in the baseline:"
	print_keys "$WORK/supp.new"
	return 1
}

# repopolicy_tree: the export with HEAD's internal/repopolicy in place of the tag's.
repopolicy_tree() {
	local pol="$WORK/policy"
	git cat-file -e "HEAD:internal/repopolicy" 2>/dev/null || { echo "HEAD has no internal/repopolicy"; return 1; }
	mkdir "$pol" && cp -R "$OUT/." "$pol/" && rm -rf "$pol/internal/repopolicy" || return 1
	git archive --format=tar HEAD -- internal/repopolicy | tar -x -C "$pol" || return 1
	echo "$pol"
}

repopolicy_run() { # repopolicy_run <tree>: go test; output to repopolicy.log
	local pol=$1 test=(go test -count=1 -v ./internal/repopolicy/...)
	if [ "$SCANNERS" = local ]; then
		chmod 000 "$PRIV" # the identifier copy is unreadable while the tests run
		(cd "$pol" && env GOTOOLCHAIN=local GOFLAGS=-mod=readonly GOWORK=off "${test[@]}") >"$WORK/repopolicy.log" 2>&1
		local rc=$?
		chmod 700 "$PRIV"
		return "$rc"
	fi
	mkdir -p "$WORK/gomod" || return 1
	set -- -e GOMODCACHE=/gomod -e GOPATH=/tmp/gopath -e GOCACHE=/tmp/gocache -e GOTOOLCHAIN=local \
		-e GOFLAGS=-mod=readonly -w /src --mount "$(mnt "$pol" /src ro)"
	# Downloads come from the Go module proxy only (no "direct"), checked against sum.golang.org.
	{ docker_run -e GOPROXY=https://proxy.golang.org "$@" --mount "$(mnt "$WORK/gomod" /gomod)" \
		"$GOLANG_IMAGE" go mod download &&
		docker_run --network=none -e GOPROXY=off "$@" --mount "$(mnt "$WORK/gomod" /gomod ro)" \
			"$GOLANG_IMAGE" "${test[@]}"; } >"$WORK/repopolicy.log" 2>&1
}

check_repopolicy() {
	local pol rc=0
	pol=$(repopolicy_tree) || { echo "$pol"; return 1; }
	repopolicy_run "$pol" || rc=$?
	if [ "$rc" -ne 0 ]; then
		grep -E '^(--- FAIL|FAIL|[[:space:]]+[a-z_]+_test\.go:[0-9]+:)' "$WORK/repopolicy.log" |
			awk 'NR <= 60' >"$WORK/repopolicy.excerpt" || true
		redact_lines "$WORK/repopolicy.excerpt"
		echo "go test failed (exit $rc)"
		return 1
	fi
	grep -q -- '--- PASS: TestPublicTreeHasNoNetworkDetails' "$WORK/repopolicy.log" || {
		echo "TestPublicTreeHasNoNetworkDetails did not run"
		return 1
	}
	echo "ok: $(grep -c -- '^--- PASS' "$WORK/repopolicy.log") tests of HEAD's repopolicy passed on the cut"
}

# gitleaks_run <normal|strict> <out>: findings as "rule<TAB>file<TAB>line". The strict pass
# scans a copy without .gitleaksignore/.gitleaks.toml: gitleaks 8.30.1 reads the scanned
# directory's .gitleaksignore even when -i names another directory.
gitleaks_run() {
	local g="$WORK/gl" src=$OUT args
	[ "$SCANNERS" = local ] || g=/gl
	args=(dir . --redact --no-banner --no-color --exit-code 99 --log-level error
		--report-format template --report-template "$g/report.tmpl" --report-path -)
	if [ "$1" = strict ]; then
		src="$WORK/gl.tree"
		args+=(-c "$g/strict.toml" -i "$g/empty" --ignore-gitleaks-allow)
	else
		args+=(-i .)
	fi
	if [ "$SCANNERS" = local ]; then
		(cd "$src" && env -u GITLEAKS_CONFIG -u GITLEAKS_CONFIG_TOML gitleaks "${args[@]}") >"$2" 2>"$WORK/gl.err"
	else
		docker_run --network=none --mount "$(mnt "$src" /src ro)" --mount "$(mnt "$WORK/gl" /gl ro)" \
			-w /src "$GITLEAKS_IMAGE" "${args[@]}" >"$2" 2>"$WORK/gl.err"
	fi
}

# gl_covered <file> <line>: a finding only the strict pass sees is covered when the
# baseline holds the inline allow on that line, or a reviewed in-tree gitleaks config or
# ignore file (which may hide findings anywhere).
gl_covered() {
	[ -n "$BASELINE" ] || return 1
	grep -qxF -- "${MARKERS[0]} $1 $(line_hash "$(sed -n "${2}p" "$OUT/$1" 2>/dev/null)")" "$WORK/baseline" && return 0
	LC_ALL=C comm -12 "$WORK/supp.keys" "$WORK/baseline" | grep -Eq '^file (.*/)?\.gitleaks(ignore|\.toml) '
}

report_extras() { # report_extras: list strict-only findings; non-zero if any is uncovered
	local rule file line bad=0 tab
	tab=$(printf '\t')
	while IFS="$tab" read -r rule file line; do
		[ -n "$rule" ] || continue
		file=${file#./}
		if gl_covered "$file" "$line"; then
			echo "  suppressed in-tree (review): $rule $(shown_path "$file"):$line"
		else
			echo "  suppressed in-tree (review): $rule $(shown_path "$file"):$line -- not covered by the baseline"
			bad=1
		fi
	done <"$WORK/gl.extra"
	return "$bad"
}

print_findings() { # print_findings <file> [label]
	local rule file line
	while IFS="$(printf '\t')" read -r rule file line; do
		[ -n "$rule" ] && echo "  ${2:-}$rule $(shown_path "${file#./}"):$line"
	done <"$1"
}

check_gitleaks() {
	local rc=0 src=0 extra=0
	mkdir -p "$WORK/gl/empty" "$WORK/gl.tree" && cp -R "$OUT/." "$WORK/gl.tree/" || return 1
	find "$WORK/gl.tree" -type f \( -name .gitleaksignore -o -name .gitleaks.toml \) -exec rm -f {} + || return 1
	printf '{{ range . }}{{ .RuleID }}\t{{ .File }}\t{{ .StartLine }}\n{{ end }}' >"$WORK/gl/report.tmpl"
	printf '[extend]\nuseDefault = true\n' >"$WORK/gl/strict.toml"
	gitleaks_run normal "$WORK/gl.normal" || rc=$?
	case $rc in 0 | 99) ;; *) redact_lines "$WORK/gl.err"; echo "gitleaks did not complete (exit $rc)"; return 1 ;; esac
	gitleaks_run strict "$WORK/gl.strict" || src=$?
	case $src in 0 | 99) ;; *) redact_lines "$WORK/gl.err"; echo "gitleaks strict pass did not complete (exit $src)"; return 1 ;; esac
	LC_ALL=C sort -u "$WORK/gl.normal" >"$WORK/gl.a"
	LC_ALL=C sort -u "$WORK/gl.strict" | LC_ALL=C comm -13 "$WORK/gl.a" - >"$WORK/gl.extra"
	report_extras || extra=1
	if [ "$rc" -eq 99 ]; then
		echo "gitleaks found leaks (secrets redacted):"
		print_findings "$WORK/gl.normal"
		echo "gitleaks found leaks; fix them in the source and re-tag"
		return 1
	fi
	[ "$extra" -eq 0 ] || { echo "findings hidden in-tree that the baseline does not cover (see above)"; return 1; }
	echo "ok: no leaks"
}

trufflehog_report() { # detector, verification state and file:line; never the secret
	local line file ln det ver
	while IFS= read -r line; do
		file=$(printf '%s' "$line" | sed -nE 's/.*"file":"([^"]*)".*/\1/p')
		ln=$(printf '%s' "$line" | sed -nE 's/.*"line":([0-9]+).*/\1/p')
		det=$(printf '%s' "$line" | sed -nE 's/.*"DetectorName":"([^"]*)".*/\1/p')
		ver=$(printf '%s' "$line" | sed -nE 's/.*"Verified":(true|false).*/\1/p')
		printf '  %s verified=%s %s:%s\n' "${det:-?}" "${ver:-?}" "$(shown_path "${file#./}")" "${ln:-?}"
	done <"$1"
}

check_trufflehog() {
	local rc=0 net=()
	set -- filesystem . --fail --no-update --json --no-color
	if [ "$NOVERIFY" -eq 1 ]; then
		set -- "$@" --no-verification --results=unverified,unknown
		net=(--network=none)
	else
		set -- "$@" --results=verified,unknown
	fi
	if [ "$SCANNERS" = local ]; then
		(cd "$OUT" && trufflehog "$@") >"$WORK/th.json" 2>"$WORK/th.log" || rc=$?
	else
		docker_run ${net[@]+"${net[@]}"} --mount "$(mnt "$OUT" /src ro)" -w /src "$TRUFFLEHOG_IMAGE" "$@" \
			>"$WORK/th.json" 2>"$WORK/th.log" || rc=$?
	fi
	case $rc in
	0) echo "ok: nothing found" ;;
	183) echo "trufflehog findings:"; trufflehog_report "$WORK/th.json"; rc=1 ;;
	*) awk 'NR > 0' "$WORK/th.log" | tail -n 20 >"$WORK/th.tail"; redact_lines "$WORK/th.tail"
		echo "trufflehog did not complete (exit $rc)"; rc=1 ;;
	esac
	rm -f "$WORK/th.json" "$WORK/th.log"
	return "$rc"
}

manifest() { # every entry's mode and type, then every file's SHA-256
	(cd "$OUT" && find . -print0 | LC_ALL=C sort -z | xargs -0 "${STAT_CMD[@]}" &&
		find . -type f -print0 | LC_ALL=C sort -z | xargs -0 "${SHA_CMD[@]}")
}

check_manifest() {
	manifest >"$WORK/manifest.after" || return 1
	cmp -s "$WORK/manifest.before" "$WORK/manifest.after" || {
		echo "the tree changed while it was being scanned; do not publish it, re-run into a fresh outdir"
		return 1
	}
	echo "ok: every file is byte- and mode-identical to what was scanned"
}

# --- summary and main -----------------------------------------------------------------
run_check() {
	local name=$1
	shift
	printf '\n== %s\n' "$name"
	if "$@"; then
		NAMES+=("$name") RESULTS+=(PASS)
	else
		NAMES+=("$name") RESULTS+=(FAIL)
		FAILED=1
	fi
}

summary() {
	local i=0
	printf '\n%-44s %s\n' "CHECK" "RESULT"
	printf '%-44s %s\n' "--------------------------------------------" "------"
	while [ "$i" -lt "${#NAMES[@]}" ]; do
		printf '%-44s %s\n' "${NAMES[$i]}" "${RESULTS[$i]}"
		i=$((i + 1))
	done
	printf '\nTag %s (%s), scanners: %s, tree: %s\n' "$TAG" "$COMMIT" "$SCANNERS" "$OUT"
	if [ "$SUPP_COUNT" -gt 0 ]; then
		echo "In-tree suppressions to review:"
		cat "$WORK/supp.list"
	fi
	[ "$NEED_REVIEW" -eq 0 ] || echo "$REVIEW_MSG"
	if [ "$STRIPPED" -gt 0 ]; then
		echo "NOTE: --strip-metadata changed $STRIPPED file(s): the cut no longer matches $TAG byte for byte."
		echo "      Prefer fixing them in the source repository and cutting a new tag."
	fi
	if [ "$FAILED" -ne 0 ]; then
		echo
		echo "FAILED: do not publish $OUT. Fix the source, tag again, and re-run into a fresh outdir."
		return 0
	fi
	cat <<EOF

All checks passed. Next steps are manual; this script performs none of them:
  1. cd "$OUT" && git init && git add -A && git commit -s -m 'Initial public release'
  2. Create a new, PRIVATE GitHub repository and push this one commit to it.
  3. Maintainer review on GitHub (docs/plans/07-public-release.md §7 checklist).
  4. Only then switch the repository's visibility to public.
EOF
}

finish() {
	summary >"$WORK/summary"
	cat "$WORK/summary"
	if [ "$FAILED" -eq 0 ]; then rm -f "$OUT/CUT-FAILED"; exit 0; fi
	cp "$WORK/summary" "$OUT/CUT-FAILED" || true
	exit 1
}

main() {
	set_locale
	parse_args "$@"
	trap cleanup EXIT
	trap 'exit 130' INT
	trap 'exit 143' TERM
	WORK=$(umask 077 && mktemp -d "${TMPDIR:-/tmp}/public-cut.XXXXXX")
	WORK=$(abs_dir "$WORK")
	PRIV="$WORK/private"
	(umask 077 && mkdir "$PRIV")
	validate_repo_and_tag
	validate_outdir
	validate_identifiers
	preflight
	inspect_tree || { echo "the tree of $TAG is unsafe to export; nothing was exported (do not publish)"; exit 1; }
	mkdir -p "$OUT"
	# The marker exists until the success path removes it: tar errors, errexit, INT and TERM keep it.
	printf 'public-cut.sh has not passed on this tree: do not publish it.\n' >"$OUT/CUT-FAILED"
	echo "Exporting $TAG ($COMMIT) to $OUT"
	git -c core.attributesFile=/dev/null archive --format=tar "$COMMIT" | tar -x -C "$OUT"

	run_check "export has no .git and no symlinks" check_export
	[ "$FAILED" -eq 0 ] || finish
	run_check "no file over 5 MiB" check_large_files
	run_check "media metadata" check_image_metadata
	manifest >"$WORK/manifest.before"
	run_check "private identifiers ($ID_COUNT patterns)" check_identifiers
	collect_suppressions || { NAMES+=("in-tree suppressions") RESULTS+=(FAIL); FAILED=1; }
	run_check "in-tree suppressions ($SUPP_COUNT)" check_suppressions
	run_check "repopolicy (HEAD's tests) on the cut" check_repopolicy
	run_check "gitleaks" check_gitleaks
	run_check "trufflehog" check_trufflehog
	run_check "scans left the tree unchanged" check_manifest
	finish
}

main "$@"
