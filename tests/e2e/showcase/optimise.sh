#!/usr/bin/env bash
# Optimises the README screenshots in place (make showcase): pngquant (lossy palette,
# quality 80-95) then oxipng (lossless, every ancillary chunk stripped). A file pngquant
# cannot bring into that quality range, or would make larger, stays lossless.
#
#   optimise.sh --check   fail early when a tool is missing (unless SHOWCASE_RAW=1)
#   optimise.sh <dir>     optimise every PNG in <dir>; fail on any file over 1 MB
set -euo pipefail

tools=(pngquant oxipng)
max_bytes=$((1024 * 1024))

missing() {
	local t out=()
	for t in "${tools[@]}"; do command -v "$t" >/dev/null 2>&1 || out+=("$t"); done
	echo "${out[*]}"
}

need_tools() {
	local m
	m=$(missing)
	[[ -z $m ]] && return 0
	if [[ ${SHOWCASE_RAW:-} == 1 ]]; then
		echo "WARNING: $m not installed; the PNGs stay unoptimised (SHOWCASE_RAW=1). Never commit them." >&2
		return 1
	fi
	echo "make showcase needs: $m (brew install pngquant oxipng, or see .github/workflows/showcase.yml)." >&2
	echo "Set SHOWCASE_RAW=1 to keep the raw PNGs for a local look." >&2
	exit 1
}

if [[ ${1:-} == --check ]]; then
	need_tools || true
	exit 0
fi

dir=${1:?usage: optimise.sh --check | <dir>}
shopt -s nullglob
pngs=("$dir"/*.png)
if ((${#pngs[@]} == 0)); then
	echo "no PNGs in $dir" >&2
	exit 1
fi
need_tools || exit 0

for f in "${pngs[@]}"; do
	rc=0
	pngquant --quality=80-95 --speed 1 --strip --skip-if-larger --force --output "$f" -- "$f" || rc=$?
	case $rc in
	0) ;;
	98 | 99) echo "$f: kept lossless (pngquant exit $rc)" ;;
	*) echo "$f: pngquant failed ($rc)" >&2 && exit 1 ;;
	esac
	oxipng -o 4 --strip all --quiet "$f"
	size=$(wc -c <"$f")
	printf '%8d  %s\n' "$size" "$f"
	if ((size > max_bytes)); then
		echo "$f is larger than 1 MB" >&2
		exit 1
	fi
done
