#!/usr/bin/env bash
# Rebuilds the two vendored woff2 subsets from the upstream releases and checks that the
# result is byte-identical to what internal/web/ui/vendor.sha256 records (tech_doc §35).
# A maintainer tool: not run in CI, never shipped. Needs bash, curl, unzip, shasum or
# sha256sum, and python3 (fontTools and brotli go into a throwaway venv).
#
#   tools/fonts/build-fonts.sh [work-dir]     (default: a temporary directory, removed on exit)
#
# Set FONT_TOOLS_ALLOW_SDIST=1 on a platform without wheels for the pinned versions (the
# source archives are hash-pinned as well).
#
# Every download is checked against a recorded SHA-256 before it is opened (the Python
# tools too: requirements.txt pins every published file by hash), and the
# output is checked against vendor.sha256, so a changed upstream asset or a different
# tool version stops the run instead of producing new bytes silently. New font bytes
# need a new versioned directory (static/vendor/fonts/<family>-<version>[-rN]/): the
# URL is cached for a year as immutable. See TestFontBuildsAreAppendOnly.
set -euo pipefail

INTER_VERSION=4.1
INTER_ZIP_URL="https://github.com/rsms/inter/releases/download/v${INTER_VERSION}/Inter-${INTER_VERSION}.zip"
INTER_ZIP_SHA256=9883fdd4a49d4fb66bd8177ba6625ef9a64aa45899767dde3d36aa425756b11e
INTER_TTF=InterVariable.ttf
INTER_TTF_SHA256=4989b125924991b90d05b2d16e0e388c48f7d5bb8b30539bbf9c755278d0ccaf
INTER_EPOCH=1792637339 # head.modified of the vendored file: 2026-10-22 02:48:59 UTC

JBMONO_VERSION=2.304
JBMONO_ZIP_URL="https://github.com/JetBrains/JetBrainsMono/releases/download/v${JBMONO_VERSION}/JetBrainsMono-${JBMONO_VERSION}.zip"
JBMONO_ZIP_SHA256=6f6376c6ed2960ea8a963cd7387ec9d76e3f629125bc33d1fdcd7eb7012f7bbf
JBMONO_TTF='fonts/variable/JetBrainsMono[wght].ttf'
JBMONO_TTF_SHA256=662a196d58f1183bf2d77428b6d5283fe3f45161ab021bea4036bc98e5cac016
JBMONO_EPOCH=1792637351 # 2026-10-22 02:49:11 UTC

# fontTools 4.67.0 and brotli 1.2.1 (the woff2 bytes depend on the encoder version too):
# exact versions and hashes in requirements.txt; tech_doc §35 records why they are younger
# than the 14-day rule allows.

UNICODES="U+0020-007E,U+00A0-00FF,U+0131,U+0152-0153,U+2013-2014,U+2018-201E,U+2022,U+2026,U+2190-2193,U+2197,U+2212,U+2264-2265,U+2318,U+2713"
NAME_IDS="0,1,2,3,4,5,6,13,14"
INTER_FEATURES="kern,ccmp,locl,mark,mkmk,calt,case,tnum,zero,ss02"
JBMONO_FEATURES="ccmp,locl,mark,mkmk,case,zero" # no ligatures

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
manifest="$repo/internal/web/ui/vendor.sha256"
if [ -n "${1:-}" ]; then
  work=$1
else
  work=$(mktemp -d)
  trap 'rm -rf "$work"' EXIT
fi
mkdir -p "$work/dl" "$work/out"

sha256() { if command -v sha256sum >/dev/null; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

check() { # file expected-sha256
  local got
  got=$(sha256 "$1")
  [ "$got" = "$2" ] || { echo "SHA-256 mismatch for $1: got $got, want $2" >&2; exit 1; }
}

fetch() { # url expected-sha256 -> path
  local dest="$work/dl/$(basename "$1")"
  [ -f "$dest" ] || curl -fsSL --proto '=https' --proto-redir '=https' -o "$dest" "$1"
  check "$dest" "$2"
  printf '%s\n' "$dest"
}

python3 -m venv "$work/venv"
binary=--only-binary=:all:
[ "${FONT_TOOLS_ALLOW_SDIST:-}" = 1 ] && binary=--prefer-binary
"$work/venv/bin/pip" install --quiet --disable-pip-version-check --no-cache-dir \
  --require-hashes "$binary" -r "$here/requirements.txt"
py() { "$work/venv/bin/python" -I "$@"; }

build() { # zip member ttf-sha256 epoch features out-name
  local zip=$1 member=$2 ttf_sha=$3 epoch=$4 features=$5 out=$6
  local ttf="$work/dl/$(basename "$member")"
  unzip -o -q -j "$zip" "$(printf '%s' "$member" | sed 's/[][]/\\&/g')" -d "$work/dl"
  check "$ttf" "$ttf_sha"
  # SOURCE_DATE_EPOCH fixes head.modified, the only field that otherwise varies per run.
  SOURCE_DATE_EPOCH=$epoch py -m fontTools.varLib.instancer "$ttf" wght=400:700 -o "$work/out/$out.ttf"
  SOURCE_DATE_EPOCH=$epoch py -m fontTools.subset "$work/out/$out.ttf" --unicodes="$UNICODES" \
    --flavor=woff2 --no-hinting --layout-features="$features" --name-IDs="$NAME_IDS" \
    --output-file="$work/out/$out.woff2"
}

inter_zip=$(fetch "$INTER_ZIP_URL" "$INTER_ZIP_SHA256")
jbmono_zip=$(fetch "$JBMONO_ZIP_URL" "$JBMONO_ZIP_SHA256")
build "$inter_zip" "$INTER_TTF" "$INTER_TTF_SHA256" "$INTER_EPOCH" "$INTER_FEATURES" inter-var-latin
build "$jbmono_zip" "$JBMONO_TTF" "$JBMONO_TTF_SHA256" "$JBMONO_EPOCH" "$JBMONO_FEATURES" jetbrains-mono-var-latin

for pair in "inter-$INTER_VERSION/inter-var-latin" "jetbrains-mono-$JBMONO_VERSION/jetbrains-mono-var-latin"; do
  want=$(awk -v f="fonts/$pair.woff2" '$2 == f { print $1 }' "$manifest")
  [ -n "$want" ] || { echo "vendor.sha256 has no fonts/$pair.woff2 (new version: new directory, new manifest line)" >&2; exit 1; }
  check "$work/out/$(basename "$pair").woff2" "$want"
  echo "ok  fonts/$pair.woff2  $want"
done
if [ -n "${1:-}" ]; then
  echo "Rebuilt files are in $work/out (identical to the vendored ones)."
else
  echo "Rebuilt files were identical to the vendored ones (temporary directory removed)."
fi
