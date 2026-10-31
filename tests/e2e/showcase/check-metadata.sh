#!/usr/bin/env bash
# Fails when a README screenshot carries anything but the PNG header fields (no text
# chunks, EXIF, XMP, ICC profile, timestamps or software tags). Needs exiftool.
set -euo pipefail
dir=${1:?usage: check-metadata.sh <dir>}
shopt -s nullglob
pngs=("$dir"/*.png)
if ((${#pngs[@]} == 0)); then
	echo "no PNGs in $dir" >&2
	exit 1
fi
# exiftool's own groups describe the file on disk, not its content.
ignore='^\[(ExifTool|System|File|Composite)\]'
header='^\[PNG(-[A-Za-z]+)?\] +(ImageWidth|ImageHeight|BitDepth|ColorType|Compression|Filter|Interlace|Palette|Transparency) +:'
bad=0
for f in "${pngs[@]}"; do
	extra=$(exiftool -a -G1 -s "$f" | grep -Ev "$ignore" | grep -Ev "$header" || true)
	if [[ -n $extra ]]; then
		echo "$f carries metadata:" >&2
		echo "$extra" >&2
		bad=1
	fi
done
exit $bad
