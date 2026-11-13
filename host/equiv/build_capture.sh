#!/bin/sh
# Build the capture harness from the 2.x drivers as committed in the import commit (417545d).
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=${1:-$REPO/host/build}
mkdir -p "$OUT/orig"
for f in EPD/UC81xx.c EPD/SSD16xx.c EPD/EPD_driver.h; do
  git -C "$REPO" show 417545d:$f > "$OUT/orig/$(basename $f)"
done
cc -std=gnu11 -w -I"$HERE/stubs" -I"$OUT/orig" "$HERE/capture.c" "$OUT/orig/UC81xx.c" \
   "$OUT/orig/SSD16xx.c" -o "$OUT/capture"
echo "$OUT/capture"
# The od_epd replay harness (copied unmodified from Firmware_Unified tests/panels/harness at
# 63c124b) linked against the vendored od/core/od_epd.c, built the way this target builds it.
cc -std=c99 -Wall -Wextra -DOD_EPD_WITH_WINDOW=0 -I"$REPO/od/core" -I"$REPO/od/hal" \
   -I"$REPO/od/protocol" "$HERE/od_epd_replay.c" "$REPO/od/core/od_epd.c" -o "$OUT/od_epd_replay"
echo "$OUT/od_epd_replay"
