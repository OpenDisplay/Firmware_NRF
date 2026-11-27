#!/bin/sh
# Build the od_epd replay harness (copied unmodified from Firmware_Unified tests/panels/harness at
# 63c124b) against the vendored od/core/od_epd.c, the way this target builds it.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
OUT=${1:-$REPO/host/build}
mkdir -p "$OUT"
cc -std=c99 -Wall -Wextra -DOD_EPD_WITH_WINDOW=0 -I"$REPO/od/core" -I"$REPO/od/hal" \
   -I"$REPO/od/protocol" "$HERE/od_epd_replay.c" "$REPO/od/core/od_epd.c" -o "$OUT/od_epd_replay"
echo "$OUT/od_epd_replay"
