#!/bin/sh
# Re-vendor the shared OpenDisplay 3.0 sources this firmware compiles, unmodified, from a
# Firmware_Unified checkout. Usage: tools/sync_od.sh /path/to/Firmware_Unified
# The files under od/ are never edited here; target-specific code lives in glue/.
set -eu
SRC=${1:?usage: tools/sync_od.sh /path/to/Firmware_Unified}
DST=$(cd "$(dirname "$0")/.." && pwd)/od
CORE_C="od_epd.c od_epd_cfg.c od_cfg_index.c od_display.c od_color.c od_config_store.c
        od_config_tlv.c od_cmd_spi_raw.c od_config_asm.c od_advert.c"
CORE_H="od_epd.h od_epd_cfg.h od_cfg_index.h od_display.h od_display_app.h od_drive_app.h
        od_color.h od_config_store.h od_config_tlv.h od_config_asm.h od_config.h od_span.h
        od_log.h od_boot_screen.h od_claim_app.h od_cmd_app.h od_cmd.h od_caps.h od_reply.h
        od_txq.h od_xfer.h od_spi_raw_app.h od_boot_app.h od_advert.h"
HAL_H="od_hal_nvs.h od_hal_radio.h"
PROTO_H="opendisplay_protocol.h opendisplay_structs.h"
rm -rf "$DST"; mkdir -p "$DST/core" "$DST/hal" "$DST/protocol"
for f in $CORE_C $CORE_H; do cp "$SRC/shared/core/$f" "$DST/core/$f"; done
for f in $HAL_H; do cp "$SRC/shared/hal/$f" "$DST/hal/$f"; done
for f in $PROTO_H; do cp "$SRC/shared/protocol/$f" "$DST/protocol/$f"; done
{
  echo "source: Firmware_Unified shared/ (core, hal, protocol)"
  echo "commit: $(git -C "$SRC" rev-parse HEAD)"
  echo "branch: $(git -C "$SRC" rev-parse --abbrev-ref HEAD)"
  echo "dirty:  $(git -C "$SRC" status --porcelain -- shared | wc -l) file(s) under shared/"
  echo "files:"
  (cd "$DST" && find . -type f ! -name SOURCE | sort | xargs sha256sum)
} > "$DST/SOURCE"
echo "synced $(find "$DST" -type f | wc -l) files into $DST"
