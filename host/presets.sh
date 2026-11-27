# Sourced by host scripts: sets PRESETS to the nRF52811 drive presets.
# They live in Firmware_Unified (panels/nrf52811/presets.yaml is the source,
# panels/generated/drive_presets_nrf52811.json the generated file). Set OD_PRESETS to that file,
# or OD_UNIFIED to a Firmware_Unified checkout; the default is a checkout next to this repo.
if [ -z "${OD_PRESETS:-}" ]; then
  OD_PRESETS=${OD_UNIFIED:-$REPO/../Firmware_Unified}/panels/generated/drive_presets_nrf52811.json
fi
if [ ! -f "$OD_PRESETS" ]; then
  echo "drive presets not found at $OD_PRESETS" >&2
  echo "set OD_PRESETS=<drive_presets_nrf52811.json> or OD_UNIFIED=<Firmware_Unified checkout>" >&2
  exit 2
fi
PRESETS=$OD_PRESETS
