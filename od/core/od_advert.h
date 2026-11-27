/* od_advert.h -- the 16-byte OpenDisplay manufacturer-specific data, encoded once.
 *
 * WHAT THIS IS NOT. od_adv_control decides WHEN to advertise (start, stop, restart, the
 * post-disconnect settle). This decides WHAT the 16 bytes SAY. The two are deliberately
 * separate modules with adjacent names because they have unrelated failure modes: getting
 * od_adv_control wrong makes a device unreachable, getting this wrong makes every host
 * misread a temperature. Neither one calls the other.
 *
 * WHY IT IS WORTH PROMOTING. Three targets encoded this same wire structure three different
 * ways: a struct-and-memcpy on ESP32, hand-placed bytes at [0][1][2][13][14][15] on Nordic
 * whose only specification was a comment citing the ESP32's line numbers, and the same
 * byte-offset form again on Silabs. A comment that points at another target's line numbers IS
 * a shared module -- just one the compiler cannot check. The (t + 40) * 2 temperature encoding
 * and the 511 cap on the 10-bit battery field were written out three times each; they agreed by
 * luck rather than structure, since nothing failed when an edit made them disagree.
 *
 * All three targets call this now; no open-coded copy is left. tests/host/advert_test.c holds
 * the two encoders they shipped and sweeps them against this one -- that sweep is the only thing
 * still able to catch a change here that would alter what a device broadcasts.
 *
 * NO HAL. Inputs are five scalars and an 11-byte block the caller already owns; the output is
 * 16 bytes into the caller's buffer. No allocation, no clock, no storage, no logging -- this
 * is the PURE tier, so every target can take it the day it lands rather than when some HAL
 * arrives. Sensor acquisition, the caching that feeds it, and the publish call all stay in the
 * target where the vendor APIs are.
 *
 * ENDIANNESS IS EXPLICIT. The bytes are written one at a time, little-endian, not by memcpy of
 * a packed struct -- shared/ compiles for three toolchains and must not inherit a host's byte
 * order. The compile-time offsetof checks in od_advert.c tie those explicit writes back to the
 * canonical struct MsdAdvertisement, so a layout change in the protocol header breaks the
 * build here instead of silently changing what goes out over the air.
 */
#ifndef OD_ADVERT_H
#define OD_ADVERT_H

#include <stdbool.h>
#include <stdint.h>

#include "opendisplay_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* sizeof(struct MsdAdvertisement); named because callers pass fixed arrays. */
#define OD_ADVERT_MSD_LEN     16u

/* The config-driven area: button/touch/SHT40/BQ27220 slots at indices the config packets
 * choose. This module copies it verbatim and never interprets it. */
#define OD_ADVERT_DYNAMIC_LEN 11u

/* The legacy advertising PDU every target sends (SECURITY_V2 5.3.3): flags + the local name
 * "OD" + 6 hex + this MSD, in 31 bytes exactly. An AD structure is 1 length + 1 type + payload. */
#define OD_ADVERT_NAME_LEN        8u    /* "OD1A2B3C" */
#define OD_ADVERT_AD_FLAGS_LEN    3u
#define OD_ADVERT_AD_NAME_LEN     (2u + OD_ADVERT_NAME_LEN)
#define OD_ADVERT_AD_MSD_LEN      (2u + OD_ADVERT_MSD_LEN)
#define OD_ADVERT_LEGACY_PDU_MAX  31u
#define OD_ADVERT_ADV_PDU_LEN     (OD_ADVERT_AD_FLAGS_LEN + OD_ADVERT_AD_NAME_LEN + \
                                   OD_ADVERT_AD_MSD_LEN)

/* THE COMPANY ID BELONGS IN THE PROTOCOL HEADER, and is here only because that header is
 * frozen. Today the value is written in four places -- two per-target #defines, one bare
 * literal in the ESP32 builder, and a same-numbered service UUID that is a DIFFERENT constant
 * that merely collides. Move this to opendisplay_protocol.h when the header reopens; until
 * then this is the one definition the shared encoder uses. */
#define OD_ADVERT_COMPANY_ID  0x2446u

/* Battery is 10 bits in units of 10 mV: low 8 in battery_voltage_low, bit 8 in status bit0,
 * bit 9 reserved and always sent 0. So 511 is not a rounding choice, it is the largest value
 * the wire field can carry -- 5.11 V. Anything above it must be clamped rather than allowed to
 * wrap, which would report a flat battery on an over-voltage reading. */
#define OD_ADVERT_BATTERY_10MV_MAX 511u

/* Temperature is one byte of 0.5 C steps biased by -40 C: 0 => -40.0 C, 255 => +87.5 C. */
#define OD_ADVERT_TEMP_MIN_C  (-40.0f)
#define OD_ADVERT_TEMP_MAX_C  (87.5f)

struct od_advert_inputs {
    /* OD_ADVERT_DYNAMIC_LEN bytes. NULL is legal and means "all zero" -- a target whose
     * dynamic area is not configured has nothing to say, and that is not an error. */
    const uint8_t *dynamic;

    /* Degrees C as the chip reports it. Float because all three targets already hold it that
     * way (EMU_TemperatureGet, an SAADC conversion, an ESP32 sensor read) and converting at
     * the boundary would only move the rounding somewhere less visible. One multiply-add on a
     * soft-float part, unchanged from what BG22 pays today. */
    float chip_temperature_c;

    /* Units of 10 mV, i.e. already the wire unit. Clamped here, so a caller holding
     * millivolts should pass od_advert_battery_mv_to_10mv() rather than dividing itself. */
    uint16_t battery_10mv;

    bool reboot_flag;            /* rebooted since the host last read */
    bool connection_requested;   /* device wants the host to connect */
    /* App-layer encryption active: encryption_enabled with a non-zero master key. */
    bool encryption_enabled;

    /* Free-running liveness nibble; only the low 4 bits reach the wire. The caller owns the
     * counter because it is per-device state with a target-specific update cadence -- see
     * od_advert_advance_counter(). */
    uint8_t loop_counter;
};

/* 0.5 C steps biased by -40 C, clamped to the byte.
 *
 * Clamping happens in the FLOAT domain, before the cast. Every shipped copy casts first and
 * clamps the int16_t after, which is undefined behaviour for a reading outside int16_t range
 * -- a sensor fault or an uninitialised float reaches the cast on all three targets today.
 * NaN maps to 0 for the same reason. That is the one deliberate behaviour change in this
 * promotion, and it only affects inputs on which the old code had no defined answer. */
uint8_t od_advert_encode_temperature(float chip_temperature_c);

/* Millivolts to the wire's 10 mV units, clamped to OD_ADVERT_BATTERY_10MV_MAX. */
uint16_t od_advert_battery_10mv_from_mv(uint16_t battery_mv);

/* counter + 1, wrapped to the nibble the status byte carries. */
uint8_t od_advert_advance_counter(uint8_t counter);

/* THE DEVICE-STATE HALF OF THE STATUS BYTE AND THE UNCONFIGURED RULE (SECURITY_V2 5.3), one
 * function for every target so no target computes them itself:
 *   status bit 2 CLAIM_MODE        = claim_mode, OR'd onto the caller's connection_requested;
 *   status bit 3 SESSION_REQUIRED  = session_required (CLAIMED or LOCKED), replacing whatever the
 *                                    caller put in encryption_enabled;
 *   dynamic[11] = 0xFF x 11        when !display_drivable (protocol 2.2 "no display configured";
 *                                    its 3.0 meaning is SECURITY_V2 5.3.2).
 * The state is a plain struct so this stays in the PURE tier; od_advert_device_state_now()
 * (od_advert_state.c, APP_IDENT tier) fills it from the live security state and config. */
struct od_advert_device_state {
    bool claim_mode;         /* od_claim_mode_active() */
    bool session_required;   /* od_sec2_needs_session() */
    bool display_drivable;   /* od_ident_display_drivable() */
};

void od_advert_apply_device_state(struct od_advert_inputs *in,
                                  const struct od_advert_device_state *st);

/* The live state (od_advert_state.c). */
void od_advert_device_state_now(struct od_advert_device_state *out);

/* SECURITY_V2 5.3.2 (od_advert_state.c): at least one display of `cfg` can be driven -- it has
 * drive data (0xB1 + mode-0 0xAE, od_cfg_has_drive_data) or a built-in controller driver (0xB3,
 * OD_IDENT_NATIVE_PANELS). false for NULL, a config that is not loaded, or no display packet.
 * The one predicate behind the MSD FF x 11, dflags HAS_PANEL and READ_IDENT's display state. */
struct od_config;
bool od_ident_display_drivable(const struct od_config *cfg);

/* Encode into out[OD_ADVERT_MSD_LEN]. Writes exactly 16 bytes and touches nothing else.
 *
 * A NULL out is ignored; a NULL in zeroes the buffer rather than leaving whatever the caller
 * last published, because a stale advertisement is indistinguishable to a host from a current
 * one and would misreport a live device. */
void od_advert_build(const struct od_advert_inputs *in, uint8_t *out);

#ifdef __cplusplus
}
#endif

#endif /* OD_ADVERT_H */
