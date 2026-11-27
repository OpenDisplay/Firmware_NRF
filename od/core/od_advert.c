/* od_advert.c -- see od_advert.h. Plain C99, no allocation, no HAL. */

#include "od_advert.h"

#include <stddef.h>
#include <string.h>

/* THE WIRE LAYOUT, TIED TO THE CANONICAL STRUCT AT COMPILE TIME.
 *
 * The bytes below are written by explicit index rather than by memcpy of a packed struct, so
 * this file cannot inherit a host's byte order. That freedom is exactly what would let the
 * indices drift away from opendisplay_structs.h without anything noticing, so each index is
 * derived from the struct's own offsetof and asserted here. A layout change in the protocol
 * header then breaks this build instead of quietly changing what a device broadcasts. */
#define OD_ADV_OFF_COMPANY   0u
#define OD_ADV_OFF_DYNAMIC   2u
#define OD_ADV_OFF_TEMP      13u
#define OD_ADV_OFF_BATT_LOW  14u
#define OD_ADV_OFF_STATUS    15u

OD_STATIC_ASSERT(sizeof(struct MsdAdvertisement) == OD_ADVERT_MSD_LEN,
                 "MSD wire size moved");
OD_STATIC_ASSERT(offsetof(struct MsdAdvertisement, company_id) == OD_ADV_OFF_COMPANY,
                 "company_id offset moved");
OD_STATIC_ASSERT(offsetof(struct MsdAdvertisement, dynamic) == OD_ADV_OFF_DYNAMIC,
                 "dynamic offset moved");
OD_STATIC_ASSERT(sizeof(((struct MsdAdvertisement *)0)->dynamic) == OD_ADVERT_DYNAMIC_LEN,
                 "dynamic length moved");
OD_STATIC_ASSERT(offsetof(struct MsdAdvertisement, chip_temperature) == OD_ADV_OFF_TEMP,
                 "chip_temperature offset moved");
OD_STATIC_ASSERT(offsetof(struct MsdAdvertisement, battery_voltage_low) == OD_ADV_OFF_BATT_LOW,
                 "battery_voltage_low offset moved");
OD_STATIC_ASSERT(offsetof(struct MsdAdvertisement, status) == OD_ADV_OFF_STATUS,
                 "status offset moved");

OD_STATIC_ASSERT(OD_ADVERT_ADV_PDU_LEN <= OD_ADVERT_LEGACY_PDU_MAX,
                 "flags + name + MSD must fit one legacy advertising PDU");

uint8_t od_advert_encode_temperature(float chip_temperature_c)
{
    float steps = (chip_temperature_c - OD_ADVERT_TEMP_MIN_C) * 2.0f;

    /* Written as !(steps > 0.0f) rather than (steps <= 0.0f) so NaN lands here too: every
     * comparison against NaN is false, so the negated form is the one that catches it. A
     * sensor that faults to NaN then reports the bottom of the range instead of casting an
     * undefined value into the byte. */
    if (!(steps > 0.0f)) {
        return 0u;
    }
    if (steps >= 255.0f) {
        return 255u;
    }
    return (uint8_t)steps;   /* truncates, matching every shipped copy */
}

uint16_t od_advert_battery_10mv_from_mv(uint16_t battery_mv)
{
    uint16_t v10 = (uint16_t)(battery_mv / 10u);

    if (v10 > OD_ADVERT_BATTERY_10MV_MAX) {
        v10 = OD_ADVERT_BATTERY_10MV_MAX;
    }
    return v10;
}

uint8_t od_advert_advance_counter(uint8_t counter)
{
    return (uint8_t)((counter + 1u) & 0x0Fu);
}

void od_advert_build(const struct od_advert_inputs *in, uint8_t *out)
{
    uint16_t battery_10mv;
    uint8_t status;

    if (out == NULL) {
        return;
    }
    memset(out, 0, OD_ADVERT_MSD_LEN);
    if (in == NULL) {
        return;
    }

    out[OD_ADV_OFF_COMPANY]     = (uint8_t)(OD_ADVERT_COMPANY_ID & 0xFFu);
    out[OD_ADV_OFF_COMPANY + 1] = (uint8_t)((OD_ADVERT_COMPANY_ID >> 8) & 0xFFu);

    /* NULL dynamic leaves the memset zeros -- a target whose dynamic area is unconfigured
     * broadcasts zeros, which is what all three do today. */
    if (in->dynamic != NULL) {
        memcpy(&out[OD_ADV_OFF_DYNAMIC], in->dynamic, OD_ADVERT_DYNAMIC_LEN);
    }

    /* Clamped again here, not merely trusted from od_advert_battery_10mv_from_mv: a caller
     * holding 10 mV units already (the Zephyr battery module does) reaches this field without
     * passing through that helper, and an unclamped value would put bit 9 into the reserved
     * bit rather than being caught. */
    battery_10mv = in->battery_10mv;
    if (battery_10mv > OD_ADVERT_BATTERY_10MV_MAX) {
        battery_10mv = OD_ADVERT_BATTERY_10MV_MAX;
    }

    out[OD_ADV_OFF_TEMP]     = od_advert_encode_temperature(in->chip_temperature_c);
    out[OD_ADV_OFF_BATT_LOW] = (uint8_t)(battery_10mv & 0xFFu);

    status = 0u;
    if ((battery_10mv & 0x100u) != 0u) {
        status |= OD_MSD_STATUS_BATTERY_VOLTAGE_BIT8;
    }
    if (in->reboot_flag) {
        status |= OD_MSD_STATUS_REBOOT_FLAG;
    }
    if (in->connection_requested) {
        status |= OD_MSD_STATUS_CONNECTION_REQUESTED;
    }
    if (in->encryption_enabled) {
        status |= OD_MSD_STATUS_ENCRYPTION_ENABLED;
    }
    status |= (uint8_t)((in->loop_counter << OD_MSD_STATUS_MAIN_LOOP_COUNTER_SHIFT)
                        & OD_MSD_STATUS_MAIN_LOOP_COUNTER_MASK);

    out[OD_ADV_OFF_STATUS] = status;
}

void od_advert_apply_device_state(struct od_advert_inputs *in,
                                  const struct od_advert_device_state *st)
{
    static const uint8_t unconfigured[OD_ADVERT_DYNAMIC_LEN] = {
        0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu
    };

    if (in == NULL || st == NULL) {
        return;
    }
    in->connection_requested = in->connection_requested || st->claim_mode;
    in->encryption_enabled = st->session_required;
    if (!st->display_drivable) {
        in->dynamic = unconfigured;
    }
}
