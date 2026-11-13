/* od_nrf_config.c -- config parsing, the write-time checks, READ_IDENT and the MSD bytes.
 *
 * The config blob is walked by od_config_tlv_walk(), the 3.0 walker every target shares: packets
 * below 0x80 have the fixed sizes of opendisplay_structs.h, packets 0x80 and up carry a length
 * prefix and are stepped over by it, so drive packets (0xAE..0xB1) and anything newer never stop
 * the parse. The drive packets themselves are read in place from flash by od_cfg_index. */
#include <string.h>

#include "od_advert.h"
#include "od_cfg_index.h"
#include "od_config_store.h"
#include "od_config_tlv.h"
#include "od_epd.h"
#include "od_nrf_glue.h"
#include "opendisplay_protocol.h"

struct od_config_asm g_od_cfg_ws;

/* ---- parse ------------------------------------------------------------------------------------ */

#define PUT_SLOT(arr, count, max, body)                                                  \
    do {                                                                                 \
        if ((count) < (max) && (body).n >= sizeof((arr)[0])) {                           \
            memcpy(&(arr)[(count)], (body).p, sizeof((arr)[0]));                         \
            (count)++;                                                                   \
        }                                                                                \
    } while (0)

static bool parse_cb(void *ctx, uint8_t id, od_span_t body)
{
    struct GlobalConfig *g = (struct GlobalConfig *)ctx;

    switch (id) {
    case 0x01:
        if (body.n >= sizeof g->system_config) {
            memcpy(&g->system_config, body.p, sizeof g->system_config);
        }
        break;
    case 0x02:
        if (body.n >= sizeof g->manufacturer_data) {
            memcpy(&g->manufacturer_data, body.p, sizeof g->manufacturer_data);
        }
        break;
    case 0x04:
        if (body.n >= sizeof g->power_option) {
            memcpy(&g->power_option, body.p, sizeof g->power_option);
        }
        break;
    case 0x20:
        PUT_SLOT(g->displays, g->display_count, 4u, body);
        break;
    case 0x21:
        PUT_SLOT(g->leds, g->led_count, 4u, body);
        break;
    case 0x23:
        PUT_SLOT(g->sensors, g->sensor_count, 4u, body);
        break;
    case 0x24:
        PUT_SLOT(g->data_buses, g->data_bus_count, 4u, body);
        break;
    case 0x25:
        PUT_SLOT(g->binary_inputs, g->binary_input_count, 4u, body);
        break;
    case 0x2A:
        PUT_SLOT(g->nfc_configs, g->nfc_config_count, 2u, body);
        break;
    default:
        break;   /* 0x26/0x27 and everything else: sized by the walker, not used here */
    }
    return true;
}

bool od_nrf_config_parse(const uint8_t *blob, uint32_t len, struct GlobalConfig *g)
{
    uint8_t version = 0;

    memset(g, 0, sizeof *g);
    if (blob == NULL || len < OD_CFG_TLV_HEADER_LEN + OD_CFG_TLV_CRC_LEN) {
        return false;
    }
    /* A stored config that runs into an unknown packet keeps what was parsed before it, as 2.x
     * did; the write path (od_nrf_config_check) refuses such a blob before it can be stored. */
    const enum od_config_tlv_result r =
        od_config_tlv_walk(od_span_make(blob, len), parse_cb, g, &version, NULL);
    if (r == OD_CFG_TLV_TOO_SHORT) {
        return false;
    }
    g->version = version;
    g->loaded = true;
    return true;
}

bool od_nrf_config_load(struct GlobalConfig *g)
{
    uint32_t len = OD_CONFIG_MAX_SIZE;
    bool ok = false;

    if (od_config_store_init() == OD_CONFIG_STORE_OK &&
        od_config_store_load(g_od_cfg_ws.buffer, &len) == OD_CONFIG_STORE_OK) {
        ok = od_nrf_config_parse(g_od_cfg_ws.buffer, len, g);
    } else {
        memset(g, 0, sizeof *g);
    }
    od_nrf_bind_display(g);
    return ok;
}

/* ---- the write-time checks (SECURITY_V2 13.7 for a build without the security module) ---------- */

struct check {
    const uint8_t *base;
    uint32_t last_end;
    bool secret;
};

static bool nonzero(const uint8_t *p, uint32_t n)
{
    while (n--) {
        if (*p++ != 0u) {
            return true;
        }
    }
    return false;
}

static bool check_cb(void *ctx, uint8_t id, od_span_t body)
{
    struct check *c = (struct check *)ctx;
    const uint8_t *b = body.p;

    c->last_end = (uint32_t)(body.p - c->base) + (uint32_t)body.n;
    switch (id) {
    case 0x26:   /* WiFi: password[32] at 32 */
        if (body.n >= 64u && nonzero(b + 32, 32u)) {
            c->secret = true;
        }
        break;
    case 0x27:   /* v1 security: enabled, or a non-zero key */
        if (body.n >= 64u && (b[0] != 0u || nonzero(b + 1, 16u))) {
            c->secret = true;
        }
        break;
    case 0x2D:   /* network keys: eik[32] at 8, net_a_adv_key[28] at 40, advertisement_key[20] at 76 */
        if (body.n >= 96u &&
            (nonzero(b + 8, 32u) || nonzero(b + 40, 28u) || nonzero(b + 76, 20u))) {
            c->secret = true;
        }
        break;
    default:
        break;
    }
    return true;
}

bool od_nrf_config_check(const uint8_t *blob, uint32_t len, uint8_t *err)
{
    struct check c = { blob, OD_CFG_TLV_HEADER_LEN, false };
    uint8_t unknown = 0;

    *err = OD_ERR_CONFIG_WRITE_FAILED;
    if (blob == NULL || len > OD_CONFIG_MAX_SIZE ||
        len < OD_CFG_TLV_HEADER_LEN + OD_CFG_TLV_CRC_LEN) {
        return false;
    }
    if (od_config_tlv_walk(od_span_make(blob, len), check_cb, &c, NULL, &unknown) !=
            OD_CFG_TLV_OK ||
        unknown != 0u || c.last_end != len - OD_CFG_TLV_CRC_LEN) {
        return false;
    }
    if (c.secret) {
        *err = OD_ERR_CONFIG_SECRET_NEEDS_CLAIM;
        return false;
    }
    return true;
}

/* ---- READ_IDENT (0x0046) ----------------------------------------------------------------------
 * Byte-compatible with od/core's od_cmd_ident.c, which this firmware does not compile because it
 * reads the shared od_config and security state. NEEDS_MIGRATION comes from the flag cached when
 * the config was bound, so this is safe to answer while a refresh runs. */

extern struct GlobalConfig globalConfig;

#define IDENT_MAX_CONFIG \
    (OD_CONFIG_MAX_SIZE < OD_CONFIG_ASM_MAX_TRANSFERABLE ? OD_CONFIG_MAX_SIZE \
                                                         : OD_CONFIG_ASM_MAX_TRANSFERABLE)

uint16_t od_nrf_ident(uint8_t *rsp, uint16_t cap)
{
    const struct GlobalConfig *g = &globalConfig;
    uint8_t flags = OD_IDENT_FLAG_CONFIG_DRIVEN;
    uint16_t n = 5u;
    uint8_t count = 0;

    if (cap < 5u + 4u * 7u + 6u) {
        return 0;
    }
    rsp[0] = RESP_ACK;
    rsp[1] = RESP_READ_IDENT;
    rsp[2] = (uint8_t)OD_PROTOCOL_VERSION_MINOR;
    rsp[3] = OD_IDENT_TARGET_NRF52811;
    if (g->loaded) {
        for (uint8_t i = 0; i < g->display_count && i < 4u; i++) {
            const struct DisplayConfig *d = &g->displays[i];
            rsp[n++] = (uint8_t)(d->panel_ic_type & 0xFFu);
            rsp[n++] = (uint8_t)(d->panel_ic_type >> 8);
            rsp[n++] = (uint8_t)(d->pixel_width & 0xFFu);
            rsp[n++] = (uint8_t)(d->pixel_width >> 8);
            rsp[n++] = (uint8_t)(d->pixel_height & 0xFFu);
            rsp[n++] = (uint8_t)(d->pixel_height >> 8);
            rsp[n++] = d->color_scheme;
            count++;
        }
        /* Only display 0 is driven on this target; the others never are. */
        if (count > 0u && (!od_nrf_display_drivable() || count > 1u)) {
            flags |= OD_IDENT_FLAG_NEEDS_MIGRATION;
        }
    }
    rsp[4] = count;
    rsp[n++] = flags;   /* no SEC_V2 bits: no security module */
    rsp[n++] = (uint8_t)(IDENT_MAX_CONFIG & 0xFFu);
    rsp[n++] = (uint8_t)(IDENT_MAX_CONFIG >> 8);
    rsp[n++] = (uint8_t)(OD_EPD_MAX_SEQ_STEPS & 0xFFu);
    rsp[n++] = (uint8_t)(OD_EPD_MAX_SEQ_STEPS >> 8);
    rsp[n++] = (uint8_t)(OD_EPD_WITH_WINDOW ? (OD_IDENT_ESC_WINDOW | OD_IDENT_ESC_FILL) : 0u);
    return n;
}

/* ---- MSD ---------------------------------------------------------------------------------------- */

extern uint8_t dynamicreturndata[11];

void od_nrf_msd(uint8_t out[16], uint8_t loop_counter, bool reboot_flag)
{
    struct od_advert_inputs in;
    const struct od_advert_device_state st = {
        .claim_mode = false,
        .session_required = false,
        .display_drivable = od_nrf_display_drivable(),
    };

    memset(&in, 0, sizeof in);
    in.dynamic = dynamicreturndata;
    in.chip_temperature_c = od_nrf_chip_temp_c();
    in.battery_10mv = od_advert_battery_10mv_from_mv(od_nrf_battery_mv());
    in.reboot_flag = reboot_flag;
    in.loop_counter = loop_counter;
    od_advert_apply_device_state(&in, &st);
    od_advert_build(&in, out);
}
