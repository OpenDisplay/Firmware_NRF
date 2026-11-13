/* EPD_service.c -- the OpenDisplay GATT service and the 3.0 command set.
 *
 * Every write to the characteristic is one frame [cmd_hi][cmd_lo][body]. Frames are handled in
 * the BLE event handler, as before, except the refresh after DIRECT_WRITE_END, which runs from
 * main() (ble_epd_service_run): a refresh takes seconds, and while it runs this handler keeps
 * answering, refusing what would disturb the panel (START: PANEL_BUSY, config writes: BUSY). */
#include "EPD_service.h"
#include "od_nrf_build_id.h"

#include <stdlib.h>
#include <string.h>

#include "ble_srv_common.h"
#include "led_control.h"
#include "main.h"
#include "nrf_delay.h"
#include "od_cfg_index.h"
#include "od_cmd_app.h"
#include "od_color.h"
#include "od_config_store.h"
#include "od_display.h"
#include "od_drive_app.h"
#include "od_hal_nvs.h"
#include "od_nrf_glue.h"
#if OD_CAP_NFC
#include "od_nrf_nfc.h"
#endif
#include "od_reply.h"
#include "od_spi_raw_app.h"
#include "od_xfer.h"
#include "sdk_macros.h"

extern struct GlobalConfig globalConfig;

/* SECURITY_V2 6 / od_dispatch: a frame longer than this is refused [FF][cmd][FE]. At this
 * firmware's ATT MTU of 247 a single write carries at most 244 bytes, so the check is a guard
 * for a larger MTU rather than a reachable path today. */
#define OD_FRAME_MAX 244u

static ble_epd_t *s_epd;

/* ---- replies ------------------------------------------------------------------------------- */

static uint32_t send_response(ble_epd_t *p_epd, const uint8_t *response, uint16_t len)
{
    if (p_epd == NULL || response == NULL || len == 0u || !p_epd->is_notification_enabled ||
        p_epd->conn_handle == BLE_CONN_HANDLE_INVALID) {
        return NRF_ERROR_INVALID_STATE;
    }
    return ble_epd_string_send(p_epd, (uint8_t *)(uintptr_t)response, len);
}

static void reply4(uint8_t status, uint8_t op, uint8_t err)
{
    const uint8_t r[4] = { status, op, err, 0x00u };
    (void)send_response(s_epd, r, sizeof r);
}

static void reply2(uint8_t status, uint8_t op)
{
    const uint8_t r[2] = { status, op };
    (void)send_response(s_epd, r, sizeof r);
}

/* The shared handlers (od/core/od_cmd_spi_raw.c) answer through od_reply(); on this target there
 * is one link and no session, so both forms are a notification. */
od_txq_status_t od_reply(od_tx_reservation_t *r, const od_reply_t *rp, const uint8_t *frame,
                         uint16_t len)
{
    (void)r;
    (void)rp;
    return send_response(s_epd, frame, len) == NRF_SUCCESS ? OD_TXQ_OK : OD_TXQ_GONE;
}

od_txq_status_t od_reply_plain(od_tx_reservation_t *r, const od_reply_t *rp, const uint8_t *frame,
                               uint16_t len)
{
    return od_reply(r, rp, frame, len);
}

/* ---- the image transfer (0x0070 / 0x0071 / 0x0072) -------------------------------------------- */

static struct {
    bool active;                  /* START accepted, END not yet */
    volatile bool refresh_pending;/* END accepted; main() runs the refresh */
    volatile bool refreshing;
    uint8_t refresh_mode;
    uint32_t expected;
    uint32_t written;
    od_color_layout_t layout;
} s_x;

bool ble_epd_refresh_busy(void)
{
    return s_x.refresh_pending || s_x.refreshing;
}

static void xfer_abort(void)
{
    if (s_x.active) {
        s_x.active = false;
        od_display_abort();
        od_drive_app_panel_down();
    }
}

/* Called by the shared SPI_RAW handler before it takes the bus. */
void od_xfer_replace_active(void)
{
    xfer_abort();
}

static void handle_direct_write_start(const uint8_t *body, uint16_t len)
{
    const struct DisplayConfig *d = od_drive_app_display();
    od_color_geometry_t g;
    od_display_rc_t rc;

    if (ble_epd_refresh_busy()) {
        reply4(RESP_NACK, RESP_DIRECT_WRITE_START_ACK, OD_ERR_PANEL_BUSY);
        return;
    }
    xfer_abort();
#if OD_CAP_SPI_RAW
    opendisplay_display_spi_raw_close();
#endif
    if (d == NULL) {
        reply2(RESP_NACK, RESP_DIRECT_WRITE_START_ACK);
        return;
    }
    if (!od_nrf_display_drivable()) {
        reply4(RESP_NACK, RESP_DIRECT_WRITE_START_ACK, OD_ERR_NEEDS_MIGRATION);
        return;
    }
    /* A START body of 4+ bytes announces a zlib stream. There is no inflater on this target
     * (no RAM for the window); the config must not advertise compression. */
    (void)body;
    if (len >= 4u ||
        od_color_direct_geometry(d->color_scheme, d->pixel_width, d->pixel_height, &g) !=
            OD_COLOR_OK ||
        g.total_bytes == 0u) {
        reply2(RESP_NACK, RESP_DIRECT_WRITE_START_ACK);
        return;
    }
    rc = od_display_begin_full(&g);
    if (rc != OD_DISPLAY_OK) {
        od_drive_app_panel_down();
        if (rc == OD_DISPLAY_PANEL_BUSY) {
            reply4(RESP_NACK, RESP_DIRECT_WRITE_START_ACK, OD_ERR_PANEL_BUSY);
        } else if (rc == OD_DISPLAY_NEEDS_MIGRATION) {
            reply4(RESP_NACK, RESP_DIRECT_WRITE_START_ACK, OD_ERR_NEEDS_MIGRATION);
        } else {
            reply2(RESP_NACK, RESP_DIRECT_WRITE_START_ACK);
        }
        return;
    }
    s_x.active = true;
    s_x.expected = g.total_bytes;
    s_x.written = 0u;
    s_x.layout = g.layout;
    reply2(RESP_ACK, RESP_DIRECT_WRITE_START_ACK);
}

static void handle_direct_write_data(const uint8_t *body, uint16_t len)
{
    if (!s_x.active || ble_epd_refresh_busy()) {
        reply2(RESP_NACK, RESP_DIRECT_WRITE_DATA_ACK);
        return;
    }
    if (len > 0u) {
        const uint32_t room = s_x.expected - s_x.written;
        const uint32_t n = len < room ? len : room;   /* bytes past the frame are dropped */

        if (n > 0u && !od_display_write(s_x.written, body, n)) {
            xfer_abort();
            reply2(RESP_NACK, RESP_DIRECT_WRITE_DATA_ACK);
            return;
        }
        s_x.written += n;
    }
    reply2(RESP_ACK, RESP_DIRECT_WRITE_DATA_ACK);
}

static void handle_direct_write_end(const uint8_t *body, uint16_t len)
{
    if (!s_x.active || ble_epd_refresh_busy()) {
        return;   /* no transfer: nothing to end (3.0: silent) */
    }
    if (s_x.layout == OD_COLOR_LAYOUT_CONTROLLER_PLANES && s_x.written != s_x.expected) {
        xfer_abort();
        reply2(RESP_NACK, RESP_DIRECT_WRITE_END_ACK);
        return;
    }
    s_x.refresh_mode = (len > 0u && body[0] == 1u) ? 1u : 0u;   /* 1 = fast */
    s_x.active = false;
    s_x.refresh_pending = true;
    reply2(RESP_ACK, RESP_DIRECT_WRITE_END_ACK);
}

static void run_refresh(void)
{
    bool ok;

    s_x.refreshing = true;
    s_x.refresh_pending = false;
    ok = od_display_refresh(s_x.refresh_mode);
    od_drive_app_panel_down();
    s_x.refreshing = false;
    reply2(RESP_ACK, ok ? RESP_DIRECT_WRITE_REFRESH_SUCCESS : RESP_DIRECT_WRITE_REFRESH_TIMEOUT);
}

/* ---- config (0x0040 / 0x0041 / 0x0042 / 0x0045) -------------------------------------------------- */

/* A config write must not change the record a pass is reading drive packets from. */
static bool config_busy(void)
{
    return ble_epd_refresh_busy() || s_x.active || od_display_active();
}

static void config_reload(void)
{
    struct GlobalConfig *g = &globalConfig;
    uint32_t len = OD_CONFIG_MAX_SIZE;

    if (od_config_store_load(g_od_cfg_ws.buffer, &len) == OD_CONFIG_STORE_OK) {
        (void)od_nrf_config_parse(g_od_cfg_ws.buffer, len, g);
    } else {
        memset(g, 0, sizeof *g);
    }
    od_nrf_bind_display(g);
    s_epd->display_config = g->display_count > 0u ? &g->displays[0] : NULL;
#if OD_CAP_NFC
    od_nrf_nfc_init(g);
#endif
    od_nrf_flash_init(g);
    updatemsdata();
}

static void config_store(uint8_t op, uint32_t len)
{
    uint8_t err = OD_ERR_CONFIG_WRITE_FAILED;

    if (od_nrf_config_check(g_od_cfg_ws.buffer, len, &err)) {
        const enum od_config_store_result r =
            od_config_store_save(&g_od_cfg_ws, sizeof g_od_cfg_ws, g_od_cfg_ws.buffer, len);
        if (r == OD_CONFIG_STORE_OK) {
            reply4(RESP_ACK, op, 0x00u);
            config_reload();
            return;
        }
        err = (r == OD_CONFIG_STORE_BUSY) ? OD_ERR_CONFIG_WRITE_BUSY : OD_ERR_CONFIG_WRITE_FAILED;
    }
    reply4(RESP_NACK, op, err);
}

static void handle_config_write(const uint8_t *body, uint16_t len)
{
    if (config_busy()) {
        od_config_asm_reset(&g_od_cfg_ws);
        reply4(RESP_NACK, RESP_CONFIG_WRITE, OD_ERR_CONFIG_WRITE_BUSY);
        return;
    }
    switch (od_config_asm_start(&g_od_cfg_ws, od_span_make(body, len))) {
    case OD_CONFIG_ASM_SINGLE:
        memmove(g_od_cfg_ws.buffer, body, len);
        config_store(RESP_CONFIG_WRITE, len);
        break;
    case OD_CONFIG_ASM_ACCEPTED:
        reply4(RESP_ACK, RESP_CONFIG_WRITE, 0x00u);
        break;
    default:
        reply4(RESP_NACK, RESP_CONFIG_WRITE, OD_ERR_CONFIG_WRITE_FAILED);
        break;
    }
}

static void handle_config_chunk(const uint8_t *body, uint16_t len)
{
    if (config_busy()) {
        od_config_asm_reset(&g_od_cfg_ws);
        reply4(RESP_NACK, RESP_CONFIG_CHUNK, OD_ERR_CONFIG_WRITE_BUSY);
        return;
    }
    switch (od_config_asm_chunk(&g_od_cfg_ws, od_span_make(body, len))) {
    case OD_CONFIG_ASM_ACCEPTED:
        reply4(RESP_ACK, RESP_CONFIG_CHUNK, 0x00u);
        break;
    case OD_CONFIG_ASM_COMPLETE:
        config_store(RESP_CONFIG_CHUNK, g_od_cfg_ws.total_size);
        break;
    default:
        reply4(RESP_NACK, RESP_CONFIG_CHUNK, OD_ERR_CONFIG_WRITE_FAILED);
        break;
    }
}

static void handle_config_clear(void)
{
    if (config_busy()) {
        reply4(RESP_NACK, RESP_CONFIG_CLEAR, OD_ERR_CONFIG_WRITE_BUSY);
        return;
    }
    od_config_asm_reset(&g_od_cfg_ws);
    if (od_config_store_clear() != OD_CONFIG_STORE_OK) {
        reply4(RESP_NACK, RESP_CONFIG_CLEAR, 0x00u);
        return;
    }
    reply4(RESP_ACK, RESP_CONFIG_CLEAR, 0x00u);
    config_reload();
}

/* CONFIG_READ streams the record from flash: [00][40][chunk LE] (+[len LE] on chunk 0) + data,
 * at most MAX_RESPONSE_DATA_SIZE bytes a frame. Chunks that do not fit the SoftDevice's queue are
 * sent from ble_epd_service_run() as notifications complete. */
static struct {
    volatile bool active;
    uint32_t len;
    uint32_t off;
    uint16_t chunk;
} s_rd;

static void config_read_pump(void)
{
    uint8_t f[MAX_RESPONSE_DATA_SIZE];

    while (s_rd.active) {
        uint16_t n = 0;
        uint32_t take;

        f[n++] = RESP_ACK;
        f[n++] = RESP_CONFIG_READ;
        f[n++] = (uint8_t)(s_rd.chunk & 0xFFu);
        f[n++] = (uint8_t)(s_rd.chunk >> 8);
        if (s_rd.chunk == 0u) {
            f[n++] = (uint8_t)(s_rd.len & 0xFFu);
            f[n++] = (uint8_t)(s_rd.len >> 8);
        }
        take = s_rd.len - s_rd.off;
        if (take > (uint32_t)(sizeof f - n)) {
            take = sizeof f - n;
        }
        if (take > 0u && od_hal_nvs_read(OD_CONFIG_STORE_HEADER_SIZE + s_rd.off, f + n, take) != 0) {
            s_rd.active = false;
            return;
        }
        const uint32_t rc = send_response(s_epd, f, (uint16_t)(n + take));
        if (rc == NRF_ERROR_RESOURCES) {
            return;   /* the queue is full: resume on BLE_GATTS_EVT_HVN_TX_COMPLETE */
        }
        if (rc != NRF_SUCCESS) {
            s_rd.active = false;
            return;
        }
        s_rd.off += take;
        s_rd.chunk++;
        if (s_rd.off >= s_rd.len) {
            s_rd.active = false;
        }
    }
}

static void handle_config_read(void)
{
    uint8_t hdr[OD_CONFIG_STORE_HEADER_SIZE];
    uint32_t len = 0;

    s_rd.active = false;
    /* Verified against its CRC before any of it is sent; the CRC is checked over flash in place. */
    if (od_hal_nvs_read(0, hdr, sizeof hdr) == 0) {
        len = (uint32_t)hdr[12] | ((uint32_t)hdr[13] << 8) | ((uint32_t)hdr[14] << 16) |
              ((uint32_t)hdr[15] << 24);
        uint32_t crc = 0;
        uint8_t buf[64];
        for (uint32_t o = 0; len <= OD_CONFIG_MAX_SIZE && o < len; o += sizeof buf) {
            const uint32_t k = (len - o) < sizeof buf ? (len - o) : sizeof buf;
            if (od_hal_nvs_read(OD_CONFIG_STORE_HEADER_SIZE + o, buf, k) != 0) {
                len = 0;
                break;
            }
            crc = od_config_store_crc32_update(crc, buf, k);
        }
        const uint32_t want = (uint32_t)hdr[8] | ((uint32_t)hdr[9] << 8) |
                              ((uint32_t)hdr[10] << 16) | ((uint32_t)hdr[11] << 24);
        if (len > OD_CONFIG_MAX_SIZE || crc != want ||
            !(hdr[0] == 0xEF && hdr[1] == 0xBE && hdr[2] == 0xAD && hdr[3] == 0xDE)) {
            len = 0;
        }
    }
    if (len == 0u) {
        reply4(RESP_NACK, RESP_CONFIG_READ, 0x00u);
        return;
    }
    s_rd.len = len;
    s_rd.off = 0u;
    s_rd.chunk = 0u;
    s_rd.active = true;
    config_read_pump();
}

/* ---- the rest of the command set ---------------------------------------------------------------- */

static void handle_firmware_version(void)
{
    static const char sha[] = OD_NRF_FW_SHA;
    uint8_t r[2 + 3 + 40];
    uint16_t n = 0;
    const uint8_t sl = (uint8_t)(sizeof sha - 1u > 40u ? 40u : sizeof sha - 1u);
    const uint8_t major = OD_NRF_FW_MAJOR, minor = OD_NRF_FW_MINOR;

    r[n++] = RESP_ACK;
    r[n++] = RESP_FIRMWARE_VERSION;
    r[n++] = major;
    r[n++] = minor;
    r[n++] = sl;
    memcpy(r + n, sha, sl);
    n = (uint16_t)(n + sl);
    (void)send_response(s_epd, r, n);
}

static void handle_read_msd(void)
{
    uint8_t r[2 + 16];
    uint8_t n = 0;

    r[0] = RESP_ACK;
    r[1] = RESP_MSD_READ;
    get_msd_payload(&r[2], 16u, &n);
    (void)send_response(s_epd, r, (uint16_t)(2u + n));
}

static void handle_read_ident(void)
{
    uint8_t r[48];
    const uint16_t n = od_nrf_ident(r, sizeof r);

    if (n > 0u) {
        (void)send_response(s_epd, r, n);
    }
}

static void handle_led_activate(const uint8_t *body, uint16_t len)
{
    if (len < 1u) {
        reply4(RESP_NACK, RESP_LED_ACTIVATE_ACK, 0x01u);
        return;
    }
    const uint8_t inst = body[0];
    if (inst >= globalConfig.led_count) {
        reply4(RESP_NACK, RESP_LED_ACTIVATE_ACK, 0x02u);
        return;
    }
    led_activate(inst);
    if (len >= 13u) {
        memcpy(globalConfig.leds[inst].reserved, body + 1, 12);
    }
    led_set_flash_active(true);
    ledFlashLogic();
    led_set_flash_active(false);
    reply4(RESP_ACK, RESP_LED_ACTIVATE_ACK, 0x00u);
}

#if OD_CAP_SPI_RAW
static void handle_spi_raw(const uint8_t *body, uint16_t len)
{
    od_tx_reservation_t r = { 1u, 0u };
    const od_cmd_ctx_t ctx = { { OD_ORIGIN_BLE, 0u }, &r, (uint16_t)(len + 2u), false };

    if (ble_epd_refresh_busy() || od_display_active()) {
        const uint8_t f[5] = { RESP_NACK, RESP_SPI_RAW, OD_ERR_SPI_RAW_PANEL,
                               len > 0u ? body[0] : 0xFFu, 0x00u };
        (void)send_response(s_epd, f, sizeof f);
        return;
    }
    (void)od_cmd_app_spi_raw(&ctx, od_span_make(body, len));
}
#endif

#if OD_CAP_NFC
static void nfc_send(const uint8_t *frame, uint16_t len)
{
    (void)send_response(s_epd, frame, len);
}
#endif

static void dispatch_command(uint16_t cmd, const uint8_t *body, uint16_t len)
{
    switch (cmd) {
    case CMD_CONFIG_READ:        handle_config_read(); break;
    case CMD_CONFIG_WRITE:       handle_config_write(body, len); break;
    case CMD_CONFIG_CHUNK:       handle_config_chunk(body, len); break;
    case CMD_CONFIG_CLEAR:       handle_config_clear(); break;
    case CMD_FIRMWARE_VERSION:   handle_firmware_version(); break;
    case CMD_READ_MSD:           handle_read_msd(); break;
    case CMD_READ_IDENT:         handle_read_ident(); break;
    case CMD_DIRECT_WRITE_START: handle_direct_write_start(body, len); break;
    case CMD_DIRECT_WRITE_DATA:  handle_direct_write_data(body, len); break;
    case CMD_DIRECT_WRITE_END:   handle_direct_write_end(body, len); break;
    case CMD_LED_ACTIVATE:       handle_led_activate(body, len); break;
#if OD_CAP_SPI_RAW
    case CMD_SPI_RAW:            handle_spi_raw(body, len); break;
#endif
#if OD_CAP_NFC
    case CMD_NFC_ENDPOINT:       od_nrf_nfc_frame(body, len, nfc_send); break;
#endif
    case CMD_AUTHENTICATE: {
        /* No security module: the 3.0 answer is NOT_CONFIG, so a v1 client learns there is
         * nothing to unlock. */
        const uint8_t r[3] = { RESP_ACK, RESP_AUTHENTICATE, AUTH_STATUS_NOT_CONFIG };
        (void)send_response(s_epd, r, sizeof r);
        break;
    }
    case CMD_REBOOT:
        nrf_delay_ms(100);
        system_reset();
        break;
    case CMD_ENTER_DFU:
        reply2(RESP_ACK, RESP_ENTER_DFU);
        nrf_delay_ms(100);
        enter_dfu_mode();
        break;
    case CMD_POWER_OFF:
        /* No power latch on this hardware. */
        reply4(RESP_NACK, RESP_POWER_OFF, OD_ERR_POWER_OFF_UNSUPPORTED);
        break;
    case CMD_DEEP_SLEEP:
        /* System OFF: wakes on reset or a configured button only (no timer wake). */
        reply2(RESP_ACK, RESP_DEEP_SLEEP);
        nrf_delay_ms(100);
        enter_deep_sleep();
        break;
    default:
        break;   /* unknown opcode: silence, as the reference firmware */
    }
}

static void epd_service_on_write(const uint8_t *p, uint16_t length)
{
    if (p == NULL || length < 2u) {
        return;
    }
    const uint16_t cmd = (uint16_t)((p[0] << 8) | p[1]);

    od_nrf_bootguard_served();
    if (length > OD_FRAME_MAX) {
        const uint8_t r[3] = { RESP_NACK, (uint8_t)(cmd & 0xFFu), 0xFEu };
        (void)send_response(s_epd, r, sizeof r);
        return;
    }
    dispatch_command(cmd, p + 2, (uint16_t)(length - 2u));
}

/* ---- GATT plumbing ------------------------------------------------------------------------------ */

static void on_write(ble_epd_t *p_epd, ble_evt_t *e)
{
    ble_gatts_evt_write_t *w = &e->evt.gatts_evt.params.write;

    if (w->handle == p_epd->char_handles.cccd_handle && w->len == 2u) {
        p_epd->is_notification_enabled = ble_srv_is_notification_enabled(w->data);
    } else if (w->handle == p_epd->char_handles.value_handle) {
        epd_service_on_write(w->data, w->len);
    }
}

#if defined(S112)
void ble_epd_evt_handler(ble_evt_t const *p_ble_evt, void *p_context)
{
    if (p_context == NULL || p_ble_evt == NULL) {
        return;
    }
    ble_epd_on_ble_evt((ble_epd_t *)p_context, (ble_evt_t *)p_ble_evt);
}
#endif

void ble_epd_on_ble_evt(ble_epd_t *p_epd, ble_evt_t *e)
{
    if (p_epd == NULL || e == NULL) {
        return;
    }
    switch (e->header.evt_id) {
    case BLE_GAP_EVT_CONNECTED:
        p_epd->conn_handle = e->evt.gap_evt.conn_handle;
        rebootFlag = 0;
        break;
    case BLE_GAP_EVT_DISCONNECTED:
        p_epd->conn_handle = BLE_CONN_HANDLE_INVALID;
        p_epd->is_notification_enabled = false;
        s_rd.active = false;
        od_config_asm_reset(&g_od_cfg_ws);
#if OD_CAP_NFC
        od_nrf_nfc_disconnected();
#endif
        if (!ble_epd_refresh_busy()) {
            xfer_abort();
#if OD_CAP_SPI_RAW
            opendisplay_display_spi_raw_close();
#endif
        }
        break;
    case BLE_GATTS_EVT_WRITE:
        on_write(p_epd, e);
        break;
    case BLE_GATTS_EVT_HVN_TX_COMPLETE:
        config_read_pump();
        break;
    default:
        break;
    }
}

void ble_epd_service_run(ble_epd_t *p_epd)
{
    (void)p_epd;
    if (s_x.refresh_pending) {
        run_refresh();
    }
}

static uint32_t epd_service_init(ble_epd_t *p_epd)
{
    ble_uuid_t ble_uuid = {0};
    ble_uuid128_t base_uuid = BLE_UUID_EPD_SVC_BASE;
    ble_add_char_params_t c;
    const uint16_t app_version = APP_VERSION;
    uint8_t app_version_bytes[2] = { (uint8_t)(app_version & 0xFFu), (uint8_t)(app_version >> 8) };

    VERIFY_SUCCESS(sd_ble_uuid_vs_add(&base_uuid, &ble_uuid.type));
    ble_uuid.uuid = BLE_UUID_EPD_SVC;
    VERIFY_SUCCESS(sd_ble_gatts_service_add(BLE_GATTS_SRVC_TYPE_PRIMARY, &ble_uuid,
                                            &p_epd->service_handle));

    memset(&c, 0, sizeof c);
    c.uuid = BLE_UUID_EPD_CHAR;
    c.uuid_type = ble_uuid.type;
    c.max_len = BLE_EPD_MAX_DATA_LEN;
    c.init_len = sizeof(uint8_t);
    c.is_var_len = true;
    c.char_props.notify = 1;
    c.char_props.write = 1;
    c.char_props.write_wo_resp = 1;
    c.read_access = SEC_OPEN;
    c.write_access = SEC_OPEN;
    c.cccd_write_access = SEC_OPEN;
    VERIFY_SUCCESS(characteristic_add(p_epd->service_handle, &c, &p_epd->char_handles));

    memset(&c, 0, sizeof c);
    c.uuid = BLE_UUID_APP_VER;
    c.uuid_type = ble_uuid.type;
    c.max_len = sizeof(uint16_t);
    c.init_len = sizeof(uint16_t);
    c.p_init_value = app_version_bytes;
    c.char_props.read = 1;
    c.read_access = SEC_OPEN;
    return characteristic_add(p_epd->service_handle, &c, &p_epd->app_ver_handles);
}

void ble_epd_sleep_prepare(ble_epd_t *p_epd)
{
    (void)p_epd;
    xfer_abort();
}

uint32_t ble_epd_init(ble_epd_t *p_epd)
{
    if (p_epd == NULL) {
        return NRF_ERROR_NULL;
    }
    s_epd = p_epd;
    p_epd->max_data_len = BLE_EPD_MAX_DATA_LEN;
    p_epd->conn_handle = BLE_CONN_HANDLE_INVALID;
    p_epd->is_notification_enabled = false;
    return epd_service_init(p_epd);
}

uint32_t ble_epd_string_send(ble_epd_t *p_epd, uint8_t *p_string, uint16_t length)
{
    ble_gatts_hvx_params_t hvx;

    if (p_epd->conn_handle == BLE_CONN_HANDLE_INVALID || !p_epd->is_notification_enabled) {
        return NRF_ERROR_INVALID_STATE;
    }
    if (length > p_epd->max_data_len) {
        return NRF_ERROR_INVALID_PARAM;
    }
    memset(&hvx, 0, sizeof hvx);
    hvx.handle = p_epd->char_handles.value_handle;
    hvx.p_data = p_string;
    hvx.p_len = &length;
    hvx.type = BLE_GATT_HVX_NOTIFICATION;
    return sd_ble_gatts_hvx(p_epd->conn_handle, &hvx);
}
