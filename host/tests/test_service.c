/* test_service.c -- host tests for the 3.0 BLE service and the glue under it.
 *
 * EPD/EPD_service.c, glue/ and the vendored od/core are compiled unmodified against the SDK
 * headers (SVCALL_AS_NORMAL_FUNCTION turns the SoftDevice calls into plain functions defined
 * here). The flash is host/tests/fds_sim.c; GPIO and the panel bus are recorded. glue/od_nrf_nvs.c
 * is included below so a simulated reboot can reset its statics.
 *
 * What runs: the opcode table and reply bytes, READ_IDENT and MSD bytes, config write/read/clear
 * (single and chunked, oversize, unknown legacy packet, secrets, busy during a refresh), the
 * upload without and with drive packets through a refresh, SPI_RAW, the oversize-frame NACK,
 * the boot guard, and config storage across a power cut at every flash step. */
#include <setjmp.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "EPD_service.h"
#include "od_nrf_build_id.h"
#include "fds_sim.h"
#include "main.h"
#include "od_advert.h"
#include "od_config_store.h"
#include "od_nrf_glue.h"
#include "opendisplay_protocol.h"
#include "preset_blob.h"   /* generated: PRESET_FRAMED[], the 0xB1 + 0xAE packets of one model */

#include "../../glue/od_nrf_nvs.c"

static int g_fail, g_pass;
#define CHECK(c)                                                                  \
    do {                                                                          \
        if (c) {                                                                  \
            g_pass++;                                                             \
        } else {                                                                  \
            g_fail++;                                                             \
            fprintf(stderr, "%s:%d: CHECK(%s) failed\n", __FILE__, __LINE__, #c); \
        }                                                                         \
    } while (0)

/* ---- what main.c provides on the target ---------------------------------------------------- */
struct GlobalConfig globalConfig;
uint8_t dynamicreturndata[11];
uint8_t rebootFlag = 1;
static int g_dfu, g_reset, g_sleep, g_served;
static uint32_t g_now;

void updatemsdata(void) {}
void get_msd_payload(uint8_t *out, uint8_t max_len, uint8_t *out_len)
{
    uint8_t m[16];
    od_nrf_msd(m, 0, false);
    *out_len = max_len < 16u ? max_len : 16u;
    memcpy(out, m, *out_len);
}
void enter_dfu_mode(void) { g_dfu++; }
void enter_deep_sleep(void) { g_sleep++; }
void system_reset(void) { g_reset++; }
void host_delay_ms(uint32_t ms) { g_now += ms; }
void od_nrf_delay_ms(uint32_t ms) { g_now += ms; }
uint32_t od_nrf_now_ms(void) { return g_now; }
void od_nrf_wdt_feed_now(void) {}
void od_nrf_pump_events(void) { fds_sim_pump(); }
float od_nrf_chip_temp_c(void) { return 21.0f; }
uint16_t od_nrf_battery_mv(void) { return 3000u; }
void od_nrf_bootguard_served(void) { g_served++; }
void led_activate(uint8_t i) { (void)i; }
void ledFlashLogic(void) {}
void led_set_flash_active(bool a) { (void)a; }

/* ---- panel bus and GPIO ---------------------------------------------------------------------- */
static FILE *g_bus;           /* NULL = not recording */
static uint32_t g_busy_level; /* what the BUSY pin reads */
static int g_gpio_inits;

void EPD_GPIO_Load_DisplayConfig(struct DisplayConfig *c, struct GlobalConfig *g) { (void)c; (void)g; }
void EPD_GPIO_Init(void) { g_gpio_inits++; }
void EPD_GPIO_Uninit(void) {}
void EPD_WriteCmd(uint8_t c)
{
    if (g_bus) fprintf(g_bus, "C %02x\n", c);
}
void EPD_WriteData(uint8_t *p, uint8_t n)
{
    if (!g_bus) return;
    fputs("D ", g_bus);
    for (unsigned i = 0; i < n; i++) fprintf(g_bus, "%02x", p[i]);
    fputc('\n', g_bus);
}
void host_gpio_write(uint32_t pin, uint32_t level) { (void)pin; (void)level; }
uint32_t host_gpio_read(uint32_t pin) { (void)pin; return g_busy_level; }

/* ---- SoftDevice -------------------------------------------------------------------------------- */
#define MAXRX 8192
static uint8_t g_rx[MAXRX][256];
static uint16_t g_rx_len[MAXRX];
static int g_nrx;
static int g_hvx_full_after = -1;   /* >= 0: that many more notifications fit, then RESOURCES */

uint32_t sd_ble_gatts_hvx(uint16_t conn, ble_gatts_hvx_params_t const *p)
{
    (void)conn;
    if (g_hvx_full_after == 0) return NRF_ERROR_RESOURCES;
    if (g_hvx_full_after > 0) g_hvx_full_after--;
    if (g_nrx < MAXRX) {
        memcpy(g_rx[g_nrx], p->p_data, *p->p_len);
        g_rx_len[g_nrx] = *p->p_len;
        g_nrx++;
    }
    return NRF_SUCCESS;
}
uint32_t sd_ble_uuid_vs_add(ble_uuid128_t const *b, uint8_t *t) { (void)b; *t = 2; return NRF_SUCCESS; }
uint32_t sd_ble_gatts_service_add(uint8_t t, ble_uuid_t const *u, uint16_t *h)
{
    (void)t; (void)u; *h = 10; return NRF_SUCCESS;
}
uint32_t characteristic_add(uint16_t s, ble_add_char_params_t *p, ble_gatts_char_handles_t *h)
{
    static uint16_t next = 11;
    (void)s; (void)p;
    h->value_handle = next++;
    h->cccd_handle = next++;
    return NRF_SUCCESS;
}
bool ble_srv_is_notification_enabled(uint8_t const *d) { return (d[0] & 1u) != 0u; }

/* ---- driving the service ------------------------------------------------------------------- */
static ble_epd_t m_epd;
static union { ble_evt_t e; uint8_t raw[sizeof(ble_evt_t) + 512]; } g_evt;

static void evt(uint16_t id)
{
    memset(&g_evt, 0, sizeof g_evt);
    g_evt.e.header.evt_id = id;
    g_evt.e.evt.gap_evt.conn_handle = 1;
    ble_epd_on_ble_evt(&m_epd, &g_evt.e);
}

static void write_handle(uint16_t h, const uint8_t *d, uint16_t n)
{
    memset(&g_evt, 0, sizeof g_evt);
    g_evt.e.header.evt_id = BLE_GATTS_EVT_WRITE;
    g_evt.e.evt.gatts_evt.conn_handle = 1;
    g_evt.e.evt.gatts_evt.params.write.handle = h;
    g_evt.e.evt.gatts_evt.params.write.len = n;
    memcpy(g_evt.e.evt.gatts_evt.params.write.data, d, n);
    ble_epd_on_ble_evt(&m_epd, &g_evt.e);
}

/* Send one frame; returns the number of notifications it produced. */
static int tx(uint16_t cmd, const uint8_t *body, uint16_t n)
{
    uint8_t f[512];
    const int before = g_nrx;
    f[0] = (uint8_t)(cmd >> 8);
    f[1] = (uint8_t)cmd;
    if (n) memcpy(f + 2, body, n);
    write_handle(m_epd.char_handles.value_handle, f, (uint16_t)(n + 2u));
    return g_nrx - before;
}

static bool last_is(const uint8_t *want, uint16_t n)
{
    return g_nrx > 0 && g_rx_len[g_nrx - 1] == n && memcmp(g_rx[g_nrx - 1], want, n) == 0;
}
#define LAST(...)                                                    \
    ({                                                               \
        const uint8_t w_[] = { __VA_ARGS__ };                        \
        last_is(w_, sizeof w_);                                      \
    })

static void connect(void)
{
    const uint8_t on[2] = { 1, 0 };
    evt(BLE_GAP_EVT_CONNECTED);
    write_handle(m_epd.char_handles.cccd_handle, on, 2);
}

/* Simulated reboot: flash survives, RAM state does not. */
static void reboot(void)
{
    fds_sim_reboot();
    s_init = false;
    s_pending = false;
    memset(&globalConfig, 0, sizeof globalConfig);
    od_nrf_config_load(&globalConfig);
    m_epd.display_config = globalConfig.display_count ? &globalConfig.displays[0] : NULL;
}

/* ---- config blobs ------------------------------------------------------------------------------ */
struct blob { uint8_t b[2100]; uint16_t n; };

static void blob_start(struct blob *x)
{
    x->n = 3;
    x->b[2] = 1;   /* version */
}
static void blob_fixed(struct blob *x, uint8_t id, const void *body, uint16_t len)
{
    x->b[x->n++] = 0;
    x->b[x->n++] = id;
    memcpy(x->b + x->n, body, len);
    x->n = (uint16_t)(x->n + len);
}
static void blob_raw(struct blob *x, const uint8_t *p, uint16_t len)
{
    memcpy(x->b + x->n, p, len);
    x->n = (uint16_t)(x->n + len);
}
static void blob_end(struct blob *x)
{
    x->b[0] = (uint8_t)x->n;
    x->b[1] = (uint8_t)(x->n >> 8);
    x->b[x->n++] = 0;   /* crc (not checked by the walker) */
    x->b[x->n++] = 0;
}

static struct DisplayConfig display(uint16_t ic, uint16_t w, uint16_t h, uint8_t scheme)
{
    struct DisplayConfig d;
    memset(&d, 0, sizeof d);
    d.panel_ic_type = ic;
    d.pixel_width = w;
    d.pixel_height = h;
    d.color_scheme = scheme;
    d.reset_pin = 3; d.busy_pin = 4; d.dc_pin = 5; d.cs_pin = 6; d.data_pin = 7; d.clk_pin = 8;
    d.cs_pin_2 = 0xFF;
    return d;
}

/* CONFIG_WRITE (single) or CONFIG_WRITE + CONFIG_CHUNKs; returns the last reply's status byte. */
static int write_config(const struct blob *x)
{
    if (x->n <= 200u) {
        tx(CMD_CONFIG_WRITE, x->b, x->n);
        return g_rx[g_nrx - 1][0];
    }
    uint8_t f[202];
    f[0] = (uint8_t)x->n;
    f[1] = (uint8_t)(x->n >> 8);
    memcpy(f + 2, x->b, 200);
    tx(CMD_CONFIG_WRITE, f, 202);
    if (g_rx[g_nrx - 1][0] != RESP_ACK) return g_rx[g_nrx - 1][0];
    for (uint16_t o = 200; o < x->n; o = (uint16_t)(o + 200u)) {
        const uint16_t k = (uint16_t)((x->n - o) < 200u ? (x->n - o) : 200u);
        tx(CMD_CONFIG_CHUNK, x->b + o, k);
        if (g_rx[g_nrx - 1][0] != RESP_ACK) break;
    }
    return g_rx[g_nrx - 1][0];
}

static void make_drivable(struct blob *x)
{
    const struct DisplayConfig d = display(PRESET_IC, PRESET_W, PRESET_H, PRESET_SCHEME);
    blob_start(x);
    blob_fixed(x, 0x20, &d, sizeof d);
    blob_raw(x, PRESET_FRAMED, sizeof PRESET_FRAMED);
    blob_end(x);
}

/* ---- tests ----------------------------------------------------------------------------------- */

static void test_opcode_table(void)
{
    CHECK(tx(0x0099, NULL, 0) == 0);                     /* unknown: silence */
    CHECK(tx(0x0052 + 0x100, NULL, 0) == 0);             /* 0x0152 is not 0x0052 */
    tx(CMD_AUTHENTICATE, NULL, 0);
    CHECK(LAST(0x00, 0x50, AUTH_STATUS_NOT_CONFIG));
    tx(CMD_POWER_OFF, NULL, 0);
    CHECK(LAST(0xFF, 0x52, 0x00, 0x00));
    tx(CMD_FIRMWARE_VERSION, NULL, 0);
    CHECK(g_rx[g_nrx - 1][0] == 0x00 && g_rx[g_nrx - 1][1] == 0x43 && g_rx[g_nrx - 1][2] == 3);
    /* [00][43][major][minor][len][sha]: the build's version and git SHA, not a placeholder */
    CHECK(g_rx[g_nrx - 1][2] == OD_NRF_FW_MAJOR && g_rx[g_nrx - 1][3] == OD_NRF_FW_MINOR &&
          g_rx[g_nrx - 1][4] == strlen(OD_NRF_FW_SHA) &&
          g_rx_len[g_nrx - 1] == 5u + strlen(OD_NRF_FW_SHA) &&
          memcmp(&g_rx[g_nrx - 1][5], OD_NRF_FW_SHA, strlen(OD_NRF_FW_SHA)) == 0);
    tx(CMD_READ_MSD, NULL, 0);
    CHECK(g_rx_len[g_nrx - 1] == 18 && g_rx[g_nrx - 1][1] == RESP_MSD_READ);
    {
        uint8_t big[250] = { 0 };
        tx(0x0071, big, 243);   /* 245-byte frame */
        CHECK(LAST(0xFF, 0x71, 0xFE));
    }
    g_dfu = 0;
    tx(CMD_ENTER_DFU, NULL, 0);
    CHECK(LAST(0x00, 0x51) && g_dfu == 1);
    g_sleep = 0;
    tx(CMD_DEEP_SLEEP, NULL, 0);
    CHECK(LAST(0x00, 0x53) && g_sleep == 1);
    g_reset = 0;
    CHECK(tx(CMD_REBOOT, NULL, 0) == 0 && g_reset == 1);
    CHECK(g_served > 0);
}

static void test_unconfigured(void)
{
    tx(CMD_CONFIG_CLEAR, NULL, 0);
    CHECK(LAST(0x00, 0x45, 0x00, 0x00));
    tx(CMD_READ_IDENT, NULL, 0);
    /* [00][46][minor][target 04][count 0][flags CONFIG_DRIVEN][max 2000][steps 128][esc 0] */
    CHECK(LAST(0x00, 0x46, OD_PROTOCOL_VERSION_MINOR, 0x04, 0x00, 0x01, 0xD0, 0x07, 0x80, 0x00,
               0x00));
    tx(CMD_DIRECT_WRITE_START, NULL, 0);
    CHECK(LAST(0xFF, 0x70));
    tx(CMD_CONFIG_READ, NULL, 0);
    CHECK(LAST(0xFF, 0x40, 0x00, 0x00));
    CHECK(tx(CMD_DIRECT_WRITE_END, NULL, 0) == 0);       /* no transfer: silent */
}

static void test_no_drive_packets(void)
{
    struct blob x;
    const struct DisplayConfig d = display(PRESET_IC, PRESET_W, PRESET_H, PRESET_SCHEME);
    uint8_t m[16];

    blob_start(&x);
    blob_fixed(&x, 0x20, &d, sizeof d);
    blob_end(&x);
    CHECK(write_config(&x) == RESP_ACK);
    tx(CMD_READ_IDENT, NULL, 0);
    CHECK(g_rx[g_nrx - 1][4] == 1);                                    /* one display */
    CHECK(g_rx[g_nrx - 1][5 + 7] == (0x01 | 0x02));                    /* NEEDS_MIGRATION */
    tx(CMD_DIRECT_WRITE_START, NULL, 0);
    CHECK(LAST(0xFF, 0x70, OD_ERR_NEEDS_MIGRATION, 0x00));
    od_nrf_msd(m, 0, false);
    {
        int ff = 0;
        for (int i = 2; i < 13; i++) ff += m[i] == 0xFF;
        CHECK(ff == 11);                                                /* 0xFF x 11 */
    }
}

static int g_img_bytes;

static void test_upload(void)
{
    struct blob x;
    uint8_t chunk[240];

    make_drivable(&x);
    CHECK(write_config(&x) == RESP_ACK);
    tx(CMD_READ_IDENT, NULL, 0);
    CHECK(g_rx[g_nrx - 1][5 + 7] == 0x01);                             /* drivable */
    {
        uint8_t m[16];
        int ff = 0;
        od_nrf_msd(m, 0, false);
        for (int i = 2; i < 13; i++) ff += m[i] == 0xFF;
        CHECK(ff < 11);
    }
    /* Compressed START (a 4-byte size body) is refused: no inflater. */
    {
        const uint8_t z[4] = { 0, 0x40, 0, 0 };
        tx(CMD_DIRECT_WRITE_START, z, 4);
        CHECK(LAST(0xFF, 0x70));
    }
    g_busy_level = PRESET_IDLE;
    g_bus = fopen(getenv("BUS_LOG") ? getenv("BUS_LOG") : "/dev/null", "w");
    tx(CMD_DIRECT_WRITE_START, NULL, 0);
    CHECK(LAST(0x00, 0x70));
    /* A config write while the upload is open is refused as busy. */
    {
        struct blob y;
        make_drivable(&y);
        CHECK(write_config(&y) == RESP_NACK);
        CHECK(g_rx[g_nrx - 1][2] == OD_ERR_CONFIG_WRITE_BUSY);
    }
    for (uint32_t o = 0; o < PRESET_FRAME_BYTES; o += sizeof chunk) {
        const uint32_t k = PRESET_FRAME_BYTES - o < sizeof chunk ? PRESET_FRAME_BYTES - o : sizeof chunk;
        memset(chunk, (o / sizeof chunk) & 1 ? 0xAA : 0x55, sizeof chunk);
        tx(CMD_DIRECT_WRITE_DATA, chunk, (uint16_t)k);
        if (!LAST(0x00, 0x71)) {
            CHECK(!"DATA not acked");
            break;
        }
        g_img_bytes += (int)k;
    }
    tx(CMD_DIRECT_WRITE_END, NULL, 0);
    CHECK(LAST(0x00, 0x72));
    /* END accepted, refresh pending: config writes, SPI_RAW and START are refused as busy. */
    {
        struct blob y;
        make_drivable(&y);
        CHECK(write_config(&y) == RESP_NACK && g_rx[g_nrx - 1][2] == OD_ERR_CONFIG_WRITE_BUSY);
        const uint8_t open[1] = { SPI_RAW_SUB_OPEN };
        tx(CMD_SPI_RAW, open, 1);
        CHECK(LAST(0xFF, 0x84, OD_ERR_SPI_RAW_PANEL, 0x00, 0x00));
        tx(CMD_DIRECT_WRITE_START, NULL, 0);
        CHECK(LAST(0xFF, 0x70, OD_ERR_PANEL_BUSY, 0x00));
    }
    ble_epd_service_run(&m_epd);
    CHECK(LAST(0x00, 0x73));
    if (g_bus) fclose(g_bus);
    g_bus = NULL;
}

/* The boot screen of the drivable config: drawn in full (BOOT_LOG records its panel bus). */
static void test_boot_screen(void)
{
    long bytes = 0;
    char ln[1024];

    g_busy_level = PRESET_IDLE;
    g_bus = tmpfile();
    od_nrf_boot_screen();
    rewind(g_bus);
    {
        FILE *keep = getenv("BOOT_LOG") ? fopen(getenv("BOOT_LOG"), "w") : NULL;
        while (fgets(ln, sizeof ln, g_bus)) {
            if (ln[0] == 'D') bytes += (long)(strlen(ln) - 3u) / 2;
            if (keep) fputs(ln, keep);
        }
        if (keep) fclose(keep);
    }
    fclose(g_bus);
    g_bus = NULL;
    CHECK(bytes >= (long)PRESET_FRAME_BYTES);
}

static void test_config_rules(void)
{
    struct blob x;
    const struct DisplayConfig d = display(PRESET_IC, PRESET_W, PRESET_H, PRESET_SCHEME);

    /* Secrets: a v1 key, a WiFi password. */
    {
        struct SecurityConfig s;
        memset(&s, 0, sizeof s);
        s.encryption_key[3] = 0x42;
        blob_start(&x);
        blob_fixed(&x, 0x20, &d, sizeof d);
        blob_fixed(&x, 0x27, &s, sizeof s);
        blob_end(&x);
        CHECK(write_config(&x) == RESP_NACK && g_rx[g_nrx - 1][2] == 0x10);
    }
    {
        struct WifiConfig w;
        memset(&w, 0, sizeof w);
        w.password[0] = 'p';
        blob_start(&x);
        blob_fixed(&x, 0x26, &w, sizeof w);
        blob_end(&x);
        CHECK(write_config(&x) == RESP_NACK && g_rx[g_nrx - 1][2] == 0x10);
    }
    /* An all-zero security packet is not a secret. */
    {
        struct SecurityConfig s;
        memset(&s, 0, sizeof s);
        make_drivable(&x);
        x.n = (uint16_t)(x.n - 2u);
        blob_fixed(&x, 0x27, &s, sizeof s);
        blob_end(&x);
        CHECK(write_config(&x) == RESP_ACK);
    }
    /* An unknown legacy id would hide the packets after it: refused. */
    {
        const uint8_t junk[4] = { 0, 0x3F, 1, 2 };
        make_drivable(&x);
        x.n = (uint16_t)(x.n - 2u);
        blob_raw(&x, junk, 4);
        blob_end(&x);
        CHECK(write_config(&x) == RESP_NACK);

    }
    /* An unknown 0x80+ packet is stepped over and kept. */
    {
        const uint8_t future[7] = { 0, 0xE7, 3, 0, 9, 9, 9 };
        make_drivable(&x);
        x.n = (uint16_t)(x.n - 2u);
        blob_raw(&x, future, 7);
        blob_end(&x);
        CHECK(write_config(&x) == RESP_ACK);
    }
    /* Oversize: a chunked start declaring 2001 bytes is refused and nothing changes. */
    {
        uint8_t f[202] = { 0xD1, 0x07 };
        tx(CMD_CONFIG_WRITE, f, 202);
        CHECK(LAST(0xFF, 0x41, 0x00, 0x00));
    }
    /* CONFIG_READ returns the stored bytes, chunked, across a full notification queue. */
    {
        uint8_t back[2100];
        uint32_t got = 0, total = 0;
        make_drivable(&x);
        CHECK(write_config(&x) == RESP_ACK);
        const int first = g_nrx;
        g_hvx_full_after = 2;
        tx(CMD_CONFIG_READ, NULL, 0);
        while (g_hvx_full_after == 0) {
            g_hvx_full_after = 2;
            evt(BLE_GATTS_EVT_HVN_TX_COMPLETE);
        }
        g_hvx_full_after = -1;
        for (int i = first; i < g_nrx; i++) {
            const uint16_t chunk = (uint16_t)(g_rx[i][2] | g_rx[i][3] << 8);
            uint16_t hdr = 4;
            CHECK(g_rx[i][0] == 0 && g_rx[i][1] == 0x40 && chunk == i - first);
            if (chunk == 0) {
                total = (uint32_t)(g_rx[i][4] | g_rx[i][5] << 8);
                hdr = 6;
            }
            memcpy(back + got, g_rx[i] + hdr, g_rx_len[i] - hdr);
            got += g_rx_len[i] - hdr;
        }
        CHECK(total == x.n && got == x.n && memcmp(back, x.b, x.n) == 0);
    }
}

static void test_spi_raw(void)
{
    const uint8_t open[2] = { SPI_RAW_SUB_OPEN, 0 };
    const uint8_t cmd[3] = { SPI_RAW_SUB_CMD, 0x12 };
    const uint8_t busy[3] = { SPI_RAW_SUB_BUSY, 100, 0 };
    const uint8_t close[1] = { SPI_RAW_SUB_CLOSE };

    tx(CMD_SPI_RAW, open, 2);
    CHECK(LAST(0x00, 0x84, SPI_RAW_SUB_OPEN));
    tx(CMD_SPI_RAW, cmd, 2);
    CHECK(LAST(0x00, 0x84, SPI_RAW_SUB_CMD));
    tx(CMD_SPI_RAW, busy, 3);
    CHECK(g_rx[g_nrx - 1][0] == 0 && g_rx[g_nrx - 1][2] == SPI_RAW_SUB_BUSY);
    tx(CMD_SPI_RAW, close, 1);
    CHECK(LAST(0x00, 0x84, SPI_RAW_SUB_CLOSE));
}

static void test_bootguard(void)
{
    uint8_t v = 0x00;
    bool dfu = false;
    int boots = 0;
    while (!dfu && boots < 20) {
        v = od_nrf_bootguard_next(v, &dfu);
        boots++;
    }
    CHECK(dfu && boots == 5 && v == 0xB1);
    CHECK((v & 0xF8u) == 0xB0u);                       /* the bootloader's DFU mask */
    v = od_nrf_bootguard_next(0xB1, &dfu);             /* the bootloader leaves 0xB1? count anew */
    CHECK(!dfu && v == 0x51);
    for (unsigned p = 0x50; p < 0x60; p++) {           /* the tag never reads as DFU */
        uint8_t n = od_nrf_bootguard_next((uint8_t)p, &dfu);
        CHECK(dfu || (n & 0xF8u) != 0xB0u);
    }
}

/* Every flash step of an update is cut once; after the reboot the config is the old one or the
 * new one, whole, and exactly one record is left. */
static void big_config(struct blob *x, uint8_t fill)
{
    static uint8_t filler[2000];
    const struct DisplayConfig d = display(PRESET_IC, PRESET_W, PRESET_H, PRESET_SCHEME);
    uint8_t hdr[4] = { 0, 0xE9, 0, 0 };

    memset(filler, fill, sizeof filler);
    blob_start(x);
    blob_fixed(x, 0x20, &d, sizeof d);
    blob_raw(x, PRESET_FRAMED, sizeof PRESET_FRAMED);
    const uint16_t room = (uint16_t)(2000u - 2u - x->n - 4u);
    hdr[2] = (uint8_t)room;
    hdr[3] = (uint8_t)(room >> 8);
    blob_raw(x, hdr, 4);
    blob_raw(x, filler, room);
    blob_end(x);
}

/* Cut every flash step of one config update, once each, and reboot: the stored config is the old
 * one or the new one, whole, and exactly one record is left. `pre` writes run first; with two
 * full-size records before it the update needs a garbage collection, so that is cut too. */
static int cut_sweep(const struct blob *pre, int npre, const struct blob *old, const struct blob *nu)
{
    jmp_buf jb;
    uint8_t buf[2100];
    int cuts = 0;

    fds_sim_jmp = &jb;
    for (int cut = 0; cut < 16; cut++) {
        bool cut_hit = false;

        fds_sim_wipe();
        reboot();
        connect();
        for (int i = 0; i < npre; i++) {
            CHECK(write_config(&pre[i]) == RESP_ACK);
        }
        CHECK(write_config(old) == RESP_ACK);
        if (setjmp(jb) == 0) {
            fds_sim_cut_after(cut);
            (void)write_config(nu);
            fds_sim_cut_after(-1);
        } else {
            cut_hit = true;
        }
        reboot();
        uint32_t len = sizeof buf;
        CHECK(od_config_store_load(buf, &len) == OD_CONFIG_STORE_OK);
        const bool is_old = len == old->n && memcmp(buf, old->b, old->n) == 0;
        const bool is_new = len == nu->n && memcmp(buf, nu->b, nu->n) == 0;
        CHECK(is_old || is_new);
        CHECK(fds_sim_valid_records() == 1);
        CHECK(od_nrf_display_drivable());
        if (!cut_hit) {
            CHECK(is_new);
            break;   /* the update ran to the end without reaching the cut */
        }
        cuts++;
    }
    fds_sim_jmp = NULL;
    return cuts;
}

static void test_power_cuts(void)
{
    struct blob a, b, c;

    make_drivable(&a);
    big_config(&b, 0x5A);
    big_config(&c, 0xA5);
    CHECK(b.n == 2000u && c.n == 2000u);
    const int plain = cut_sweep(NULL, 0, &a, &b);
    const int gc = cut_sweep(&b, 1, &c, &b);     /* b, c stored: the next update must collect */
    printf("power cuts: %d steps cut in a plain update, %d in an update that needs GC\n", plain, gc);
    CHECK(plain == 2 && gc == 3);
    /* Ten full-size rewrites in a row: the dirty space is collected, nothing is refused. */
    fds_sim_wipe();
    reboot();
    connect();
    for (int i = 0; i < 10; i++) {
        CHECK(write_config(i & 1 ? &b : &c) == RESP_ACK);
    }
    CHECK(fds_sim_valid_records() == 1);
}

/* The boot screen reads the device id from FICR (0x10000000): give the host a page there. */
static void map_ficr(void)
{
    void *p = mmap((void *)NRF_FICR_BASE, 4096, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (p != (void *)NRF_FICR_BASE) {
        fprintf(stderr, "cannot map FICR\n");
        exit(2);
    }
    ((volatile uint32_t *)p)[(offsetof(NRF_FICR_Type, DEVICEID) / 4u) + 1u] = 0x00D5AAADu;
}

int main(void)
{
    map_ficr();
    fds_sim_wipe();
    ble_epd_init(&m_epd);
    reboot();
    connect();
    test_opcode_table();
    test_unconfigured();
    test_no_drive_packets();
    test_upload();
    test_boot_screen();
    test_config_rules();
    test_spi_raw();
    test_bootguard();
    test_power_cuts();
    printf("test_service: %d passed, %d failed (image bytes %d)\n", g_pass, g_fail, g_img_bytes);
    return g_fail ? 1 : 0;
}
