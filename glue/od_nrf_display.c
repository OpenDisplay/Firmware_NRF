/* od_nrf_display.c -- the panel side of the glue: the od_epd_cfg bus over this firmware's SPI and
 * GPIO (EPD/EPD_driver.c), the od_drive_app / od_display_app seams od_display.c calls, the
 * CMD_SPI_RAW backend, and the boot screen.
 *
 * There are no panel drivers in this firmware. Everything a panel needs -- reset, init registers,
 * RAM addressing, refresh, sleep -- comes from the drive packets 0xAE..0xB1 in the stored config,
 * interpreted by od/core/od_epd.c. A display without them is not drawn (NEEDS_MIGRATION). */
#include <string.h>

#include "EPD_driver.h"
#include "nrf_gpio.h"
#include "od_boot_app.h"
#include "od_boot_screen.h"
#include "od_cfg_index.h"
#include "od_color.h"
#include "od_display.h"
#include "od_display_app.h"
#include "od_drive_app.h"
#include "od_epd_cfg.h"
#include "od_nrf_build_id.h"
#include "od_nrf_glue.h"
#include "od_spi_raw_app.h"
#include "opendisplay_protocol.h"
#include "qrcode.h"

static const struct DisplayConfig *s_disp;
static const struct GlobalConfig *s_cfg;
static bool s_drivable;
static bool s_panel_up;
static bool s_spi_raw_open;

/* ---- bus ------------------------------------------------------------------------------------- */

static void bus_cmd(uint8_t c)
{
    EPD_WriteCmd(c);
}

static void bus_data(const uint8_t *d, size_t n)
{
    /* EPD_WriteData takes a byte count; the SPI driver moves at most 255 bytes per transfer. */
    while (n > 0u) {
        const uint8_t k = n > 255u ? 255u : (uint8_t)n;

        EPD_WriteData((uint8_t *)(uintptr_t)d, k);
        d += k;
        n -= k;
    }
}

/* Reset: high, low, high, `hold_ms` each, as the 2.x drivers pulsed it. */
static void bus_reset(uint32_t hold_ms)
{
    if (s_disp == NULL || s_disp->reset_pin == 0xFFu) {
        return;
    }
    nrf_gpio_pin_write(s_disp->reset_pin, 1);
    od_nrf_delay_ms(hold_ms);
    nrf_gpio_pin_write(s_disp->reset_pin, 0);
    od_nrf_delay_ms(hold_ms);
    nrf_gpio_pin_write(s_disp->reset_pin, 1);
    od_nrf_delay_ms(hold_ms);
}

static int bus_busy_read(void)
{
    if (s_disp == NULL || s_disp->busy_pin == 0xFFu) {
        return -1;
    }
    return (int)nrf_gpio_pin_read(s_disp->busy_pin);
}

static bool bus_pin_write(uint8_t pin, uint8_t level)
{
    nrf_gpio_cfg_output(pin);
    nrf_gpio_pin_write(pin, level ? 1u : 0u);
    return true;
}

static const od_epd_cfg_bus_t s_bus = {
    .cmd = bus_cmd,
    .data = bus_data,
    .reset = bus_reset,
    .busy_read = bus_busy_read,
    .delay_ms = od_nrf_delay_ms,
    .now_ms = od_nrf_now_ms,
    .faulted = NULL,
    .pin_write = bus_pin_write,
    .cs_select = NULL,
    .read_bytes = NULL,
};

/* ---- display binding --------------------------------------------------------------------------- */

void od_nrf_bind_display(const struct GlobalConfig *g)
{
    s_cfg = g;
    s_disp = (g != NULL && g->loaded && g->display_count > 0u) ? &g->displays[0] : NULL;
    s_drivable = false;
    if (s_disp != NULL) {
        EPD_GPIO_Load_DisplayConfig((struct DisplayConfig *)(uintptr_t)s_disp,
                                    (struct GlobalConfig *)(uintptr_t)g);
        (void)od_cfg_index_build();
        s_drivable = od_cfg_has_drive_data(s_disp->instance_number, s_disp->color_scheme);
    }
}

bool od_nrf_display_configured(void)
{
    return s_disp != NULL;
}

bool od_nrf_display_drivable(void)
{
    return s_drivable;
}

/* ---- od_display_app / od_drive_app ------------------------------------------------------------- */

void od_display_app_phase(od_display_phase_t phase)
{
    (void)phase;
    od_nrf_wdt_feed_now();
}

const struct DisplayConfig *od_drive_app_display(void)
{
    return s_disp;
}

const od_epd_cfg_bus_t *od_drive_app_bus(void)
{
    return &s_bus;
}

bool od_drive_app_panel_up(const struct DisplayConfig *d)
{
    if (d == NULL) {
        return false;
    }
    if (!s_panel_up) {
        EPD_GPIO_Init();
        s_panel_up = true;
    }
    return true;
}

void od_drive_app_panel_down(void)
{
    if (s_panel_up) {
        EPD_GPIO_Uninit();
        s_panel_up = false;
    }
}

void od_drive_app_abort(void)
{
    if (s_spi_raw_open) {
        opendisplay_display_spi_raw_close();
    }
    od_display_abort();
    od_drive_app_panel_down();
}

bool od_drive_app_adopt(const od_color_geometry_t *frame, uint8_t passes, bool compressed,
                        od_span_t tail)
{
    return od_display_adopt_drive(frame, passes, compressed, tail);
}

int8_t od_drive_app_temp_c(void)
{
    const float t = od_nrf_chip_temp_c();

    if (t < -128.0f || t > 126.0f) {
        return OD_DRIVE_TEMP_UNKNOWN;
    }
    return (int8_t)(t + (t >= 0.0f ? 0.5f : -0.5f));
}

/* ---- CMD_SPI_RAW (0x0084) backend ---------------------------------------------------------------- */
#if OD_CAP_SPI_RAW
bool opendisplay_display_spi_raw_is_open(void)
{
    return s_spi_raw_open;
}

int opendisplay_display_spi_raw_open(bool run_panel_init)
{
    od_drive_app_abort();
    if (s_disp == NULL || !od_epd_cfg_load(s_disp, &s_bus)) {
        return -OD_ERR_SPI_RAW_NO_CONFIG;
    }
    if (!od_drive_app_panel_up(s_disp)) {
        return -OD_ERR_SPI_RAW_PANEL;
    }
    /* run_panel_init runs mode 0's head up to its image marker and then hands the bus over. */
    if (run_panel_init) {
        if (!od_epd_cfg_select(0u, NULL) || !od_epd_cfg_begin_pass(0u)) {
            od_drive_app_panel_down();
            return -OD_ERR_SPI_RAW_PANEL;
        }
        od_epd_cfg_raw_detach();
    }
    s_spi_raw_open = true;
    return 0;
}

int opendisplay_display_spi_raw_cmd(const uint8_t *data, uint16_t len)
{
    if (!s_spi_raw_open) {
        return -OD_ERR_SPI_RAW_NOT_OPEN;
    }
    if (data == NULL || len == 0u) {
        return -OD_ERR_SPI_RAW_BAD_ARGS;
    }
    od_epd_cfg_raw_cmd(data, len);
    return 0;
}

int opendisplay_display_spi_raw_data(const uint8_t *data, uint16_t len)
{
    if (!s_spi_raw_open) {
        return -OD_ERR_SPI_RAW_NOT_OPEN;
    }
    if (data == NULL || len == 0u) {
        return -OD_ERR_SPI_RAW_BAD_ARGS;
    }
    od_epd_cfg_raw_data(data, len);
    return 0;
}

int opendisplay_display_spi_raw_busy(uint32_t timeout_ms, uint16_t *elapsed_ms_out,
                                     bool *still_busy_out)
{
    if (!s_spi_raw_open) {
        return -OD_ERR_SPI_RAW_NOT_OPEN;
    }
    if (timeout_ms > 90000u) {
        timeout_ms = 90000u;
    }
    od_epd_cfg_raw_busy(timeout_ms, elapsed_ms_out, still_busy_out);
    return 0;
}

int opendisplay_display_spi_raw_reset(uint8_t hold_ms)
{
    if (!s_spi_raw_open) {
        return -OD_ERR_SPI_RAW_NOT_OPEN;
    }
    od_epd_cfg_raw_reset(hold_ms < 1u ? 1u : (hold_ms > 50u ? 50u : hold_ms));
    return 0;
}

void opendisplay_display_spi_raw_close(void)
{
    if (!s_spi_raw_open) {
        return;
    }
    s_spi_raw_open = false;
    od_epd_cfg_sleep();
    od_drive_app_panel_down();
}
#endif /* OD_CAP_SPI_RAW */

/* ---- boot screen --------------------------------------------------------------------------------
 * A landing-page QR code plus the device name, rendered one 1bpp row at a time and widened to the
 * wire format of the panel's colour scheme. The rows stream through od_display's boot sink, so the
 * frame goes out exactly the way an upload would: the same drive packets, the same markers. */

static const char *const LANDING_URL_PREFIX = "https://opendisplay.org/l/?";

typedef struct { char c; uint8_t col[5]; } glyph_t;
static const glyph_t FONT5X7[] = {
    {' ', {0, 0, 0, 0, 0}},
    {'.', {0, 0, 0x40, 0, 0}},
    {'0', {0x3E, 0x51, 0x49, 0x45, 0x3E}}, {'1', {0x00, 0x42, 0x7F, 0x40, 0x00}},
    {'2', {0x62, 0x51, 0x49, 0x49, 0x46}}, {'3', {0x22, 0x49, 0x49, 0x49, 0x36}},
    {'4', {0x18, 0x14, 0x12, 0x7F, 0x10}}, {'5', {0x2F, 0x49, 0x49, 0x49, 0x31}},
    {'6', {0x3E, 0x49, 0x49, 0x49, 0x32}}, {'7', {0x01, 0x71, 0x09, 0x05, 0x03}},
    {'8', {0x36, 0x49, 0x49, 0x49, 0x36}}, {'9', {0x26, 0x49, 0x49, 0x49, 0x3E}},
    {':', {0x00, 0x36, 0x36, 0x00, 0x00}},
    {'A', {0x7E, 0x11, 0x11, 0x11, 0x7E}}, {'B', {0x7F, 0x49, 0x49, 0x49, 0x36}},
    {'C', {0x3E, 0x41, 0x41, 0x41, 0x22}}, {'D', {0x7F, 0x41, 0x41, 0x22, 0x1C}},
    {'E', {0x7F, 0x49, 0x49, 0x49, 0x41}}, {'F', {0x7F, 0x09, 0x09, 0x09, 0x01}},
    {'G', {0x3E, 0x41, 0x49, 0x49, 0x7A}}, {'I', {0x00, 0x41, 0x7F, 0x41, 0x00}},
    {'L', {0x7F, 0x40, 0x40, 0x40, 0x40}}, {'N', {0x7F, 0x02, 0x0C, 0x10, 0x7F}},
    {'O', {0x3E, 0x41, 0x41, 0x41, 0x3E}}, {'P', {0x7F, 0x09, 0x09, 0x09, 0x06}},
    {'R', {0x7F, 0x09, 0x19, 0x29, 0x46}}, {'S', {0x26, 0x49, 0x49, 0x49, 0x32}},
    {'W', {0x3F, 0x40, 0x38, 0x40, 0x3F}}, {'Y', {0x07, 0x08, 0x70, 0x08, 0x07}},
};

#define BOOT_MAX_W 1024u
#define BOOT_TEXT_LINES 3u   /* domain, OD id, firmware version */
/* "FW:N 3.0.0": the version line of the 3.0 boot screens. The letter names the firmware family
 * the way BG22 shows "FW:S"; N is this nRF5 SDK build. */
#define BOOT_FW_STR_(x) #x
#define BOOT_FW_STR(x) BOOT_FW_STR_(x)
#define BOOT_FW_LINE                                                                              \
    "FW:N " BOOT_FW_STR(OD_NRF_FW_MAJOR) "." BOOT_FW_STR(OD_NRF_FW_MINOR) "."                    \
        BOOT_FW_STR(OD_NRF_FW_PATCH)
static uint8_t s_row[BOOT_MAX_W / 8u];

static const uint8_t *glyph(char c)
{
    for (unsigned i = 0; i < sizeof FONT5X7 / sizeof FONT5X7[0]; i++) {
        if (FONT5X7[i].c == c) {
            return FONT5X7[i].col;
        }
    }
    return FONT5X7[0].col;
}

static void px_black(uint16_t x, uint16_t w)
{
    if (x < w) {
        s_row[x >> 3] &= (uint8_t)~(0x80u >> (x & 7u));
    }
}

static void text_row(uint16_t y, uint16_t x0, uint16_t y0, const char *s, uint8_t scale,
                     uint16_t w)
{
    if (y < y0 || y >= (uint16_t)(y0 + 7u * scale)) {
        return;
    }
    const uint8_t gy = (uint8_t)((y - y0) / scale);

    for (uint16_t cx = x0; *s; s++, cx = (uint16_t)(cx + 6u * scale)) {
        const uint8_t *g = glyph(*s);

        for (uint8_t col = 0; col < 5u; col++) {
            if ((g[col] >> gy) & 1u) {
                for (uint8_t sx = 0; sx < scale; sx++) {
                    px_black((uint16_t)(cx + col * scale + sx), w);
                }
            }
        }
    }
}

static uint16_t text_w(const char *s, uint8_t scale)
{
    return (uint16_t)(strlen(s) * 6u * scale);
}

static uint16_t b64url(const uint8_t *d, uint16_t n, char *out, uint16_t cap)
{
    static const char t[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint16_t o = 0;
    uint32_t acc = 0;
    int bits = 0;

    for (uint16_t i = 0; i < n; i++) {
        acc = (acc << 8) | d[i];
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            if (o + 1u >= cap) {
                return 0;
            }
            out[o++] = t[(acc >> bits) & 63u];
        }
    }
    if (bits > 0) {
        if (o + 1u >= cap) {
            return 0;
        }
        out[o++] = t[(acc << (6 - bits)) & 63u];
    }
    out[o] = 0;
    return o;
}

/* Widen s_row (1bpp, 1 = white) to the wire's packing and push it through the boot sink. */
static bool emit_row(uint8_t bpp, uint32_t row_bytes, bool blank)
{
    uint8_t out[64];
    uint32_t done = 0;

    while (done < row_bytes) {
        uint32_t n = row_bytes - done;

        if (n > sizeof out) {
            n = sizeof out;
        }
        for (uint32_t i = 0; i < n; i++) {
            const uint32_t ob = done + i;
            uint8_t v = 0;

            if (blank) {
                v = 0x00u;   /* the colour plane: no colour */
            } else if (bpp == 1u) {
                v = s_row[ob];
            } else {
                const uint8_t ppb = (uint8_t)(8u / bpp);   /* pixels per output byte */
                for (uint8_t k = 0; k < ppb; k++) {
                    const uint32_t x = ob * ppb + k;
                    const bool white = (s_row[x >> 3] >> (7u - (x & 7u))) & 1u;
                    /* BWRY: 00 black, 01 white. 4bpp: 0 black, 1 white. */
                    v = (uint8_t)((v << bpp) | (white ? 1u : 0u));
                }
            }
            out[i] = v;
        }
        if (od_boot_app_write_row(0u, 0u, out, (uint16_t)n) != 0) {
            return false;
        }
        done += n;
    }
    return true;
}

bool od_boot_screen_render(const struct od_config *cfg, const struct SecurityConfig *security,
                           const struct od_boot_bufs *bufs)
{
    const struct DisplayConfig *d = s_disp;
    od_color_geometry_t g;
    QRCode qr;
    uint8_t qrbuf[256];
    uint8_t payload[23] = {0};
    char b64[48];
    char url[80];
    char name[12];
    const uint32_t last3 = NRF_FICR->DEVICEID[1] & 0xFFFFFFu;

    (void)cfg;
    (void)security;
    (void)bufs;
    if (d == NULL || s_cfg == NULL || d->pixel_width == 0u || d->pixel_width > BOOT_MAX_W ||
        od_color_direct_geometry(d->color_scheme, d->pixel_width, d->pixel_height, &g) !=
            OD_COLOR_OK) {
        return false;
    }
    /* Landing payload: tag type(2) + device id(3) + key(16, none on this build) + manufacturer(2). */
    payload[0] = (uint8_t)(d->legacy_tag_type >> 8);
    payload[1] = (uint8_t)d->legacy_tag_type;
    payload[2] = (uint8_t)(last3 >> 16);
    payload[3] = (uint8_t)(last3 >> 8);
    payload[4] = (uint8_t)last3;
    payload[21] = (uint8_t)(s_cfg->manufacturer_data.manufacturer_id >> 8);
    payload[22] = (uint8_t)s_cfg->manufacturer_data.manufacturer_id;
    if (b64url(payload, sizeof payload, b64, sizeof b64) == 0u ||
        qrcode_getBufferSize(6) > sizeof qrbuf) {
        return false;
    }
    strcpy(url, LANDING_URL_PREFIX);
    strcat(url, b64);
    if (qrcode_initText(&qr, qrbuf, 6, 1 /* ECC_MEDIUM */, url) != 0) {
        return false;
    }
    {
        static const char hex[] = "0123456789ABCDEF";
        name[0] = 'O';
        name[1] = 'D';
        for (int i = 0; i < 6; i++) {
            name[2 + i] = hex[(last3 >> (20 - 4 * i)) & 0xFu];
        }
        name[8] = 0;
    }

    const uint16_t w = d->pixel_width;
    const uint16_t h = d->pixel_height;
    const uint8_t scale = (w >= 400u && h >= 300u) ? 2u : 1u;
    const uint16_t pad = (uint16_t)(scale * 6u);
    const uint16_t modules = (uint16_t)(qr.size + 8u);
    const uint16_t text_h = (uint16_t)(BOOT_TEXT_LINES * 10u * scale);
    uint16_t mpx = (uint16_t)(((h > w ? w : h) - 2u * pad) / modules);
    if (mpx < 1u) {
        mpx = 1u;
    }
    if (mpx > 6u) {
        mpx = 6u;
    }
    const bool right = w >= (uint16_t)(mpx * modules + 160u);
    /* Text above the QR: shrink the QR rather than draw the lines into it. */
    while (!right && mpx > 1u && (uint32_t)mpx * modules + text_h + 3u * pad > h) {
        mpx--;
    }
    const uint16_t qpx = (uint16_t)(mpx * modules);
    const uint16_t qx = right ? (uint16_t)(w - pad - qpx) : (uint16_t)((w - qpx) / 2u);
    const uint16_t qy = right ? pad : (uint16_t)(h > pad + qpx ? h - pad - qpx : 0u);
    const uint16_t avail = right ? qx : w;
    const char *const domain = "OPENDISPLAY.ORG";
    const uint16_t ty = right ? (uint16_t)(qy + (qpx > text_h ? (qpx - text_h) / 2u : 0u))
                              : pad;
    const uint8_t bpp = g.bits_per_pixel ? g.bits_per_pixel : 1u;

    for (uint8_t part = 0; part < g.part_count; part++) {
        const uint32_t rows = g.row_bytes[part] ? g.part_bytes[part] / g.row_bytes[part] : 0u;
        const bool blank = part > 0u && d->color_scheme != OD_COLOR_SCHEME_GRAY4;

        for (uint32_t y = 0; y < rows; y++) {
            memset(s_row, 0xFF, sizeof s_row);
            if (!blank) {
                const uint16_t dw = text_w(domain, scale), nw = text_w(name, scale);
                const uint16_t fw = text_w(BOOT_FW_LINE, scale);
                text_row((uint16_t)y, dw < avail ? (uint16_t)((avail - dw) / 2u) : pad, ty, domain,
                         scale, w);
                text_row((uint16_t)y, nw < avail ? (uint16_t)((avail - nw) / 2u) : pad,
                         (uint16_t)(ty + scale * 10u), name, scale, w);
                text_row((uint16_t)y, fw < avail ? (uint16_t)((avail - fw) / 2u) : pad,
                         (uint16_t)(ty + scale * 20u), BOOT_FW_LINE, scale, w);
                if (y >= qy && y < (uint32_t)(qy + qpx)) {
                    const int16_t my = (int16_t)((y - qy) / mpx) - 4;
                    for (uint16_t mx = 0; mx < modules; mx++) {
                        const int16_t qxm = (int16_t)mx - 4;
                        if (qxm >= 0 && my >= 0 && qxm < qr.size && my < qr.size &&
                            qrcode_getModule(&qr, (uint8_t)qxm, (uint8_t)my)) {
                            for (uint16_t p = 0; p < mpx; p++) {
                                px_black((uint16_t)(qx + mx * mpx + p), w);
                            }
                        }
                    }
                }
            }
            if (!emit_row(part == 0u ? bpp : (g.layout == OD_COLOR_LAYOUT_CONTROLLER_PLANES ? 1u : bpp),
                          g.row_bytes[part], blank)) {
                return false;
            }
        }
    }
    return true;
}

bool od_boot_screen_render_setup(const struct od_config *cfg, enum od_setup_screen kind,
                                 uint32_t code, const struct od_boot_bufs *bufs)
{
    (void)cfg;
    (void)kind;
    (void)code;
    (void)bufs;
    return false;   /* no claim mode on this build */
}

void od_nrf_boot_screen(void)
{
    if (!s_drivable || s_disp == NULL ||
        (s_disp->transmission_modes & OD_TRANSMISSION_MODE_CLEAR_ON_BOOT) != 0u) {
        return;
    }
    (void)od_display_boot(NULL, NULL, NULL);
    od_drive_app_panel_down();
}
