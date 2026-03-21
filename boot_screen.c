#include "boot_screen.h"

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "constants.h"
#include "encryption.h" // securityConfig
#include "hal/hal.h"

#include "qr/qrcode.h"

// Keep the URL short so QR version can be fixed.
static const char* LANDING_URL_PREFIX = "https://opendisplay.org/l/?";

// 5x7 font for a subset of ASCII we need (0-9, A-F, and a few uppercase letters + '.')
// Each glyph: 5 columns, LSB is top pixel.
typedef struct { char c; uint8_t col[5]; } Glyph5x7;
static const Glyph5x7 FONT5X7[] = {
    {' ', {0,0,0,0,0}},
    {'.', {0,0,0x40,0,0}},
    {'0', {0x3E,0x51,0x49,0x45,0x3E}},
    {'1', {0x00,0x42,0x7F,0x40,0x00}},
    {'2', {0x62,0x51,0x49,0x49,0x46}},
    {'3', {0x22,0x49,0x49,0x49,0x36}},
    {'4', {0x18,0x14,0x12,0x7F,0x10}},
    {'5', {0x2F,0x49,0x49,0x49,0x31}},
    {'6', {0x3E,0x49,0x49,0x49,0x32}},
    {'7', {0x01,0x71,0x09,0x05,0x03}},
    {'8', {0x36,0x49,0x49,0x49,0x36}},
    {'9', {0x26,0x49,0x49,0x49,0x3E}},
    {'A', {0x7E,0x11,0x11,0x11,0x7E}},
    {'B', {0x7F,0x49,0x49,0x49,0x36}},
    {'C', {0x3E,0x41,0x41,0x41,0x22}},
    {'D', {0x7F,0x41,0x41,0x22,0x1C}},
    {'E', {0x7F,0x49,0x49,0x49,0x41}},
    {'F', {0x7F,0x09,0x09,0x09,0x01}},
    {'G', {0x3E,0x41,0x49,0x49,0x7A}},
    {'I', {0x00,0x41,0x7F,0x41,0x00}},
    {'L', {0x7F,0x40,0x40,0x40,0x40}},
    {'N', {0x7F,0x02,0x0C,0x10,0x7F}},
    {'O', {0x3E,0x41,0x41,0x41,0x3E}},
    {'P', {0x7F,0x09,0x09,0x09,0x06}},
    {'R', {0x7F,0x09,0x19,0x29,0x46}},
    {'S', {0x26,0x49,0x49,0x49,0x32}},
    {'W', {0x3F,0x40,0x38,0x40,0x3F}},
    {'Y', {0x07,0x08,0x70,0x08,0x07}},
};

static const uint8_t* glyph5x7(char c) {
    for (unsigned i = 0; i < sizeof(FONT5X7)/sizeof(FONT5X7[0]); i++) {
        if (FONT5X7[i].c == c) return FONT5X7[i].col;
    }
    return FONT5X7[0].col; // space
}

static void set_pixel_row(uint8_t* row, uint16_t x, bool black) {
    uint16_t byte = x >> 3;
    uint8_t bit = (uint8_t)(0x80 >> (x & 7));
    if (black) row[byte] &= (uint8_t)~bit; // 0 = black
    else row[byte] |= bit;                 // 1 = white
}

static void draw_rect_row(uint8_t* row, uint16_t y, uint16_t x0, uint16_t y0, uint16_t w, uint16_t h, bool black) {
    if (y < y0 || y >= (uint16_t)(y0 + h)) return;
    for (uint16_t x = x0; x < (uint16_t)(x0 + w); x++) set_pixel_row(row, x, black);
}

static void draw_text_row(uint8_t* row, uint16_t y, uint16_t x0, uint16_t y0, const char* s, uint8_t scale, bool black) {
    if (!s || scale == 0) return;
    uint16_t cursor = x0;
    for (const char* p = s; *p; p++) {
        const uint8_t* g = glyph5x7(*p);
        for (uint8_t col = 0; col < 5; col++) {
            uint8_t bits = g[col];
            for (uint8_t gy = 0; gy < 7; gy++) {
                bool on = (bits >> gy) & 1;
                if (!on) continue;
                uint16_t py = (uint16_t)(y0 + (uint16_t)gy * scale);
                if (y < py || y >= (uint16_t)(py + scale)) continue;
                uint16_t px = (uint16_t)(cursor + (uint16_t)col * scale);
                for (uint8_t sx = 0; sx < scale; sx++) {
                    for (uint8_t sy = 0; sy < scale; sy++) {
                        if (y == (uint16_t)(py + sy)) set_pixel_row(row, (uint16_t)(px + sx), black);
                    }
                }
            }
        }
        cursor = (uint16_t)(cursor + (uint16_t)(6 * scale));
    }
}

static void bytes_to_hex(const uint8_t* in, uint16_t len, char* out, uint16_t outSize) {
    static const char* H = "0123456789ABCDEF";
    if (!out || outSize == 0) return;
    uint16_t need = (uint16_t)(len * 2 + 1);
    if (outSize < need) { out[0] = 0; return; }
    for (uint16_t i = 0; i < len; i++) {
        out[i*2 + 0] = H[(in[i] >> 4) & 0x0F];
        out[i*2 + 1] = H[in[i] & 0x0F];
    }
    out[len*2] = 0;
}

static uint16_t base64url_encode(const uint8_t* data, uint16_t len, char* out, uint16_t outSize) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    uint16_t outLen = 0;
    uint16_t i = 0;
    while (i + 3 <= len) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i+1] << 8) | data[i+2];
        i += 3;
        if (outLen + 4 >= outSize) return 0;
        out[outLen++] = tbl[(v >> 18) & 63];
        out[outLen++] = tbl[(v >> 12) & 63];
        out[outLen++] = tbl[(v >> 6) & 63];
        out[outLen++] = tbl[v & 63];
    }
    uint16_t rem = (uint16_t)(len - i);
    if (rem == 1) {
        uint32_t v = ((uint32_t)data[i] << 16);
        if (outLen + 2 >= outSize) return 0;
        out[outLen++] = tbl[(v >> 18) & 63];
        out[outLen++] = tbl[(v >> 12) & 63];
    } else if (rem == 2) {
        uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i+1] << 8);
        if (outLen + 3 >= outSize) return 0;
        out[outLen++] = tbl[(v >> 18) & 63];
        out[outLen++] = tbl[(v >> 12) & 63];
        out[outLen++] = tbl[(v >> 6) & 63];
    }
    if (outLen >= outSize) return 0;
    out[outLen] = 0;
    return outLen;
}

static uint16_t text_width_px(const char* s, uint8_t scale) {
    if (!s || scale == 0) return 0;
    return (uint16_t)(strlen(s) * 6U * scale);
}

bool boot_screen_render(epd_model_t* epd, const struct GlobalConfig* cfg) {
    if (!epd || !epd->drv || !epd->drv->write_ram || !epd->drv->refresh || !cfg || cfg->display_count == 0) return false;

    const struct DisplayConfig* dc = &cfg->displays[0];
    const uint16_t w = epd->width;
    const uint16_t h = epd->height;
    const uint16_t row_bytes = (uint16_t)((w + 7U) / 8U);

    // Build landing payload: res(2) + name(3) + key(16) + mfg(2)
    uint8_t payload[23] = {0};
    uint16_t res = dc->tag_type; // 2 bytes as used by web/l (human-readable hex)
    payload[0] = (uint8_t)((res >> 8) & 0xFF);
    payload[1] = (uint8_t)(res & 0xFF);

    uint32_t id2 = hal_deviceid_word1();
    uint32_t last3 = id2 & 0xFFFFFF;
    payload[2] = (uint8_t)((last3 >> 16) & 0xFF);
    payload[3] = (uint8_t)((last3 >> 8) & 0xFF);
    payload[4] = (uint8_t)(last3 & 0xFF);

    uint8_t key[16] = {0};
    if (securityConfig.flags & SECURITY_FLAG_SHOW_KEY_ON_SCREEN) {
        memcpy(key, securityConfig.encryption_key, 16);
    } else {
        memset(key, 0, 16);
    }
    memcpy(&payload[5], key, 16);

    uint16_t mfg = cfg->manufacturer_data.manufacturer_id;
    payload[21] = (uint8_t)((mfg >> 8) & 0xFF);
    payload[22] = (uint8_t)(mfg & 0xFF);

    char payloadB64[64];
    if (!base64url_encode(payload, sizeof(payload), payloadB64, sizeof(payloadB64))) return false;

    char url[128];
    snprintf(url, sizeof(url), "%s%s", LANDING_URL_PREFIX, payloadB64);

    // Generate QR (fixed "medium" ECC)
    QRCode qr;
    uint8_t qrVersion = 6; // size = 41, fits typical boot URL lengths comfortably
    uint16_t qrBufSize = qrcode_getBufferSize(qrVersion);
    // keep buffer on stack (<= v6 => 41*41 bits => 211 bytes)
    uint8_t qrBuf[256];
    if (qrBufSize > sizeof(qrBuf)) return false;
    if (qrcode_initText(&qr, qrBuf, qrVersion, ECC_MEDIUM, url) != 0) return false;

    const uint8_t qrSize = qr.size;
    const uint8_t quiet = 4;
    const uint16_t qrModules = (uint16_t)(qrSize + (uint8_t)(2 * quiet));

    // Layout: title + name/key on left, QR on right if enough space else centered below.
    uint8_t scaleText = (uint8_t)((w >= 400 && h >= 300) ? 2 : 1);
    uint16_t pad = (uint16_t)(scaleText * 6);

    uint16_t qrPxMax = (uint16_t)((h > w ? w : h) - pad * 2);
    uint16_t modulePx = (uint16_t)(qrPxMax / qrModules);
    if (modulePx < 1) modulePx = 1;
    if (modulePx > 6) modulePx = 6;
    uint16_t qrPx = (uint16_t)(modulePx * qrModules);

    bool qrRight = (w >= (uint16_t)(qrPx + 160));
    uint16_t qrX = qrRight ? (uint16_t)(w - pad - qrPx) : (uint16_t)((w - qrPx) / 2);
    uint16_t qrY = qrRight ? pad : (uint16_t)(h - pad - qrPx);

    char nameLine[16];
    snprintf(nameLine, sizeof(nameLine), "OD%06lX", (unsigned long)last3);
    const char* domainLine = "OPENDISPLAY.ORG";
    char keyHex[33];
    bytes_to_hex(key, 16, keyHex, sizeof(keyHex));

    // Stream rows to RAM
    epd->drv->set_window(epd, 0, 0, w, h);
    uint8_t cfgBegin = EPD_WRITE_CFG_PLANE1_BEGIN;
    uint8_t cfgCont = EPD_WRITE_CFG_PLANE1_CONTINUE;

    bool ok = false;
    uint8_t* row = (uint8_t*)malloc(row_bytes);
    if (!row) return false;

    for (uint16_t y = 0; y < h; y++) {
        memset(row, 0xFF, row_bytes);

        // Simple header separator
        draw_rect_row(row, y, 0, 0, w, (uint16_t)(scaleText * 10), false);

        uint16_t availW = qrRight ? qrX : w;
        uint16_t textY = (uint16_t)(pad);
        if (qrRight) {
            const uint16_t lineH = (uint16_t)(scaleText * 10);
            const uint16_t blockH = (uint16_t)(4 * lineH + 7 * scaleText);
            if (qrPx > blockH) {
                textY = (uint16_t)(qrY + (uint16_t)((qrPx - blockH) / 2));
            } else {
                textY = qrY;
            }
        }

        // Line 1: domain
        uint16_t dW = text_width_px(domainLine, scaleText);
        uint16_t domX = (dW < availW) ? (uint16_t)((availW - dW) / 2) : pad;
        draw_text_row(row, y, domX, textY, domainLine, scaleText, true);

        // Line 2: device name
        uint16_t nW = text_width_px(nameLine, scaleText);
        uint16_t nameX = (nW < availW) ? (uint16_t)((availW - nW) / 2) : pad;
        draw_text_row(row, y, nameX, (uint16_t)(textY + scaleText * 10), nameLine, scaleText, true);

        // (Blank line)
        // Lines 3-4: key hex (no "KEY:" label), split into 2 centered lines
        char k1[17], k2[17];
        memcpy(k1, keyHex, 16); k1[16] = 0;
        memcpy(k2, keyHex + 16, 16); k2[16] = 0;
        uint16_t k1W = text_width_px(k1, scaleText);
        uint16_t k2W = text_width_px(k2, scaleText);
        uint16_t k1X = (k1W < availW) ? (uint16_t)((availW - k1W) / 2) : pad;
        uint16_t k2X = (k2W < availW) ? (uint16_t)((availW - k2W) / 2) : pad;
        draw_text_row(row, y, k1X, (uint16_t)(textY + scaleText * 30), k1, scaleText, true);
        draw_text_row(row, y, k2X, (uint16_t)(textY + scaleText * 40), k2, scaleText, true);

        // QR code (black modules)
        if (y >= qrY && y < (uint16_t)(qrY + qrPx)) {
            uint16_t localY = (uint16_t)(y - qrY);
            uint16_t my = (uint16_t)(localY / modulePx);
            if (my < qrModules) {
                int16_t qy = (int16_t)my - quiet;
                for (uint16_t mx = 0; mx < qrModules; mx++) {
                    int16_t qx = (int16_t)mx - quiet;
                    bool on = false;
                    if (qx >= 0 && qy >= 0 && qx < qrSize && qy < qrSize) {
                        on = qrcode_getModule(&qr, (uint8_t)qx, (uint8_t)qy);
                    }
                    if (!on) continue;
                    uint16_t px0 = (uint16_t)(qrX + mx * modulePx);
                    for (uint16_t px = px0; px < (uint16_t)(px0 + modulePx); px++) {
                        set_pixel_row(row, px, true);
                    }
                }
            }
        }

        // write row chunk
        // write row in chunks (write_ram takes uint8_t len)
        uint8_t cfgByte = (y == 0) ? cfgBegin : cfgCont;
        uint16_t off = 0;
        while (off < row_bytes) {
            uint16_t chunk = row_bytes - off;
            if (chunk > EPD_SPI_CHUNK_SIZE) chunk = EPD_SPI_CHUNK_SIZE;
            if (chunk > 255) chunk = 255;
            epd->drv->write_ram(epd, cfgByte, row + off, (uint8_t)chunk);
            cfgByte = cfgCont;
            off = (uint16_t)(off + chunk);
        }
    }

    // For B/W+Red displays, the second plane (red) needs explicit init.
    // If left untouched, panel RAM can contain random data -> red noise.
    if (epd->color == COLOR_BWR) {
        // Match direct-write inversion rules for plane2.
        bool should_invert_plane2 =
            epd->ic != DRV_IC_UC8151 &&
            epd->ic != DRV_IC_UCVAR43 &&
            epd->id != SSD1619_022_LITE_BW &&
            epd->id != SSD1619_022_LITE_BWR;

        // "White" polarity differs across controllers; the direct-write path inverts
        // plane2 for most BWR panels. For clearing the red plane, use the opposite
        // fill so the *effective* value is white after controller expectations.
        uint8_t fill = should_invert_plane2 ? 0xFF : 0x00;
        epd->drv->set_window(epd, 0, 0, w, h);
        uint8_t cfgBegin2 = EPD_WRITE_CFG_PLANE2_BEGIN;
        uint8_t cfgCont2 = EPD_WRITE_CFG_PLANE2_CONTINUE;

        for (uint16_t y = 0; y < h; y++) {
            memset(row, fill, row_bytes);
            uint8_t cfgByte = (y == 0) ? cfgBegin2 : cfgCont2;
            uint16_t off = 0;
            while (off < row_bytes) {
                uint16_t chunk = row_bytes - off;
                if (chunk > EPD_SPI_CHUNK_SIZE) chunk = EPD_SPI_CHUNK_SIZE;
                if (chunk > 255) chunk = 255;
                epd->drv->write_ram(epd, cfgByte, row + off, (uint8_t)chunk);
                cfgByte = cfgCont2;
                off = (uint16_t)(off + chunk);
            }
        }
    }

    epd->drv->refresh(epd);
    ok = true;
    free(row);
    return ok;
}

