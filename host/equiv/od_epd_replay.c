/* Replay drive packets through the REAL shared/core/od_epd.c against a recording io.
 *
 *   od_epd_replay <packets.bin> <mode_index|sleep> [<W> <H> [<x> <y> <w> <h>]]
 *
 * W/H is the panel size WINDOW/FILL resolve against; x y w h narrows the window to a partial
 * rectangle (od_epd_set_window), as od_display does for a partial update. Built once per
 * target class: the defaults, and BG22's -DOD_EPD_WITH_WINDOW=0 (shared/profiles.cmake). The
 * mode sequence is read from the packet buffer through io->seq_read, as on a target.
 *
 * packets.bin holds framed length-prefixed packets ([number][id][len:2 LE][body]) as a
 * host would append them to a config. The 0xB1/0xAE/0xAF bodies are decoded with the
 * offsets od_epd_cfg.c uses (asserted against opendisplay_structs.h below), the panel is
 * driven through od_epd's public API exactly as od_epd_cfg_stream_write drives it, and
 * every bus event is printed in the grammar of bbep_rec_io.inl, plus:
 *   T <ms>        io->reset(hold)
 *   P <ref> <l>   io->set_pin(ref, level)
 *   I <part> <of> <cs> the walk paused on an image marker (frame bytes are the host's)
 * Exit status: 0 ok, otherwise 10 + (-od_epd rc).
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "od_epd.h"
#include "opendisplay_structs.h"

_Static_assert(sizeof(struct DisplayModeHead) == 37, "0xAE head");
_Static_assert(offsetof(struct DisplayModeHead, seq_len) == 35, "0xAE seq_len");
_Static_assert(offsetof(struct DisplayModeHead, lut_slot) == 19, "0xAE lut_slot");
_Static_assert(offsetof(struct DisplayModeHead, vsn1) == 27, "0xAE vsn1");
_Static_assert(sizeof(struct DisplayLutHead) == 4, "0xAF head");
_Static_assert(sizeof(struct DisplayPanelHead) == 13, "0xB1 head");
_Static_assert(offsetof(struct DisplayPanelHead, code_map) == 7, "0xB1 code_map");
_Static_assert(offsetof(struct DisplayPanelHead, sleep_seq_len) == 12, "0xB1 sleep len");

#define MAXP 48
static struct { uint8_t id; uint16_t len; const uint8_t *body; } pk[MAXP];
static int npk;
static int g_cs = 1;
static int g_in_image;

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }

static void hexline(char tag, const uint8_t *d, size_t n)
{
    if (g_in_image) {
        printf("I %zu %d\n", n, g_cs);
        return;
    }
    putchar(tag);
    putchar(' ');
    for (size_t i = 0; i < n; i++) {
        printf("%02x", d[i]);
    }
    printf(" %d\n", g_cs);
}

static void io_cmd(uint8_t c) { hexline('C', &c, 1); }
static void io_data(const uint8_t *d, size_t n) { if (n) hexline('D', d, n); }
static void io_reset(uint32_t ms) { printf("T %u\n", (unsigned)ms); }
static uint8_t g_idle;
static bool io_busy(void) { printf("B\n"); return g_idle != 0; }
static void io_delay(uint32_t ms) { printf("W %u\n", (unsigned)ms); }

static const uint8_t *mode_body(uint8_t idx, uint16_t *len)
{
    for (int i = 0; i < npk; i++) {
        if (pk[i].id == 0xAE && pk[i].len >= 37 && pk[i].body[1] == idx) {
            *len = pk[i].len;
            return pk[i].body;
        }
    }
    return NULL;
}

static const uint8_t *lut_body(uint8_t slot, uint16_t *len)
{
    for (int i = 0; i < npk; i++) {
        if (pk[i].id == 0xAF && pk[i].len > 4 && pk[i].body[1] == slot) {
            *len = pk[i].len;
            return pk[i].body;
        }
    }
    return NULL;
}

static uint16_t io_seq_read(uint8_t mode, uint16_t off, uint8_t *dst, uint16_t len)
{
    uint16_t bl;
    const uint8_t *b = mode_body(mode, &bl);
    if (!b || 37u + off + len > bl) return 0;
    memcpy(dst, b + 37 + off, len);
    return len;
}

static bool io_mode_read(uint8_t index, od_epd_mode_t *out)
{
    uint16_t bl;
    const uint8_t *h = mode_body(index, &bl);
    if (!h) return false;
    memset(out, 0, sizeof(*out));
    memcpy(out->name, h + 2, 11);
    out->color_scheme = h[14];
    out->passes = h[15];
    out->temp_min_c = (int8_t)h[16];
    out->temp_max_c = (int8_t)h[17];
    out->temp_policy = h[18];
    memcpy(out->lut_slot, h + 19, 8);
    memcpy(out->vsn1, h + 27, 8);
    out->seq_len = rd16(h + 35);
    return out->passes >= 1 && out->passes <= 8 && out->seq_len >= 1 &&
           37u + out->seq_len <= bl;
}

static uint16_t crc16(const uint8_t *d, size_t n)
{
    uint16_t crc = 0xFFFF;
    for (size_t i = 0; i < n; i++) {
        crc ^= (uint16_t)(d[i] << 8);
        for (int b = 0; b < 8; b++) crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021) : (uint16_t)(crc << 1);
    }
    return crc;
}

static bool io_lut_info(uint8_t slot, uint16_t *len_out)
{
    uint16_t bl;
    const uint8_t *b = lut_body(slot, &bl);
    if (!b || bl - 4u > OD_EPD_LUT_BYTES || crc16(b + 4, bl - 4u) != rd16(b + 2)) return false;
    *len_out = (uint16_t)(bl - 4u);
    return true;
}

static uint16_t io_lut_read(uint8_t slot, uint16_t off, uint8_t *dst, uint16_t len)
{
    uint16_t bl;
    const uint8_t *b = lut_body(slot, &bl);
    if (!b || 4u + off + len > bl) return 0;
    memcpy(dst, b + 4 + off, len);
    return len;
}

static bool io_set_pin(uint8_t ref, uint8_t level) { printf("P %u %u\n", ref, level); return true; }
static bool io_cs_select(uint8_t cs) { g_cs = cs ? 2 : 1; return true; }

/* Image markers in a sequence (same grammar as od_epd_validate). */
static int count_images(const uint8_t *s, uint16_t n)
{
    int c = 0;
    uint16_t i = 0;
    while (i < n) {
        if (s[i] != 0) { i = (uint16_t)(i + 1u + s[i]); continue; }
        if (i + 1u >= n) break;
        switch (s[i + 1]) {
            case 0x00: return c;
            case 0x01: case 0x04: i += 2; break;
            case 0x03: c++; i += 2; break;
            case 0x07: c++; i += 4; break;
            case 0x05: case 0x06: case 0x09: i += 4; break;
            case 0x08: i += 3; break;
            case 0x0A: i += 5; break;
            case 0x0B: i += 6; break;
            case 0x0D: i += 5; break;
            case 0x02: case 0x0C: i = (uint16_t)(i + 3u + 2u * s[i + 2]); break;
            default: return -1;
        }
    }
    return c;
}

int main(int argc, char **argv)
{
    static uint8_t blob[16384];
    if (argc != 3 && argc != 5 && argc != 9) {
        fprintf(stderr, "usage: %s packets.bin mode|sleep [W H [x y w h]]\n", argv[0]);
        return 2;
    }
    FILE *f = fopen(argv[1], "rb");
    if (!f) return 2;
    size_t n = fread(blob, 1, sizeof blob, f);
    fclose(f);
    for (size_t o = 0; o + 4 <= n && npk < MAXP;) {
        uint16_t l = rd16(blob + o + 2);
        if (o + 4u + l > n) return 3;
        pk[npk].id = blob[o + 1];
        pk[npk].len = l;
        pk[npk].body = blob + o + 4;
        npk++;
        o += 4u + l;
    }
    od_panel_desc_t d;
    memset(&d, 0, sizeof d);
    for (int i = 0; i < npk; i++) {
        if (pk[i].id == 0xB1 && pk[i].len >= 13) {
            const uint8_t *b = pk[i].body;
            d.busy_usable = (b[1] & 1u) != 0;
            d.busy_idle_level = b[2];
            d.busy_timeout_ms = rd16(b + 3);
            d.busy_fixed_delay_ms = rd16(b + 5);
            memcpy(d.code_map, b + 7, 4);
            d.mode_count = b[11];
            d.sleep_seq_len = b[12];
            if (d.sleep_seq_len > OD_EPD_SLEEP_SEQ_MAX || 13u + d.sleep_seq_len > pk[i].len) return 4;
            memcpy(d.sleep_seq, b + 13, d.sleep_seq_len);
        }
    }
    if (d.mode_count == 0) return 4;
    if (argc >= 5) {
        d.width = (uint16_t)atoi(argv[3]);
        d.height = (uint16_t)atoi(argv[4]);
    }
    g_idle = d.busy_idle_level;

    od_epd_io_t io = {
        .cmd = io_cmd, .data = io_data, .reset = io_reset, .busy_level = io_busy,
        .delay_ms = io_delay, .seq_read = io_seq_read, .mode_read = io_mode_read,
        .lut_info = io_lut_info, .lut_read = io_lut_read,
        .set_pin = io_set_pin, .cs_select = io_cs_select, .read_bytes = NULL,
    };
    static od_epd_t e;
    int rc = od_epd_init(&e, &d, &io);
    if (rc) return 10 - rc;
    if (strcmp(argv[2], "sleep") == 0) {
        rc = od_epd_sleep(&e);
        return rc ? 10 - rc : 0;
    }
    rc = od_epd_select_mode(&e, (uint8_t)atoi(argv[2]));
    if (rc) return 10 - rc;
    if (argc == 9) {
        od_epd_set_window(&e, (uint16_t)atoi(argv[5]), (uint16_t)atoi(argv[6]),
                          (uint16_t)atoi(argv[7]), (uint16_t)atoi(argv[8]));
    }
    for (uint8_t p = 0; p < e.active.passes; p++) {
        printf("M pass %u\n", p);
        rc = od_epd_begin_pass(&e, p);
        if (rc) return 10 - rc;
        uint16_t bl;
        const uint8_t *mb = mode_body(e.mode, &bl);
        int imgs = mb ? count_images(mb + 37, e.seq_len) : -1;
        if (imgs < 1) return 20;
        for (int k = 0; k < imgs; k++) {
            printf("I %u %u %d\n", e.img_part, e.img_of, g_cs);
            if (k + 1 < imgs) {
                rc = od_epd_next_plane(&e);
                if (rc) return 10 - rc;
            }
        }
        rc = od_epd_finish_pass(&e);
        if (rc) return 10 - rc;
    }
    return 0;
}
