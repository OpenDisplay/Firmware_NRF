/* capture.c -- record the SPI/reset/busy/delay stream the 2.x C panel drivers produced.
 *
 * The 2.x drivers (EPD/UC81xx.c, EPD/SSD16xx.c, EPD/EPD_driver.h from the import commit) are
 * compiled unchanged against this recording mock. main() replays the 2.x direct-write flow of
 * EPD/EPD_service.c for one model: START (GPIO init, drv->init), DATA (plane 1, then for BWR
 * models the window reset and plane 2, 200-byte chunks, with the 2.x per-model inversion),
 * END (PTOUT for UC8176/UC8179, drv->refresh, one read_busy poll, drv->sleep, 200 ms).
 *
 * Output, one event per line, in the event language of the od_epd replay harness:
 *   T ms | C cmd cs | D hex cs | I n cs | B | W ms | N plane <p> inv <0|1> ... | S (sleep begins)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "EPD_driver.h"

static uint8_t g_img[64];          /* every image byte comes from here, so I can tell it apart */
static uint8_t g_inv[64];
static int g_busy_level;           /* the BUSY pin level that means idle for the model's IC */

void rec_delay(uint32_t ms) { if (ms) printf("W %u\n", ms); }
void EPD_GPIO_Load_DisplayConfig(struct DisplayConfig *c, struct GlobalConfig *g) { (void)c; (void)g; }
void EPD_GPIO_Init(void) {}
void EPD_GPIO_Uninit(void) {}
void EPD_SPI_Write(uint8_t *v, uint8_t n) { (void)v; (void)n; }
void EPD_SPI_Read(uint8_t *v, uint8_t n) { memset(v, 0, n); }
void EPD_WriteCmd(uint8_t cmd) { printf("C %02x 1\n", cmd); }
static int is_img(const uint8_t *p) {
    return (p >= g_img && p < g_img + sizeof g_img) || (p >= g_inv && p < g_inv + sizeof g_inv);
}
void EPD_WriteData(uint8_t *v, uint8_t n) {
    if (is_img(v)) { printf("I %u 1\n", n); return; }
    printf("D ");
    for (unsigned i = 0; i < n; i++) printf("%02x", v[i]);
    printf(" 1\n");
}
void EPD_ReadData(uint8_t *v, uint8_t n) { memset(v, 0, n); printf("X read %u\n", n); }
void EPD_WriteByte(uint8_t v) { printf("D %02x 1\n", v); }
uint8_t EPD_ReadByte(void) { printf("X readbyte\n"); return 0; }
void EPD_FillRAM(uint8_t cmd, uint8_t value, uint32_t len) { (void)cmd; (void)value; (void)len; printf("X fill\n"); }
void EPD_Reset(bool status, uint16_t d) { (void)status; printf("T %u\n", d); }
bool EPD_ReadBusy(void) { printf("B\n"); return g_busy_level != 0; }
void EPD_WaitBusy(bool status, uint16_t timeout) { (void)status; (void)timeout; printf("B\n"); }
uint16_t EPD_ReadVoltage(void) { return 3000; }

extern const epd_model_t epd_uc8176_420_bw, epd_uc8176_420_bwr, epd_uc8159_750_bw, epd_uc8159_750_bwr,
    epd_uc8179_750_bw, epd_uc8179_750_bwr, epd_uc8151_029_bw, epd_uc8151_029_bwr, epd_ssd1619_420_bwr,
    epd_ssd1619_420_bw, epd_ssd1619_016_bw, epd_ssd1619_016_bwr, epd_ssd1619_022_bw, epd_ssd1619_022_bwr,
    epd_ssd1619_026_bw, epd_ssd1619_026_bwr, epd_uc8151_027_bw, epd_uc8151_027_bwr, epd_ucvar43_430_bw,
    epd_ucvar43_430_bwr, epd_ssd1619_029_bw, epd_ssd1619_029_bwr, epd_ssd1619_013_bw, epd_ssd1619_013_bwr,
    epd_ssd1619_022_lite_bw, epd_ssd1619_022_lite_bwr, epd_ssd1677_750_bwr, epd_ssd1677_750_bw,
    epd_jd79668_420_bwry, epd_jd79665_750_bwry, epd_jd79665_583_bwry;
static const epd_model_t *const MODELS[] = {
    &epd_uc8176_420_bw, &epd_uc8176_420_bwr, &epd_uc8159_750_bw, &epd_uc8159_750_bwr, &epd_uc8179_750_bw,
    &epd_uc8179_750_bwr, &epd_uc8151_029_bw, &epd_uc8151_029_bwr, &epd_ssd1619_420_bwr, &epd_ssd1619_420_bw,
    &epd_ssd1619_016_bw, &epd_ssd1619_016_bwr, &epd_ssd1619_022_bw, &epd_ssd1619_022_bwr, &epd_ssd1619_026_bw,
    &epd_ssd1619_026_bwr, &epd_uc8151_027_bw, &epd_uc8151_027_bwr, &epd_ucvar43_430_bw, &epd_ucvar43_430_bwr,
    &epd_ssd1619_029_bw, &epd_ssd1619_029_bwr, &epd_ssd1619_013_bw, &epd_ssd1619_013_bwr,
    &epd_ssd1619_022_lite_bw, &epd_ssd1619_022_lite_bwr, &epd_ssd1677_750_bwr, &epd_ssd1677_750_bw,
    &epd_jd79668_420_bwry, &epd_jd79665_750_bwry, &epd_jd79665_583_bwry,
};

/* 2.x EPD_service.c inversion rules, verbatim in meaning. */
static int inv_plane2(const epd_model_t *e) {
    return e->ic != DRV_IC_UC8151 && e->ic != DRV_IC_UCVAR43 && e->id != SSD1619_022_LITE_BW &&
           e->id != SSD1619_022_LITE_BWR && e->id != SSD1619_016_BWR && e->id != SSD1619_420_BWR &&
           e->id != SSD1619_022_BWR && e->id != UC8179_750_BWR;
}
static int inv_plane1(const epd_model_t *e) {
    return e->ic == DRV_IC_UCVAR43 || e->id == SSD1619_013_BW || e->id == SSD1619_013_BWR ||
           e->id == SSD1619_022_LITE_BW || e->id == SSD1619_022_LITE_BWR;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: capture <model id 1..31> | list\n"); return 2; }
    if (strcmp(argv[1], "list") == 0) {
        for (size_t i = 0; i < sizeof MODELS / sizeof MODELS[0]; i++)
            printf("%d %d %d %u %u\n", MODELS[i]->id, MODELS[i]->color, MODELS[i]->ic,
                   MODELS[i]->width, MODELS[i]->height);
        return 0;
    }
    const int id = atoi(argv[1]);
    epd_model_t *e = NULL;
    for (size_t i = 0; i < sizeof MODELS / sizeof MODELS[0]; i++)
        if (MODELS[i]->id == id) e = (epd_model_t *)MODELS[i];
    if (!e) return 3;
    const int uc = e->drv->read_busy != NULL && e->ic < DRV_IC_SSD1619;
    g_busy_level = uc ? 1 : 0;   /* UC81xx: BUSY low = busy, so idle reads 1; SSD16xx idle reads 0 */
    /* START */
    e->drv->init(e);
    /* DATA */
    const int planes = e->color == COLOR_BWR ? 2 : 1;
    const uint32_t per_plane = ((uint32_t)e->width + 7u) / 8u * e->height;
    for (int p = 0; p < planes; p++) {
        const int inv = p == 0 ? inv_plane1(e) : inv_plane2(e);
        printf("N plane %d inv %d bytes %u\n", p, inv, per_plane);
        if (p == 1) e->drv->set_window(e, 0, 0, e->width, e->height);   /* plane switch */
        uint32_t done = 0;
        while (done < per_plane) {
            uint32_t n = per_plane - done;
            if (n > 200u) n = 200u;
            uint8_t cfg;
            if (done == 0) {
                if (p == 1) e->drv->set_window(e, 0, 0, e->width, e->height);
                cfg = p == 0 ? 0x0F : 0x00;   /* EPD_WRITE_CFG_PLANE1/2_BEGIN */
            } else {
                cfg = p == 0 ? 0xFF : 0xF0;   /* ..._CONTINUE */
            }
            /* the chunk pointer only marks the bytes as image; its contents do not matter */
            e->drv->write_ram(e, cfg, inv ? g_inv : g_img, (uint8_t)(n > 64u ? 64u : n));
            /* account for the full chunk with the remaining bytes as further image data */
            if (n > 64u) {
                uint32_t r = n - 64u;
                while (r) { uint8_t k = (uint8_t)(r > 64u ? 64u : r); printf("I %u 1\n", k); r -= k; }
            }
            done += n;
        }
    }
    /* END */
    printf("N end\n");
    if (e->ic == DRV_IC_UC8176 || e->ic == DRV_IC_UC8179) EPD_WriteCmd(UC81xx_PTOUT);
    e->drv->refresh(e);
    (void)e->drv->read_busy(e);
    printf("S\n");
    e->drv->sleep(e);
    rec_delay(200);   /* EPD_SLEEP_DELAY_MS, then GPIO uninit */
    return 0;
}
