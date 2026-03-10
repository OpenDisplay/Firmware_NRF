#include "EPD_driver.h"

bool UC81xx_ReadBusy(epd_model_t* epd) { return EPD_ReadBusy() == false; }

static void UC81xx_WaitBusy(uint16_t timeout) { EPD_WaitBusy(false, timeout); }

static void UC81xx_PowerOn(epd_model_t* epd) {
    EPD_WriteCmd(UC81xx_PON);
    UC81xx_WaitBusy(200);
}

static void UC81xx_PowerOff(epd_model_t* epd) {
    EPD_WriteCmd(UC81xx_POF);
    if (epd->color == COLOR_BWRY) EPD_WriteByte(0x00);
    UC81xx_WaitBusy(200);
}

// Read temperature from driver chip
int8_t UC81xx_ReadTemp(epd_model_t* epd) {
    EPD_WriteCmd(UC81xx_TSC);
    UC81xx_WaitBusy(100);
    return (int8_t)EPD_ReadByte();
}

void UC81xx_SetWindow(epd_model_t* epd, uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
    switch (epd->ic) {
        case DRV_IC_UC8151:
        case DRV_IC_UCVAR43:
            (void)x;
            (void)y;
            (void)w;
            (void)h;
            break;
        case DRV_IC_JD79668:
        case DRV_IC_JD79665:
            EPD_Write(0x83,  // partial window
                      x / 256, x % 256, (x + w - 1) / 256, (x + w - 1) % 256, y / 256, y % 256, (y + h - 1) / 256,
                      (y + h - 1) % 256, 0x01);
            break;
        default: {
            uint16_t xe = (x + w - 1) | 0x0007;  // byte boundary inclusive (last byte)
            uint16_t ye = y + h - 1;
            x &= 0xFFF8;           // byte boundary
            EPD_Write(UC81xx_PTL,  // partial window
                      x / 256, x % 256, xe / 256, xe % 256, y / 256, y % 256, ye / 256, ye % 256, 0x00);
        } break;
    }
}

void UC81xx_Refresh(epd_model_t* epd) {
    EPD_DEBUG("refresh begin");

    if (epd->ic == DRV_IC_UC8151 || epd->ic == DRV_IC_UCVAR43) {
        // Match variant behavior: power on right before refresh.
        EPD_WriteCmd(UC81xx_PON);
        UC81xx_WaitBusy(200);
    } else {
        UC81xx_SetWindow(epd, 0, 0, epd->width, epd->height);
    }

    EPD_WriteCmd(UC81xx_DRF);
    if (epd->color == COLOR_BWRY) EPD_WriteByte(0x00);
    delay(100);
    UC81xx_WaitBusy(UINT16_MAX);

    EPD_DEBUG("refresh end");
}

void UC81xx_Init(epd_model_t* epd) {
    EPD_Reset(true, 50);
    switch (epd->ic) {
        case DRV_IC_UC8151:
            EPD_Write(0x4D, 0x55);
            EPD_Write(0xF3, 0x0A);
            EPD_Write(0x31, 0x00);
            EPD_Write(UC81xx_BTST, 0xE5, 0x35, 0x3C);
            EPD_Write(UC81xx_CDI, 0x57);
            EPD_Write(UC81xx_PSR, 0x03, 0x09);  // SHL=0 (fixes horizontal mirror vs working code's drawDirectionRight)
            break;
        case DRV_IC_UCVAR43:
            EPD_Write(0xF8, 0x60, 0x05);
            EPD_Write(0xF8, 0xA1, 0x00);
            EPD_Write(0xF8, 0x73, 0x05);
            EPD_Write(0xF8, 0x7E, 0x31);
            EPD_Write(0xF8, 0xB8, 0x80);
            EPD_Write(0xF8, 0x92, 0x00);
            EPD_Write(0xF8, 0x87, 0x11);
            EPD_Write(0xF8, 0x88, 0x06);
            EPD_Write(0xF8, 0xA8, 0x30);
            EPD_Write(UC81xx_TRES, epd->width >> 8, epd->width & 0xFF, epd->height >> 8, epd->height & 0xFF);
            EPD_Write(UC81xx_BTST, 0x57, 0x63, 0x3A);
            EPD_Write(UC81xx_CDI, 0xA7);  // 0x87 | 0x20: set DDX[1] to invert BW data polarity (web sends UC8151-format)
            EPD_Write(UC81xx_PSR, 0x03, 0x09);  // SHL=0: fix horizontal mirror (same fix as UC8151 2.7")
            break;
        case DRV_IC_UC8159:
            EPD_Write(UC81xx_PWR, 0x37, 0x00);
            EPD_Write(UC81xx_PSR, 0xCF, 0x08);
            EPD_Write(UC81xx_PLL, 0x3A);
            EPD_Write(UC81xx_VDCS, 0x28);
            EPD_Write(UC81xx_BTST, 0xc7, 0xcc, 0x15);
            EPD_Write(UC81xx_CDI, 0x77);
            EPD_Write(UC81xx_TCON, 0x22);
            EPD_Write(0x65, 0x00);  // FLASH CONTROL
            EPD_Write(0xe5, 0x03);  // FLASH MODE
            EPD_Write(UC81xx_TRES, epd->width >> 8, epd->width & 0xff, epd->height >> 8, epd->height & 0xff);
            break;
        case DRV_IC_JD79668:
            EPD_Write(0x4D, 0x78);
            EPD_Write(UC81xx_PSR, 0x0F, 0x29);
            EPD_Write(UC81xx_BTST, 0x0D, 0x12, 0x24, 0x25, 0x12, 0x29, 0x10);
            EPD_Write(UC81xx_PLL, 0x08);
            EPD_Write(UC81xx_CDI, 0x37);
            EPD_Write(UC81xx_TRES, epd->width / 256, epd->width % 256, epd->height / 256, epd->height % 256);
            EPD_Write(0xAE, 0xCF);
            EPD_Write(0xB0, 0x13);
            EPD_Write(0xBD, 0x07);
            EPD_Write(0xBE, 0xFE);
            EPD_Write(0xE9, 0x01);
            break;
        case DRV_IC_JD79665:
            EPD_Write(0x4D, 0x78);
            EPD_Write(UC81xx_PSR, 0x2F, 0x29);
            EPD_Write(UC81xx_BTST, 0x0F, 0x8B, 0x93, 0xA1);
            EPD_Write(UC81xx_TSE, 0x00);
            EPD_Write(UC81xx_CDI, 0x37);
            EPD_Write(UC81xx_TCON, 0x02, 0x02);
            EPD_Write(UC81xx_TRES, epd->width / 256, epd->width % 256, epd->height / 256, epd->height % 256);
            EPD_Write(0x62, 0x98, 0x98, 0x98, 0x75, 0xCA, 0xB2, 0x98, 0x7E);
            if (epd->id == JD79665_750_BWRY)
                EPD_Write(UC81xx_GSST, 0x00, 0x00, 0x00, 0x00);
            else
                EPD_Write(UC81xx_GSST, 0x00, 0x10, 0x00, 0x00);
            EPD_Write(0xE7, 0x1C);
            EPD_Write(UC81xx_PWS, 0x00);
            EPD_Write(0xE9, 0x01);
            EPD_Write(UC81xx_PLL, 0x08);
            break;
        default:
            EPD_Write(UC81xx_PSR, epd->color == COLOR_BWR ? 0x0F : 0x1F);
            EPD_Write(UC81xx_CDI, epd->color == COLOR_BWR ? 0x77 : 0x97);
            break;
    }
    UC81xx_PowerOn(epd);
    UC81xx_SetWindow(epd, 0, 0, epd->width, epd->height);
}

void UC81xx_Clear(epd_model_t* epd, bool refresh) {
    uint32_t wb = (epd->width + 7) / 8;
    switch (epd->ic) {
        case DRV_IC_UC8159:
            EPD_WriteCmd(UC81xx_DTM1);
            for (uint32_t j = 0; j < epd->height; j++) {
                for (uint32_t i = 0; i < wb; i++) {
                    for (uint8_t k = 0; k < 4; k++) {
                        EPD_WriteByte(0x33);
                    }
                }
            }
            break;
        case DRV_IC_JD79668:
        case DRV_IC_JD79665:
            wb = (epd->width + 3) / 4;  // 2bpp
            EPD_WriteCmd(UC81xx_DTM1);
            for (uint16_t i = 0; i < epd->height; i++) {
                for (uint16_t j = 0; j < wb; j++) {
                    EPD_WriteByte(0x55);
                }
            }
            break;
        default:
            EPD_FillRAM(UC81xx_DTM1, 0xFF, wb * epd->height);
            EPD_FillRAM(UC81xx_DTM2, 0xFF, wb * epd->height);
            break;
    }
    if (refresh) UC81xx_Refresh(epd);
}

void UC81xx_WriteRam(epd_model_t* epd, uint8_t cfg, uint8_t* data, uint8_t len) {
    bool begin = (cfg >> 4) == 0x00;
    bool black = (cfg & 0x0F) == 0x0F;
    if (begin) {
        if (epd->ic == DRV_IC_UC8176 || epd->ic == DRV_IC_UC8179) {
            EPD_WriteCmd(UC81xx_PTIN);  // partial in
        }
        UC81xx_SetWindow(epd, 0, 0, epd->width, epd->height);
    }
    switch (epd->ic) {
        case DRV_IC_UC8151:
        case DRV_IC_UCVAR43:
            if (begin) {
                if (black) EPD_WriteByte(0x00);
                EPD_WriteCmd(black ? UC81xx_DTM1 : UC81xx_DTM2);
            }
            EPD_WriteData(data, len);
            break;
        case DRV_IC_UC8159:
        case DRV_IC_JD79665:
        case DRV_IC_JD79668:
            if (begin) EPD_WriteCmd(UC81xx_DTM1);
            EPD_WriteData(data, len);
            break;
        default:
            if (begin) {
                if (epd->color == COLOR_BWR)
                    EPD_WriteCmd(black ? UC81xx_DTM1 : UC81xx_DTM2);
                else
                    EPD_WriteCmd(UC81xx_DTM2);
            }
            EPD_WriteData(data, len);
            break;
    }
}

void UC81xx_Sleep(epd_model_t* epd) {
    if (epd->ic == DRV_IC_UC8151) {
        EPD_WriteCmd(UC81xx_POF);
        UC81xx_WaitBusy(500);
        EPD_Write(UC81xx_DSLP, 0xA5);
        delay(200);
    } else {
        UC81xx_PowerOff(epd);
        delay(100);
        EPD_Write(UC81xx_DSLP, 0xA5);
    }
}

static const epd_driver_t epd_drv_uc81xx = {
    .init = UC81xx_Init,
    .clear = UC81xx_Clear,
    .write_ram = UC81xx_WriteRam,
    .refresh = UC81xx_Refresh,
    .sleep = UC81xx_Sleep,
    .read_temp = UC81xx_ReadTemp,
    .read_busy = UC81xx_ReadBusy,
    .set_window = UC81xx_SetWindow,
};

const epd_model_t epd_uc8176_420_bw = {UC8176_420_BW, COLOR_BW, &epd_drv_uc81xx, DRV_IC_UC8176, 400, 300};
const epd_model_t epd_uc8176_420_bwr = {UC8176_420_BWR, COLOR_BWR, &epd_drv_uc81xx, DRV_IC_UC8176, 400, 300};
const epd_model_t epd_uc8159_750_bw = {UC8159_750_LOW_BW, COLOR_BW, &epd_drv_uc81xx, DRV_IC_UC8159, 640, 384};
const epd_model_t epd_uc8159_750_bwr = {UC8159_750_LOW_BWR, COLOR_BWR, &epd_drv_uc81xx, DRV_IC_UC8159, 640, 384};
const epd_model_t epd_uc8179_750_bw = {UC8179_750_BW, COLOR_BW, &epd_drv_uc81xx, DRV_IC_UC8179, 800, 480};
const epd_model_t epd_uc8179_750_bwr = {UC8179_750_BWR, COLOR_BWR, &epd_drv_uc81xx, DRV_IC_UC8179, 800, 480};
const epd_model_t epd_jd79668_420_bwry = {JD79668_420_BWRY, COLOR_BWRY, &epd_drv_uc81xx, DRV_IC_JD79668, 400, 300};
const epd_model_t epd_jd79665_750_bwry = {JD79665_750_BWRY, COLOR_BWRY, &epd_drv_uc81xx, DRV_IC_JD79665, 800, 480};
const epd_model_t epd_jd79665_583_bwry = {JD79665_583_BWRY, COLOR_BWRY, &epd_drv_uc81xx, DRV_IC_JD79665, 648, 480};
const epd_model_t epd_uc8151_029_bw = {UC8151_029_BW, COLOR_BW, &epd_drv_uc81xx, DRV_IC_UC8151, 168, 384};
const epd_model_t epd_uc8151_029_bwr = {UC8151_029_BWR, COLOR_BWR, &epd_drv_uc81xx, DRV_IC_UC8151, 168, 384};
const epd_model_t epd_uc8151_027_bw = {UC8151_027_BW, COLOR_BW, &epd_drv_uc81xx, DRV_IC_UC8151, 200, 300};
const epd_model_t epd_uc8151_027_bwr = {UC8151_027_BWR, COLOR_BWR, &epd_drv_uc81xx, DRV_IC_UC8151, 200, 300};
const epd_model_t epd_ucvar43_430_bw = {UCVAR43_430_BW, COLOR_BW, &epd_drv_uc81xx, DRV_IC_UCVAR43, 152, 522};
const epd_model_t epd_ucvar43_430_bwr = {UCVAR43_430_BWR, COLOR_BWR, &epd_drv_uc81xx, DRV_IC_UCVAR43, 152, 522};
