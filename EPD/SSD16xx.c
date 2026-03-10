#include "EPD_driver.h"

bool SSD16xx_ReadBusy(epd_model_t* epd) { return EPD_ReadBusy(); }

static void SSD16xx_WaitBusy(uint16_t timeout) { EPD_WaitBusy(true, timeout); }

static void SSD16xx_Update(uint8_t seq) {
    EPD_Write(SSD16xx_DISP_CTRL2, seq);
    EPD_WriteCmd(SSD16xx_MASTER_ACTIVATE);
}

int8_t SSD16xx_ReadTemp(epd_model_t* epd) {
    SSD16xx_Update(0xB1);
    SSD16xx_WaitBusy(500);
    EPD_WriteCmd(SSD16xx_TSENSOR_READ);
    return (int8_t)EPD_ReadByte();
}

static uint8_t SSD16xx_GetXOffset(epd_model_t* epd) {
    switch (epd->id) {
        case SSD1619_022_BW:  case SSD1619_022_BWR:
        case SSD1619_022_LITE_BW:  case SSD1619_022_LITE_BWR:
        case SSD1619_026_BW:  case SSD1619_026_BWR:
        case SSD1619_029_BW:  case SSD1619_029_BWR:
        case SSD1619_013_BW:  case SSD1619_013_BWR:
            return 1;  // 8 pixels = 1 byte offset
        default:
            return 0;
    }
}

static bool SSD16xx_YIncrease(epd_model_t* epd) {
    switch (epd->id) {
        case SSD1619_016_BW:  case SSD1619_016_BWR:
        case SSD1619_013_BW:  case SSD1619_013_BWR:
        case SSD1619_022_LITE_BW:  case SSD1619_022_LITE_BWR:
            return true;
        default:
            return (epd->ic == DRV_IC_SSD1677);
    }
}

void SSD16xx_SetWindow(epd_model_t* epd, uint16_t x, uint16_t y, uint16_t w, uint16_t h) {
    bool y_inc = SSD16xx_YIncrease(epd);
    uint8_t x_off = SSD16xx_GetXOffset(epd);
    EPD_Write(SSD16xx_ENTRY_MODE, y_inc ? 0x03 : 0x01);
    switch (epd->ic) {
        case DRV_IC_SSD1677:
            EPD_Write(SSD16xx_RAM_XPOS, x % 256, x / 256, (x + w - 1) % 256, (x + w - 1) / 256);
            EPD_Write(SSD16xx_RAM_XCOUNT, x % 256, x / 256);
            break;
        default:
            EPD_Write(SSD16xx_RAM_XPOS, (x / 8) + x_off, ((x + w - 1) / 8) + x_off);
            EPD_Write(SSD16xx_RAM_XCOUNT, (x / 8) + x_off);
            break;
    }
    if (y_inc) {
        EPD_Write(SSD16xx_RAM_YPOS, y % 256, y / 256, (y + h - 1) % 256, (y + h - 1) / 256);
        EPD_Write(SSD16xx_RAM_YCOUNT, y % 256, y / 256);
    } else {
        EPD_Write(SSD16xx_RAM_YPOS, (y + h) % 256, (y + h) / 256, y % 256, y / 256);
        EPD_Write(SSD16xx_RAM_YCOUNT, (y + h - 1) % 256, (y + h - 1) / 256);
    }
}

void SSD16xx_Init(epd_model_t* epd) {
    EPD_Reset(true, 10);
    EPD_WriteCmd(SSD16xx_SW_RESET);
    SSD16xx_WaitBusy(200);
    EPD_Write(SSD16xx_GDO_CTR, epd->height & 0xFF, epd->height >> 8, 0x00);
    EPD_Write(SSD16xx_BORDER_CTRL, 0x05);
    EPD_Write(SSD16xx_TSENSOR_CTRL, 0x80);
    uint8_t ctrl1 = epd->color == COLOR_BWR ? 0x08 : 0x48;
    if (epd->id == SSD1619_013_BW || epd->id == SSD1619_013_BWR) ctrl1 |= 0x80;
    EPD_Write(SSD16xx_DISP_CTRL1, ctrl1, 0x00);

    SSD16xx_SetWindow(epd, 0, 0, epd->width, epd->height);
}

static void SSD16xx_Refresh(epd_model_t* epd) {
    EPD_DEBUG("refresh begin");
    EPD_DEBUG("temperature: %d", SSD16xx_ReadTemp(epd));
    uint8_t ctrl1 = epd->color == COLOR_BWR ? 0x08 : 0x48;
    if (epd->id == SSD1619_013_BW || epd->id == SSD1619_013_BWR) ctrl1 |= 0x80;
    EPD_Write(SSD16xx_DISP_CTRL1, ctrl1, 0x00);
    SSD16xx_Update(0xF7);
    SSD16xx_WaitBusy(UINT16_MAX);
    EPD_DEBUG("refresh end");
    SSD16xx_SetWindow(epd, 0, 0, epd->width, epd->height);
}

void SSD16xx_Clear(epd_model_t* epd, bool refresh) {
    uint32_t ram_bytes = ((epd->width + 7) / 8) * epd->height;

    SSD16xx_SetWindow(epd, 0, 0, epd->width, epd->height);

    EPD_FillRAM(SSD16xx_WRITE_RAM1, 0xFF, ram_bytes);
    EPD_FillRAM(SSD16xx_WRITE_RAM2, 0xFF, ram_bytes);

    if (refresh) SSD16xx_Refresh(epd);
}

void SSD16xx_WriteRam(epd_model_t* epd, uint8_t cfg, uint8_t* data, uint8_t len) {
    bool begin = (cfg >> 4) == 0x00;
    bool black = (cfg & 0x0F) == 0x0F;
    if (begin) SSD16xx_SetWindow(epd, 0, 0, epd->width, epd->height);
    if (begin) {
        if (epd->color == COLOR_BWR)
            EPD_WriteCmd(black ? SSD16xx_WRITE_RAM1 : SSD16xx_WRITE_RAM2);
        else
            EPD_WriteCmd(SSD16xx_WRITE_RAM1);
    }
    EPD_WriteData(data, len);
}

void SSD16xx_Sleep(epd_model_t* epd) {
    EPD_Write(SSD16xx_SLEEP_MODE, 0x01);
    delay(100);
}

static const epd_driver_t epd_drv_ssd16xx = {
    .init = SSD16xx_Init,
    .clear = SSD16xx_Clear,
    .write_ram = SSD16xx_WriteRam,
    .refresh = SSD16xx_Refresh,
    .sleep = SSD16xx_Sleep,
    .read_temp = SSD16xx_ReadTemp,
    .read_busy = SSD16xx_ReadBusy,
    .set_window = SSD16xx_SetWindow,
};

const epd_model_t epd_ssd1619_420_bwr = {SSD1619_420_BWR, COLOR_BWR, &epd_drv_ssd16xx, DRV_IC_SSD1619, 400, 300};
const epd_model_t epd_ssd1619_420_bw = {SSD1619_420_BW, COLOR_BW, &epd_drv_ssd16xx, DRV_IC_SSD1619, 400, 300};
const epd_model_t epd_ssd1677_750_bwr = {SSD1677_750_HD_BWR, COLOR_BWR, &epd_drv_ssd16xx, DRV_IC_SSD1677, 880, 528};
const epd_model_t epd_ssd1677_750_bw = {SSD1677_750_HD_BW, COLOR_BW, &epd_drv_ssd16xx, DRV_IC_SSD1677, 880, 528};
const epd_model_t epd_ssd1619_016_bw = {SSD1619_016_BW, COLOR_BW, &epd_drv_ssd16xx, DRV_IC_SSD1619, 200, 200};
const epd_model_t epd_ssd1619_016_bwr = {SSD1619_016_BWR, COLOR_BWR, &epd_drv_ssd16xx, DRV_IC_SSD1619, 200, 200};
const epd_model_t epd_ssd1619_022_bw = {SSD1619_022_BW, COLOR_BW, &epd_drv_ssd16xx, DRV_IC_SSD1619, 240, 320};
const epd_model_t epd_ssd1619_022_bwr = {SSD1619_022_BWR, COLOR_BWR, &epd_drv_ssd16xx, DRV_IC_SSD1619, 240, 320};
const epd_model_t epd_ssd1619_026_bw = {SSD1619_026_BW, COLOR_BW, &epd_drv_ssd16xx, DRV_IC_SSD1619, 296, 152};
const epd_model_t epd_ssd1619_026_bwr = {SSD1619_026_BWR, COLOR_BWR, &epd_drv_ssd16xx, DRV_IC_SSD1619, 296, 152};
const epd_model_t epd_ssd1619_029_bw = {SSD1619_029_BW, COLOR_BW, &epd_drv_ssd16xx, DRV_IC_SSD1619, 168, 384};
const epd_model_t epd_ssd1619_029_bwr = {SSD1619_029_BWR, COLOR_BWR, &epd_drv_ssd16xx, DRV_IC_SSD1619, 168, 384};
const epd_model_t epd_ssd1619_013_bw = {SSD1619_013_BW, COLOR_BW, &epd_drv_ssd16xx, DRV_IC_SSD1619, 144, 200};
const epd_model_t epd_ssd1619_013_bwr = {SSD1619_013_BWR, COLOR_BWR, &epd_drv_ssd16xx, DRV_IC_SSD1619, 144, 200};
const epd_model_t epd_ssd1619_022_lite_bw = {SSD1619_022_LITE_BW, COLOR_BW, &epd_drv_ssd16xx, DRV_IC_SSD1619, 128, 250};
const epd_model_t epd_ssd1619_022_lite_bwr = {SSD1619_022_LITE_BWR, COLOR_BWR, &epd_drv_ssd16xx, DRV_IC_SSD1619, 128, 250};
