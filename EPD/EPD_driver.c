#include "EPD_driver.h"

#include "app_error.h"
#include "constants.h"
#include "nrf_drv_spi.h"
#include "structs.h"
#include "nrf.h"
#if defined(S112)
#include "nrf_saadc.h"
#else
#include "nrf_adc.h"
#endif

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#define BUFFER_SIZE 128

extern void app_feed_wdt(void); // Feed the watchdog timer (main.c)

static uint32_t EPD_MOSI_PIN = 5;
static uint32_t EPD_SCLK_PIN = 8;
static uint32_t EPD_CS_PIN = 9;
static uint32_t EPD_DC_PIN = 10;
static uint32_t EPD_RST_PIN = 11;
static uint32_t EPD_BUSY_PIN = 12;
static uint32_t EPD_BS_PIN = 13;
static uint32_t EPD_EN_PIN = 0xFF;

#define SPI_INSTANCE 0                                               /**< SPI instance index. */
static const nrf_drv_spi_t spi = NRF_DRV_SPI_INSTANCE(SPI_INSTANCE); /**< SPI instance. */

#if defined(S112)
#define HAL_SPI_INSTANCE spi.u.spi.p_reg
#else
#define HAL_SPI_INSTANCE spi.p_registers
nrf_gpio_pin_dir_t nrf_gpio_pin_dir_get(uint32_t pin) {
    NRF_GPIO_Type* reg = nrf_gpio_pin_port_decode(&pin);
    return (nrf_gpio_pin_dir_t)((reg->PIN_CNF[pin] & GPIO_PIN_CNF_DIR_Msk) >> GPIO_PIN_CNF_DIR_Pos);
}
#endif

void pinMode(uint32_t pin, uint32_t mode) {
    switch (mode) {
        case INPUT:
            nrf_gpio_cfg_input(pin, NRF_GPIO_PIN_NOPULL);
            break;
        case INPUT_PULLUP:
            nrf_gpio_cfg_input(pin, NRF_GPIO_PIN_PULLUP);
            break;
        case INPUT_PULLDOWN:
            nrf_gpio_cfg_input(pin, NRF_GPIO_PIN_PULLDOWN);
            break;
        case OUTPUT:
            nrf_gpio_cfg_output(pin);
            break;
        case DEFAULT:
        default:
            nrf_gpio_cfg_default(pin);
            break;
    }
}

static uint16_t m_driver_refs = 0;

void EPD_GPIO_Load_DisplayConfig(struct DisplayConfig* cfg, struct GlobalConfig* globalCfg) {
    if (cfg == NULL) return;
    EPD_MOSI_PIN = cfg->data_pin;
    EPD_SCLK_PIN = cfg->clk_pin;
    EPD_CS_PIN = cfg->cs_pin;
    EPD_DC_PIN = cfg->dc_pin;
    EPD_RST_PIN = cfg->reset_pin;
    EPD_BUSY_PIN = cfg->busy_pin;
    EPD_BS_PIN = 13;
    if (globalCfg != NULL && globalCfg->system_config.pwr_pin != 0xFF) {
        EPD_EN_PIN = globalCfg->system_config.pwr_pin;
    } else {
        EPD_EN_PIN = 0xFF;
    }
}


void EPD_GPIO_Init(void) {
    if (m_driver_refs++ > 0) return;

    pinMode(EPD_DC_PIN, OUTPUT);
    pinMode(EPD_RST_PIN, OUTPUT);
    pinMode(EPD_BUSY_PIN, INPUT);

    nrf_drv_spi_config_t spi_config = NRF_DRV_SPI_DEFAULT_CONFIG;
    spi_config.sck_pin = EPD_SCLK_PIN;
    spi_config.mosi_pin = EPD_MOSI_PIN;
    spi_config.ss_pin = EPD_CS_PIN;
#if defined(S112)
    APP_ERROR_CHECK(nrf_drv_spi_init(&spi, &spi_config, NULL, NULL));
#else
    APP_ERROR_CHECK(nrf_drv_spi_init(&spi, &spi_config, NULL));
#endif

    if (EPD_BS_PIN != 0xFF) {
        pinMode(EPD_BS_PIN, OUTPUT);
        digitalWrite(EPD_BS_PIN, LOW);
    }
    if (EPD_EN_PIN != 0xFF) {
        pinMode(EPD_EN_PIN, OUTPUT);
        digitalWrite(EPD_EN_PIN, HIGH);
    }

    digitalWrite(EPD_DC_PIN, LOW);
    digitalWrite(EPD_RST_PIN, HIGH);

}

void EPD_GPIO_Uninit(void) {
    if (m_driver_refs == 0) return;
    if (--m_driver_refs > 0) return;

    nrf_drv_spi_uninit(&spi);

    digitalWrite(EPD_DC_PIN, LOW);
    digitalWrite(EPD_CS_PIN, LOW);
    digitalWrite(EPD_RST_PIN, LOW);
    if (EPD_EN_PIN != 0xFF) digitalWrite(EPD_EN_PIN, LOW);

    pinMode(EPD_MOSI_PIN, DEFAULT);
    pinMode(EPD_SCLK_PIN, DEFAULT);
    pinMode(EPD_CS_PIN, DEFAULT);
    pinMode(EPD_DC_PIN, DEFAULT);
    pinMode(EPD_RST_PIN, DEFAULT);
    pinMode(EPD_BUSY_PIN, DEFAULT);
    pinMode(EPD_BS_PIN, DEFAULT);
    pinMode(EPD_EN_PIN, DEFAULT);
}

// SPI
void EPD_SPI_Write(uint8_t* value, uint8_t len) {
    nrf_gpio_pin_dir_t dir = nrf_gpio_pin_dir_get(EPD_MOSI_PIN);
    if (dir != NRF_GPIO_PIN_DIR_OUTPUT) {
        pinMode(EPD_MOSI_PIN, OUTPUT);
        nrf_spi_pins_set(HAL_SPI_INSTANCE, EPD_SCLK_PIN, EPD_MOSI_PIN, NRF_SPI_PIN_NOT_CONNECTED);
    }
    APP_ERROR_CHECK(nrf_drv_spi_transfer(&spi, value, len, NULL, 0));
}

void EPD_SPI_Read(uint8_t* value, uint8_t len) {
    nrf_gpio_pin_dir_t dir = nrf_gpio_pin_dir_get(EPD_MOSI_PIN);
    if (dir != NRF_GPIO_PIN_DIR_INPUT) {
        pinMode(EPD_MOSI_PIN, INPUT);
        nrf_spi_pins_set(HAL_SPI_INSTANCE, EPD_SCLK_PIN, NRF_SPI_PIN_NOT_CONNECTED, EPD_MOSI_PIN);
    }
    APP_ERROR_CHECK(nrf_drv_spi_transfer(&spi, NULL, 0, value, len));
}

// EPD
void EPD_WriteCmd(uint8_t cmd) {
    digitalWrite(EPD_DC_PIN, LOW);
    EPD_SPI_Write(&cmd, 1);
}

void EPD_WriteData(uint8_t* value, uint8_t len) {
    digitalWrite(EPD_DC_PIN, HIGH);
    EPD_SPI_Write(value, len);
}

void EPD_ReadData(uint8_t* value, uint8_t len) {
    digitalWrite(EPD_DC_PIN, HIGH);
    EPD_SPI_Read(value, len);
}

void EPD_WriteByte(uint8_t value) {
    digitalWrite(EPD_DC_PIN, HIGH);
    EPD_SPI_Write(&value, 1);
}

uint8_t EPD_ReadByte(void) {
    uint8_t value;
    digitalWrite(EPD_DC_PIN, HIGH);
    EPD_SPI_Read(&value, 1);
    return value;
}

void EPD_FillRAM(uint8_t cmd, uint8_t value, uint32_t len) {
    uint8_t buffer[BUFFER_SIZE];
    for (uint8_t i = 0; i < BUFFER_SIZE; i++) buffer[i] = value;

    EPD_WriteCmd(cmd);
    uint16_t remaining = len;
    while (remaining > 0) {
        uint16_t chunk_size = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;
        EPD_WriteData(buffer, chunk_size);
        remaining -= chunk_size;
    }
}

void EPD_Reset(bool status, uint16_t duration) {
    digitalWrite(EPD_RST_PIN, status);
    delay(duration);
    digitalWrite(EPD_RST_PIN, status ? LOW : HIGH);
    delay(duration);
    digitalWrite(EPD_RST_PIN, status);
    delay(duration);
}

bool EPD_ReadBusy(void) { return digitalRead(EPD_BUSY_PIN); }

void EPD_WaitBusy(bool status, uint16_t timeout) {
    EPD_DEBUG("check busy");
    while (EPD_ReadBusy() == status) {
        if (timeout % EPD_BUSY_WDT_FEED_INTERVAL == 0) {
            app_feed_wdt();
        }
        delay(EPD_BUSY_CHECK_DELAY_MS);
        timeout--;
        if (timeout == 0) {
            EPD_DEBUG("busy timeout!");
            break;
        }
    }
    EPD_DEBUG("busy release");
}

uint16_t EPD_ReadVoltage(void) {
#if defined(S112)
    volatile int16_t value = 0;
    NRF_SAADC->RESOLUTION = SAADC_RESOLUTION_VAL_10bit;
    NRF_SAADC->ENABLE = (SAADC_ENABLE_ENABLE_Enabled << SAADC_ENABLE_ENABLE_Pos);
    NRF_SAADC->CH[0].CONFIG =
        ((SAADC_CH_CONFIG_RESP_Bypass << SAADC_CH_CONFIG_RESP_Pos) & SAADC_CH_CONFIG_RESP_Msk) |
        ((SAADC_CH_CONFIG_RESP_Bypass << SAADC_CH_CONFIG_RESN_Pos) & SAADC_CH_CONFIG_RESN_Msk) |
        ((SAADC_CH_CONFIG_GAIN_Gain1_6 << SAADC_CH_CONFIG_GAIN_Pos) & SAADC_CH_CONFIG_GAIN_Msk) |
        ((SAADC_CH_CONFIG_REFSEL_Internal << SAADC_CH_CONFIG_REFSEL_Pos) & SAADC_CH_CONFIG_REFSEL_Msk) |
        ((SAADC_CH_CONFIG_TACQ_3us << SAADC_CH_CONFIG_TACQ_Pos) & SAADC_CH_CONFIG_TACQ_Msk) |
        ((SAADC_CH_CONFIG_MODE_SE << SAADC_CH_CONFIG_MODE_Pos) & SAADC_CH_CONFIG_MODE_Msk);
    NRF_SAADC->CH[0].PSELN = SAADC_CH_PSELN_PSELN_NC;
    NRF_SAADC->CH[0].PSELP = SAADC_CH_PSELP_PSELP_VDD;
    NRF_SAADC->RESULT.PTR = (uint32_t)&value;
    NRF_SAADC->RESULT.MAXCNT = 1;
    NRF_SAADC->TASKS_START = 0x01UL;
    while (!NRF_SAADC->EVENTS_STARTED);
    NRF_SAADC->EVENTS_STARTED = 0x00UL;
    NRF_SAADC->TASKS_SAMPLE = 0x01UL;
    while (!NRF_SAADC->EVENTS_END);
    NRF_SAADC->EVENTS_END = 0x00UL;
    NRF_SAADC->TASKS_STOP = 0x01UL;
    while (!NRF_SAADC->EVENTS_STOPPED);
    NRF_SAADC->EVENTS_STOPPED = 0x00UL;
    if (value < 0) value = 0;
    NRF_SAADC->ENABLE = (SAADC_ENABLE_ENABLE_Disabled << SAADC_ENABLE_ENABLE_Pos);
#else
    NRF_ADC->ENABLE = 1;
    NRF_ADC->CONFIG = (ADC_CONFIG_RES_10bit << ADC_CONFIG_RES_Pos) |
                      (ADC_CONFIG_INPSEL_SupplyOneThirdPrescaling << ADC_CONFIG_INPSEL_Pos) |
                      (ADC_CONFIG_REFSEL_VBG << ADC_CONFIG_REFSEL_Pos) |
                      (ADC_CONFIG_PSEL_Disabled << ADC_CONFIG_PSEL_Pos) |
                      (ADC_CONFIG_EXTREFSEL_None << ADC_CONFIG_EXTREFSEL_Pos);
    NRF_ADC->TASKS_START = 1;
    while (!NRF_ADC->EVENTS_END);
    NRF_ADC->EVENTS_END = 0;
    uint16_t value = NRF_ADC->RESULT;
    NRF_ADC->TASKS_STOP = 1;
    NRF_ADC->ENABLE = 0;
#endif
    EPD_DEBUG("ADC value: %d", value);
    return (value * 3600) / (1 << 10);
}

extern epd_model_t epd_uc8176_420_bw;
extern epd_model_t epd_uc8176_420_bwr;
extern epd_model_t epd_uc8159_750_bw;
extern epd_model_t epd_uc8159_750_bwr;
extern epd_model_t epd_uc8179_750_bw;
extern epd_model_t epd_uc8179_750_bwr;
extern epd_model_t epd_uc8151_029_bw;
extern epd_model_t epd_uc8151_029_bwr;
extern epd_model_t epd_ssd1619_420_bwr;
extern epd_model_t epd_ssd1619_420_bw;
extern epd_model_t epd_ssd1619_016_bw;
extern epd_model_t epd_ssd1619_016_bwr;
extern epd_model_t epd_ssd1619_022_bw;
extern epd_model_t epd_ssd1619_022_bwr;
extern epd_model_t epd_ssd1619_026_bw;
extern epd_model_t epd_ssd1619_026_bwr;
extern epd_model_t epd_ssd1619_029_bw;
extern epd_model_t epd_ssd1619_029_bwr;
extern epd_model_t epd_uc8151_027_bw;
extern epd_model_t epd_uc8151_027_bwr;
extern epd_model_t epd_ucvar43_430_bw;
extern epd_model_t epd_ucvar43_430_bwr;
extern epd_model_t epd_ssd1677_750_bwr;
extern epd_model_t epd_ssd1677_750_bw;
extern epd_model_t epd_ssd1619_013_bw;
extern epd_model_t epd_ssd1619_013_bwr;
extern epd_model_t epd_ssd1619_022_lite_bw;
extern epd_model_t epd_ssd1619_022_lite_bwr;
extern epd_model_t epd_jd79668_420_bwry;
extern epd_model_t epd_jd79665_750_bwry;
extern epd_model_t epd_jd79665_583_bwry;

static epd_model_t* epd_models[] = {
    &epd_uc8176_420_bw,    &epd_uc8176_420_bwr,   &epd_uc8159_750_bw,    &epd_uc8159_750_bwr,  &epd_uc8179_750_bw,
    &epd_uc8179_750_bwr,   &epd_uc8151_029_bw,    &epd_uc8151_029_bwr,   &epd_ssd1619_420_bwr,  &epd_ssd1619_420_bw,
    &epd_ssd1619_016_bw,   &epd_ssd1619_016_bwr,  &epd_ssd1619_022_bw,   &epd_ssd1619_022_bwr,  &epd_ssd1619_026_bw,
    &epd_ssd1619_026_bwr,  &epd_uc8151_027_bw,    &epd_uc8151_027_bwr,   &epd_ucvar43_430_bw,   &epd_ucvar43_430_bwr,
    &epd_ssd1619_029_bw,   &epd_ssd1619_029_bwr,
    &epd_ssd1619_013_bw,  &epd_ssd1619_013_bwr,
    &epd_ssd1619_022_lite_bw, &epd_ssd1619_022_lite_bwr,
    &epd_ssd1677_750_bwr, &epd_ssd1677_750_bw,
    &epd_jd79668_420_bwry, &epd_jd79665_750_bwry, &epd_jd79665_583_bwry,
};

epd_model_t* epd_init(epd_model_id_t id) {
    epd_model_t* epd = NULL;
    for (uint8_t i = 0; i < ARRAY_SIZE(epd_models); i++) {
        if (epd_models[i]->id == id) {
            epd = epd_models[i];
        }
    }
    if (epd == NULL) epd = epd_models[0];
    epd->drv->init(epd);
    return epd;
}

epd_model_id_t map_panel_ic_to_model_id(uint16_t panel_ic_type, uint8_t color_scheme) {
    if (panel_ic_type >= 1000 && panel_ic_type <= 1999) {
        panel_ic_type -= 999;
    }
    epd_color_t target_color = (color_scheme == 0) ? COLOR_BW : COLOR_BWR;
    if (panel_ic_type >= 1 && panel_ic_type <= 31) {
        epd_model_id_t model_id = (epd_model_id_t)panel_ic_type;
        switch (model_id) {
            case SSD1619_420_BW:
            case SSD1619_420_BWR:
                return (target_color == COLOR_BW) ? SSD1619_420_BW : SSD1619_420_BWR;
            case SSD1619_016_BW:
            case SSD1619_016_BWR:
                return (target_color == COLOR_BW) ? SSD1619_016_BW : SSD1619_016_BWR;
            case SSD1619_022_BW:
            case SSD1619_022_BWR:
                return (target_color == COLOR_BW) ? SSD1619_022_BW : SSD1619_022_BWR;
            case SSD1619_026_BW:
            case SSD1619_026_BWR:
                return (target_color == COLOR_BW) ? SSD1619_026_BW : SSD1619_026_BWR;
            case UC8151_027_BW:
            case UC8151_027_BWR:
                return (target_color == COLOR_BW) ? UC8151_027_BW : UC8151_027_BWR;
            case UCVAR43_430_BW:
            case UCVAR43_430_BWR:
                return (target_color == COLOR_BW) ? UCVAR43_430_BW : UCVAR43_430_BWR;
            case SSD1619_029_BW:
            case SSD1619_029_BWR:
                return (target_color == COLOR_BW) ? SSD1619_029_BW : SSD1619_029_BWR;
            case UC8151_029_BW:
            case UC8151_029_BWR:
                return (target_color == COLOR_BW) ? UC8151_029_BW : UC8151_029_BWR;
            case SSD1619_013_BW:
            case SSD1619_013_BWR:
                return (target_color == COLOR_BW) ? SSD1619_013_BW : SSD1619_013_BWR;
            case SSD1619_022_LITE_BW:
            case SSD1619_022_LITE_BWR:
                return (target_color == COLOR_BW) ? SSD1619_022_LITE_BW : SSD1619_022_LITE_BWR;
            default:
                return model_id;
        }
    }
    return UC8176_420_BW;
}
