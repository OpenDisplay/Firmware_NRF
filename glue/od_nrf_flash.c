/* od_nrf_flash.c -- external SPI flash deep power-down from the config (0x2B FlashConfig).
 *
 * This firmware never uses the external flash, so all it does is park it: the first FlashConfig
 * with flags bit0 set names MOSI, SCK and CS; the JEDEC deep power-down command 0xB9 is clocked
 * out (SPI mode 0) and CS is then held high, MOSI/SCK low. The pin levels are kept through System
 * OFF. Runs at boot, after every config write and before System OFF; 0xB9 to a flash that is
 * already powered down does nothing. Pins are plain GPIO numbers. */
#include "od_nrf_glue.h"

#include "nrf_delay.h"
#include "nrf_gpio.h"

static uint8_t s_mosi = 0xFFu, s_sck = 0xFFu, s_cs = 0xFFu;

static void power_down(void)
{
    uint8_t cmd = 0xB9u;

    if (s_cs == 0xFFu) {
        return;
    }
    nrf_gpio_pin_set(s_cs);
    nrf_gpio_cfg_output(s_cs);
    nrf_gpio_pin_clear(s_sck);
    nrf_gpio_cfg_output(s_sck);
    nrf_gpio_pin_clear(s_mosi);
    nrf_gpio_cfg_output(s_mosi);
    nrf_delay_us(1);
    nrf_gpio_pin_clear(s_cs);
    for (uint8_t i = 0; i < 8u; i++) {
        nrf_gpio_pin_write(s_mosi, (cmd & 0x80u) != 0u ? 1u : 0u);
        cmd = (uint8_t)(cmd << 1);
        nrf_delay_us(1);
        nrf_gpio_pin_set(s_sck);
        nrf_delay_us(1);
        nrf_gpio_pin_clear(s_sck);
    }
    nrf_gpio_pin_clear(s_mosi);
    nrf_gpio_pin_set(s_cs);
    nrf_delay_us(30);   /* tDP: the flash is in deep power-down after this */
}

void od_nrf_flash_init(const struct GlobalConfig *g)
{
    s_mosi = s_sck = s_cs = 0xFFu;
    if (g == NULL || !g->loaded) {
        return;
    }
    for (uint8_t i = 0; i < g->flash_config_count && i < 2u; i++) {
        const struct FlashConfig *f = &g->flash_configs[i];
        if ((f->flags & 0x01u) == 0u) {
            continue;
        }
        if (f->mosi_pin < 32u && f->sck_pin < 32u && f->cs_pin < 32u &&
            f->mosi_pin != f->sck_pin && f->mosi_pin != f->cs_pin && f->sck_pin != f->cs_pin) {
            s_mosi = f->mosi_pin;
            s_sck = f->sck_pin;
            s_cs = f->cs_pin;
            power_down();
        }
        return;   /* the first enabled one decides */
    }
}

void od_nrf_flash_sleep(void)
{
    power_down();
}
