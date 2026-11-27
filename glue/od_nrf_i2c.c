/* od_nrf_i2c.c -- see od_nrf_i2c.h. */
#include "od_nrf_i2c.h"

#include "nrf_delay.h"
#include "nrf_gpio.h"

#define HALF_US      5u      /* ~100 kHz */
#define STRETCH_US   1000u

static uint8_t s_scl = 0xFFu, s_sda = 0xFFu;

static void od_pin(uint8_t pin)
{
    nrf_gpio_cfg(pin, NRF_GPIO_PIN_DIR_OUTPUT, NRF_GPIO_PIN_INPUT_CONNECT, NRF_GPIO_PIN_PULLUP,
                 NRF_GPIO_PIN_S0D1, NRF_GPIO_PIN_NOSENSE);
    nrf_gpio_pin_set(pin);   /* released */
}

void od_nrf_i2c_begin(uint8_t scl, uint8_t sda)
{
    s_scl = scl;
    s_sda = sda;
    od_pin(sda);
    od_pin(scl);
    nrf_delay_us(HALF_US);
}

void od_nrf_i2c_end(void)
{
    if (s_scl != 0xFFu) {
        nrf_gpio_cfg_default(s_scl);
    }
    if (s_sda != 0xFFu) {
        nrf_gpio_cfg_default(s_sda);
    }
    s_scl = s_sda = 0xFFu;
}

static inline void sda(bool hi) { nrf_gpio_pin_write(s_sda, hi ? 1u : 0u); }

/* Release SCL and wait for it to rise (a slave may hold it low). */
static bool scl_hi(void)
{
    nrf_gpio_pin_set(s_scl);
    for (uint32_t t = 0; nrf_gpio_pin_read(s_scl) == 0u; t++) {
        if (t >= STRETCH_US) {
            return false;
        }
        nrf_delay_us(1);
    }
    nrf_delay_us(HALF_US);
    return true;
}

static inline void scl_lo(void)
{
    nrf_gpio_pin_clear(s_scl);
    nrf_delay_us(HALF_US);
}

static bool start(void)
{
    sda(true);
    if (!scl_hi()) {
        return false;
    }
    sda(false);
    nrf_delay_us(HALF_US);
    scl_lo();
    return true;
}

static void stop(void)
{
    sda(false);
    nrf_delay_us(HALF_US);
    (void)scl_hi();
    sda(true);
    nrf_delay_us(HALF_US);
}

/* true = ACK */
static bool put(uint8_t b)
{
    for (uint8_t m = 0x80u; m != 0u; m >>= 1) {
        sda((b & m) != 0u);
        if (!scl_hi()) {
            return false;
        }
        scl_lo();
    }
    sda(true);
    if (!scl_hi()) {
        return false;
    }
    const bool ack = nrf_gpio_pin_read(s_sda) == 0u;
    scl_lo();
    return ack;
}

static uint8_t get(bool ack)
{
    uint8_t b = 0;
    sda(true);
    for (uint8_t i = 0; i < 8u; i++) {
        (void)scl_hi();
        b = (uint8_t)((b << 1) | (nrf_gpio_pin_read(s_sda) != 0u ? 1u : 0u));
        scl_lo();
    }
    sda(!ack);
    (void)scl_hi();
    scl_lo();
    sda(true);
    return b;
}

static bool wr(uint8_t addr7, const uint8_t *w, uint16_t wn)
{
    if (!start() || !put((uint8_t)(addr7 << 1))) {
        return false;
    }
    for (uint16_t i = 0; i < wn; i++) {
        if (!put(w[i])) {
            return false;
        }
    }
    return true;
}

static bool rd(uint8_t addr7, uint8_t *r, uint16_t rn)
{
    if (!start() || !put((uint8_t)((addr7 << 1) | 1u))) {
        return false;
    }
    for (uint16_t i = 0; i < rn; i++) {
        r[i] = get(i + 1u < rn);
    }
    return true;
}

bool od_nrf_i2c_write(uint8_t addr7, const uint8_t *w, uint16_t wn)
{
    const bool ok = wr(addr7, w, wn);
    stop();
    return ok;
}

bool od_nrf_i2c_read(uint8_t addr7, uint8_t *r, uint16_t rn)
{
    const bool ok = rd(addr7, r, rn);
    stop();
    return ok;
}

bool od_nrf_i2c_write_read(uint8_t addr7, const uint8_t *w, uint16_t wn, uint8_t *r, uint16_t rn)
{
    const bool ok = wr(addr7, w, wn) && rd(addr7, r, rn);
    stop();
    return ok;
}
