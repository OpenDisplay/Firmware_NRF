#pragma once

// Single include point for platform/MCU-dependent APIs.
// Porting to a new target should mostly mean replacing this header (or making it
// dispatch to a target-specific implementation).

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// nRF52 (current target)
#include "nrf.h"
#include "nrf_delay.h"
#include "nrf_soc.h"
#include "nrf_gpio.h"
#include "nrf_log.h"

static inline uint32_t platform_deviceid_word0(void) { return NRF_FICR->DEVICEID[0]; }
static inline uint32_t platform_deviceid_word1(void) { return NRF_FICR->DEVICEID[1]; }

static inline void platform_reboot(void) { NVIC_SystemReset(); }

static inline void platform_delay_ms(uint32_t ms) { nrf_delay_ms(ms); }
static inline void platform_delay_us(uint32_t us) { nrf_delay_us(us); }

static inline uint32_t platform_rand_get(uint8_t* out, size_t len) {
    return sd_rand_application_vector_get(out, (uint8_t)len);
}

static inline uint32_t platform_rand_available(uint8_t* available) {
    return sd_rand_application_bytes_available_get(available);
}

static inline void platform_gpio_cfg_input(uint32_t pin, nrf_gpio_pin_pull_t pull) {
    nrf_gpio_cfg_input(pin, pull);
}

static inline uint32_t platform_gpio_read(uint32_t pin) { return nrf_gpio_pin_read(pin); }

static inline void platform_gpio_cfg_default(uint32_t pin) { nrf_gpio_cfg_default(pin); }

