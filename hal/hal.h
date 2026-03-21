#pragma once

// Hardware Abstraction Layer (HAL)
//
// Business-logic modules should include small headers from `hal/` instead of
// pulling in MCU/SDK headers directly.
//
// Current implementation is for nRF52 and is header-only to avoid code size
// growth.

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

// Select target implementation.
// For now, default to nRF52 for this firmware tree.
#ifndef HAL_TARGET_NRF52
#define HAL_TARGET_NRF52 1
#endif

#if HAL_TARGET_NRF52
#include "platform/platform.h"

// ---- system ----
static inline uint32_t hal_deviceid_word0(void) { return platform_deviceid_word0(); }
static inline uint32_t hal_deviceid_word1(void) { return platform_deviceid_word1(); }
static inline void hal_reboot(void) { platform_reboot(); }

// ---- delay ----
static inline void hal_delay_ms(uint32_t ms) { platform_delay_ms(ms); }
static inline void hal_delay_us(uint32_t us) { platform_delay_us(us); }

// ---- random ----
static inline uint32_t hal_rand_get(uint8_t* out, size_t len) { return platform_rand_get(out, len); }
static inline uint32_t hal_rand_available(uint8_t* available) { return platform_rand_available(available); }

// ---- gpio ----
typedef enum {
    HAL_GPIO_NOPULL = 0,
    HAL_GPIO_PULLUP = 1,
    HAL_GPIO_PULLDOWN = 2,
} hal_gpio_pull_t;

static inline void hal_gpio_cfg_input(uint32_t pin, hal_gpio_pull_t pull) {
    // Map HAL pull to nRF pull through platform header.
    nrf_gpio_pin_pull_t p = NRF_GPIO_PIN_NOPULL;
    if (pull == HAL_GPIO_PULLUP) p = NRF_GPIO_PIN_PULLUP;
    else if (pull == HAL_GPIO_PULLDOWN) p = NRF_GPIO_PIN_PULLDOWN;
    platform_gpio_cfg_input(pin, p);
}
static inline uint32_t hal_gpio_read(uint32_t pin) { return platform_gpio_read(pin); }
static inline void hal_gpio_cfg_default(uint32_t pin) { platform_gpio_cfg_default(pin); }

#else
#error "No HAL target selected"
#endif

