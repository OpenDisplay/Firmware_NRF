/* Host test: GPIO calls become recorded events (host/tests/test_service.c). */
#ifndef HOST_NRF_GPIO_H
#define HOST_NRF_GPIO_H
#include <stdint.h>
#include "nrf.h"
void host_gpio_write(uint32_t pin, uint32_t level);
uint32_t host_gpio_read(uint32_t pin);
#define nrf_gpio_pin_write(p, v) host_gpio_write((p), (v))
#define nrf_gpio_pin_read(p) host_gpio_read(p)
#define nrf_gpio_pin_set(p) host_gpio_write((p), 1u)
#define nrf_gpio_pin_clear(p) host_gpio_write((p), 0u)
#define nrf_gpio_cfg_output(p) ((void)(p))
#define nrf_gpio_cfg_input(p, pull) ((void)(p))
#define nrf_gpio_cfg_default(p) ((void)(p))
#endif
