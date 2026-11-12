/* host stub: GPIO writes are recorded only where the drivers use them directly (none) */
#pragma once
#include <stdint.h>
#define nrf_gpio_pin_write(pin, v) ((void)(pin), (void)(v))
#define nrf_gpio_pin_read(pin) (0)
