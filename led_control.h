#ifndef LED_CONTROL_H__
#define LED_CONTROL_H__

#include <stdint.h>
#include <stdbool.h>

void flashLed(uint8_t color, uint8_t brightness);
void ledFlashLogic(void);
void led_init(void);
void led_activate(uint8_t instance);
void led_set_flash_active(bool active);

#endif // LED_CONTROL_H__
