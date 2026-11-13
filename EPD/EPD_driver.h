#ifndef __EPD_DRIVER_H__
#define __EPD_DRIVER_H__

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "structs.h"
#include "nrf_delay.h"
#include "nrf_gpio.h"


/* Panel bus primitives only. There are no panel drivers in this firmware: every panel is driven
 * from the drive packets in the stored config (od/core/od_epd.c via glue/od_nrf_display.c). */

#define LOW (0x0)
#define HIGH (0x1)

#define DEFAULT (0xFF)
#define INPUT (0x0)
#define OUTPUT (0x1)
#define INPUT_PULLUP (0x2)
#define INPUT_PULLDOWN (0x3)

// Arduino like function wrappers
void pinMode(uint32_t pin, uint32_t mode);
#define digitalWrite(pin, value) nrf_gpio_pin_write(pin, value)
#define digitalRead(pin) nrf_gpio_pin_read(pin)
#define delay(ms) nrf_delay_ms(ms)

// GPIO
void EPD_GPIO_Load_DisplayConfig(struct DisplayConfig* cfg, struct GlobalConfig* globalCfg);
void EPD_GPIO_Init(void);
void EPD_GPIO_Uninit(void);

// SPI
void EPD_SPI_Write(uint8_t* value, uint8_t len);
void EPD_SPI_Read(uint8_t* value, uint8_t len);

// EPD
void EPD_WriteCmd(uint8_t cmd);
void EPD_WriteData(uint8_t* value, uint8_t len);
void EPD_ReadData(uint8_t* value, uint8_t len);
bool EPD_ReadBusy(void);

// VDD voltage
uint16_t EPD_ReadVoltage(void);


#endif
