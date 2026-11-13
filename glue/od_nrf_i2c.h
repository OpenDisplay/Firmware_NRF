/* od_nrf_i2c.h -- a small bit-banged I2C master for the NFC tag chip (glue/od_nrf_nfc.c).
 *
 * The nRF52811 has one TWI, which shares its peripheral slot with SPI1; a GPIO master needs no
 * sdk_config change, costs less flash than the TWIM driver and parks the pins completely between
 * sessions. Pins are open-drain (S0D1) with the internal pull-ups; SCL stretching is honoured up
 * to 1 ms. About 100 kHz. Host tests replace this file with a fake bus. */
#ifndef OD_NRF_I2C_H
#define OD_NRF_I2C_H

#include <stdbool.h>
#include <stdint.h>

/* Take the pins (open-drain, pulled up, both released) / give them back (disconnected inputs). */
void od_nrf_i2c_begin(uint8_t scl, uint8_t sda);
void od_nrf_i2c_end(void);

/* All three return true when every byte was ACKed. addr7 is the 7-bit address. */
bool od_nrf_i2c_write(uint8_t addr7, const uint8_t *w, uint16_t wn);
bool od_nrf_i2c_read(uint8_t addr7, uint8_t *r, uint16_t rn);
/* START, write, REPEATED START, read, STOP: one transaction. */
bool od_nrf_i2c_write_read(uint8_t addr7, const uint8_t *w, uint16_t wn, uint8_t *r, uint16_t rn);

#endif /* OD_NRF_I2C_H */
