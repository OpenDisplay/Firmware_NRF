/* od_nrf_nfc.h -- NFC for the nRF52811: an I2C NFC tag chip driven from the config.
 *
 * Config: the first NfcConfig (0x2A) with flags bit0 set, whose bus_instance names an I2C
 * DataBus (0x24: pin_1 SCL, pin_2 SDA, pin_3 power when power_pin is 0xFF). Pins are plain nRF
 * GPIO numbers (port 0).
 *
 * Chips (nfc_ic_type):
 *   OD_NFC_IC_AUTO 0      probe an NXP NTAG I2C plus at 0x55 first, else treat as TNB132M
 *   OD_NFC_IC_TNB132M 1   the Type-3 flow of the EFR32BG22 target, byte for byte
 *   OD_NFC_IC_NTAG_I2C 3  NXP NT3H2111/NT3H2211 (Type 2): NDEF TLV in user blocks 0x01..0x37;
 *                         block 0 (address, lock and capability bytes) and the config/lock blocks
 *                         are never written
 * The chip is powered only for a session (boot init, each 0x0083 read or write).
 *
 * Host side: CMD_NFC_ENDPOINT 0x0083, the shared sub-protocol (READ / WRITE / WRITE_START / DATA /
 * END, the same status and NACK bytes and checks in the same order as od/core's od_nfc.c).
 *
 * Field detect: field_detect_mode 1 polls the pin from the main loop, 2 adds a pin-change
 * interrupt. A rising (active) edge counts a 7-bit tap counter; the advertised byte
 * dynamicreturndata[adv_button_byte_index] is state | counter << 1. The pin's pull follows its
 * active level (active low: pull-up, for an open-drain FD output). Before System OFF the pin is
 * armed as a wake source. */
#ifndef OD_NRF_NFC_H
#define OD_NRF_NFC_H

#include <stdbool.h>
#include <stdint.h>

#include "structs.h"

#ifndef OD_NFC_IC_NTAG_I2C
#define OD_NFC_IC_NTAG_I2C 3u   /* target-local until the protocol header allocates it */
#endif

typedef void (*od_nrf_nfc_send_fn)(const uint8_t *frame, uint16_t len);

/* (Re)apply the config: boot and every config reload. Runs the chip's init sequence. */
void od_nrf_nfc_init(const struct GlobalConfig *g);
/* One 0x0083 frame body (after the opcode). Answers through `send`. */
void od_nrf_nfc_frame(const uint8_t *body, uint16_t len, od_nrf_nfc_send_fn send);
/* The link went away: a chunked write in progress is dropped. */
void od_nrf_nfc_disconnected(void);
/* Main loop. true = the advertised field-detect byte changed. */
bool od_nrf_nfc_process(void);
/* Before System OFF: arm the field-detect pin as a wake source. */
void od_nrf_nfc_sleep_arm(void);

#endif /* OD_NRF_NFC_H */
