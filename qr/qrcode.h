/**
 * Minimal QR header (MIT) derived from ricmoo/QRCode.
 * We keep only the APIs used by Firmware_NRF boot screen.
 */
#ifndef __QRCODE_H_
#define __QRCODE_H_

#include <stdint.h>
#include <stdbool.h>

// Error Correction Code Levels (only ECC_MEDIUM supported in this firmware)
#define ECC_MEDIUM         1

typedef struct QRCode {
    uint8_t version;
    uint8_t size;
    uint8_t ecc;
    uint8_t mode;
    uint8_t mask;
    uint8_t *modules;
} QRCode;

#ifdef __cplusplus
extern "C"{
#endif

uint16_t qrcode_getBufferSize(uint8_t version);

// Returns 0 on success, <0 on error.
int8_t qrcode_initText(QRCode *qrcode, uint8_t *modules, uint8_t version, uint8_t ecc, const char *data);

// Returns 0 on success, <0 on error.
int8_t qrcode_initBytes(QRCode *qrcode, uint8_t *modules, uint8_t version, uint8_t ecc, uint8_t *data, uint16_t length);

bool qrcode_getModule(QRCode *qrcode, uint8_t x, uint8_t y);

// Data capacity in bytes for version at ECC_MEDIUM, or 0 if invalid.
uint16_t qrcode_getDataCapacityBytes(uint8_t version);

#ifdef __cplusplus
}
#endif

#endif
