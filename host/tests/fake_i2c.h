#ifndef FAKE_I2C_H
#define FAKE_I2C_H
#include "od_nrf_i2c.h"

enum { FAKE_NONE = 0, FAKE_NTAG = 1, FAKE_TNB = 2 };

struct fake_i2c {
    int chip;
    int open, sessions, closed_access, forbidden;
    uint8_t scl, sda;
    uint8_t ntag[256][16];
    uint8_t ptr;
    int reg;
    int ns_reg;
    uint8_t tnb_ai[16];
    uint8_t tnb_data[256];
    uint8_t log[128][2];
    int nlog;
};
extern struct fake_i2c g_fi;
void fake_i2c_reset(int chip);
#endif
