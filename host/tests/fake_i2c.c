/* fake_i2c.c -- host stand-in for glue/od_nrf_i2c.c: an NXP NTAG I2C plus at 0x55 and a TNB132M
 * (0x30 / 0x40 / 0x43 / 0x48), each present or absent. Writes are logged so the tests can check
 * which blocks were touched and in what order. */
#include "fake_i2c.h"

#include <string.h>

struct fake_i2c g_fi;

void fake_i2c_reset(int chip)
{
    memset(&g_fi, 0, sizeof g_fi);
    g_fi.chip = chip;
    /* NTAG block 0 as shipped: UID, I2C address byte 0x04 on read, lock 00 00, CC E1 10 6D 00 */
    const uint8_t b0[16] = { 0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x80,
                             0x00, 0x00, 0x00, 0x00, 0xE1, 0x10, 0x6D, 0x00 };
    memcpy(g_fi.ntag[0], b0, 16);
    g_fi.ntag[1][0] = 0x03;   /* empty NDEF TLV */
    g_fi.ntag[1][1] = 0x00;
    g_fi.ntag[1][2] = 0xFE;
}

void od_nrf_i2c_begin(uint8_t scl, uint8_t sda)
{
    g_fi.scl = scl;
    g_fi.sda = sda;
    g_fi.sessions++;
    g_fi.open = 1;
}

void od_nrf_i2c_end(void) { g_fi.open = 0; }

static void log_w(uint8_t addr, uint8_t sub)
{
    if (g_fi.nlog < (int)(sizeof g_fi.log / sizeof g_fi.log[0])) {
        g_fi.log[g_fi.nlog][0] = addr;
        g_fi.log[g_fi.nlog][1] = sub;
        g_fi.nlog++;
    }
}

bool od_nrf_i2c_write(uint8_t a, const uint8_t *w, uint16_t n)
{
    if (!g_fi.open) {
        g_fi.closed_access++;
        return false;
    }
    if (g_fi.chip == FAKE_NTAG && a == 0x55) {
        if (n == 1) {
            g_fi.ptr = w[0];
            g_fi.reg = -1;
        } else if (n == 2 && w[0] == 0xFE) {
            g_fi.reg = w[1];
        } else if (n == 17) {
            log_w(a, w[0]);
            if (w[0] == 0 || w[0] > 0x37) {
                g_fi.forbidden++;   /* block 0 / config / lock: must never be written */
            }
            memcpy(g_fi.ntag[w[0]], w + 1, 16);
        } else {
            return false;
        }
        return true;
    }
    if (g_fi.chip == FAKE_TNB) {
        if (a == 0x30 || a == 0x43) {
            return true;
        }
        if ((a == 0x48 || a == 0x40) && n == 17) {
            log_w(a, w[0]);
            if (a == 0x48) {
                memcpy(g_fi.tnb_ai, w + 1, 16);
            } else if (w[0] >= 0x10 && (w[0] & 0x0F) == 0) {
                memcpy(&g_fi.tnb_data[w[0] - 0x10], w + 1, 16);
            }
            return true;
        }
    }
    return false;
}

bool od_nrf_i2c_read(uint8_t a, uint8_t *r, uint16_t n)
{
    if (!g_fi.open || g_fi.chip != FAKE_NTAG || a != 0x55) {
        return false;
    }
    if (g_fi.reg >= 0) {
        r[0] = (uint8_t)g_fi.ns_reg;   /* NS_REG: not busy unless a test says so */
        g_fi.reg = -1;
        return n == 1;
    }
    memcpy(r, g_fi.ntag[g_fi.ptr], n > 16 ? 16 : n);
    return true;
}

bool od_nrf_i2c_write_read(uint8_t a, const uint8_t *w, uint16_t wn, uint8_t *r, uint16_t rn)
{
    if (!g_fi.open || g_fi.chip != FAKE_TNB || wn != 1) {
        return false;
    }
    if (a == 0x30 || a == 0x43) {
        memset(r, 0, rn);
        return true;
    }
    if (a == 0x48 && rn == 16) {
        memcpy(r, g_fi.tnb_ai, 16);
        return true;
    }
    if (a == 0x40 && rn == 16 && w[0] >= 0x10) {
        memcpy(r, &g_fi.tnb_data[w[0] - 0x10], 16);
        return true;
    }
    return false;
}
