/* od_nrf_nfc.c -- see od_nrf_nfc.h. */
#include "od_nrf_nfc.h"

#include <string.h>

#include "nrf_delay.h"
#include "nrf_gpio.h"
#include "od_nrf_glue.h"
#include "od_nrf_i2c.h"
#include "opendisplay_protocol.h"
#ifndef OD_NRF_HOST_TEST
#include "nrf_drv_gpiote.h"
#endif

extern uint8_t dynamicreturndata[11];

#define PIN_NONE        0xFFu
#define NFC_ASM_MAX     512u   /* the wire's assembly limit */
#define NFC_READ_MAX    218u   /* the wire's read cap: one notification */
#define RBUF            256u   /* NDEF bytes a read can take in */

/* NXP NTAG I2C plus */
#define NTAG_ADDR       0x55u
#define NTAG_FIRST      0x01u  /* user memory: blocks 0x01..0x37 on both sizes */
#define NTAG_LAST       0x37u
#define NTAG_SESSION    0xFEu
#define NTAG_NS_REG     0x06u
#define NS_WR_BUSY      0x02u
#define NS_WR_ERR       0x04u

/* TNB132M (Type 3): attribute block, data window, control, cache */
#define TNB_AI          0x48u
#define TNB_DATA        0x40u
#define TNB_CTL         0x30u
#define TNB_CACHE       0x43u
#define TNB_MAX         240u   /* data offset is one byte: 0x10 + 16*14 is the last block */

static struct {
    bool on;
    uint8_t ic;          /* configured selector */
    uint8_t chip;        /* resolved: NTAG_I2C or TNB132M, 0 = not yet */
    uint8_t scl, sda, pwr;
    uint8_t pwr_delay;
    /* field detect */
    bool fd;
    uint8_t fd_pin, fd_mode, fd_debounce, fd_idx;
    bool fd_high;
    uint8_t fd_state, fd_ctr;
    uint32_t fd_last;
    bool fd_irq_on;
    volatile bool fd_irq;
} s;

static struct {
    bool active;
    uint8_t type;
    uint16_t total, got;
    uint8_t data[NFC_ASM_MAX];
} s_asm;

static uint8_t s_rbuf[RBUF];

/* ---- power and session --------------------------------------------------------------------- */

static void session_begin(void)
{
    if (s.pwr != PIN_NONE) {
        nrf_gpio_cfg_output(s.pwr);
        nrf_gpio_pin_set(s.pwr);
    }
    od_nrf_i2c_begin(s.scl, s.sda);
    od_nrf_delay_ms(s.pwr != PIN_NONE ? s.pwr_delay : 10u);
}

static void session_end(void)
{
    od_nrf_i2c_end();
    if (s.pwr != PIN_NONE) {
        nrf_gpio_pin_clear(s.pwr);
        nrf_gpio_cfg_default(s.pwr);
    }
}

/* ---- TNB132M (Type 3) ------------------------------------------------------------------------ */

static void tnb_prime(void)
{
    static const uint8_t open_window[2] = { 0x21u, 0x04u };
    static const uint8_t sel_25 = 0x25u, sel_30 = 0x30u;
    uint8_t sink[16];

    /* wake/window pokes; their ACKs are not part of the flow */
    (void)od_nrf_i2c_write(TNB_CTL, open_window, 2u);
    (void)od_nrf_i2c_write_read(TNB_CTL, &sel_25, 1u, sink, 1u);
    od_nrf_delay_ms(20u);
    (void)od_nrf_i2c_write_read(TNB_CACHE, &sel_30, 1u, sink, 16u);
}

static bool tnb_rd16(uint8_t dev, uint8_t sub, uint8_t *out)
{
    return od_nrf_i2c_write_read(dev, &sub, 1u, out, 16u);
}

static bool tnb_wr16(uint8_t dev, uint8_t sub, const uint8_t *in)
{
    uint8_t b[17];
    b[0] = sub;
    memcpy(b + 1, in, 16u);
    return od_nrf_i2c_write(dev, b, sizeof b);
}

/* ---- NTAG I2C plus (Type 2) ----------------------------------------------------------------- */

static bool ntag_probe(void)
{
    const uint8_t mema = 0x00u;
    return od_nrf_i2c_write(NTAG_ADDR, &mema, 1u);
}

static bool ntag_rd(uint8_t blk, uint8_t *out)
{
    return od_nrf_i2c_write(NTAG_ADDR, &blk, 1u) && od_nrf_i2c_read(NTAG_ADDR, out, 16u);
}

/* Write one block and wait for its EEPROM cycle (about 4 ms). */
static bool ntag_wr(uint8_t blk, const uint8_t *in)
{
    uint8_t b[17];
    b[0] = blk;
    memcpy(b + 1, in, 16u);
    if (!od_nrf_i2c_write(NTAG_ADDR, b, sizeof b)) {
        return false;
    }
    od_nrf_delay_ms(5u);
    for (uint8_t t = 0; t < 20u; t++) {
        const uint8_t reg[2] = { NTAG_SESSION, NTAG_NS_REG };
        uint8_t ns = 0xFFu;
        if (od_nrf_i2c_write(NTAG_ADDR, reg, 2u) && od_nrf_i2c_read(NTAG_ADDR, &ns, 1u)) {
            if ((ns & NS_WR_ERR) != 0u) {
                return false;
            }
            if ((ns & NS_WR_BUSY) == 0u) {
                return true;
            }
        }
        od_nrf_delay_ms(1u);
    }
    return false;
}

/* The chip, resolved once per config: AUTO probes the NTAG address. Inside a session. */
static uint8_t chip(void)
{
    if (s.chip == 0u) {
        if (s.ic == OD_NFC_IC_TNB132M) {
            s.chip = OD_NFC_IC_TNB132M;
        } else if (s.ic == OD_NFC_IC_NTAG_I2C || ntag_probe()) {
            s.chip = OD_NFC_IC_NTAG_I2C;
        } else {
            s.chip = OD_NFC_IC_TNB132M;
        }
    }
    return s.chip;
}

/* ---- NDEF records ----------------------------------------------------------------------------- */

/* A record is a short header the firmware writes plus the host's bytes. */
struct rec {
    uint8_t hdr[12];
    uint8_t hn;
    const uint8_t *body;
    uint16_t bn;
};

static uint8_t rec_at(const struct rec *r, uint16_t i)
{
    if (i < r->hn) {
        return r->hdr[i];
    }
    i = (uint16_t)(i - r->hn);
    return i < r->bn ? r->body[i] : 0x00u;
}

/* The record bytes for one rec_type, the encoding of the other 3.0 targets. */
static bool rec_build(uint8_t type, const uint8_t *d, uint16_t n, struct rec *r)
{
    uint16_t pl;

    memset(r, 0, sizeof *r);
    if (d == NULL || n == 0u) {
        return false;
    }
    switch (type) {
    case OD_NFC_REC_TEXT:
        pl = (uint16_t)(3u + n);
        if (pl > 255u) {
            return false;
        }
        memcpy(r->hdr, (const uint8_t[]){ 0xD1u, 0x01u, (uint8_t)pl, 'T', 0x02u, 'e', 'n' }, 7u);
        r->hn = 7u;
        r->body = d;
        r->bn = n;
        return true;
    case OD_NFC_REC_URI:
        pl = (uint16_t)(1u + n);
        if (pl > 255u) {
            return false;
        }
        memcpy(r->hdr, (const uint8_t[]){ 0xD1u, 0x01u, (uint8_t)pl, 'U', 0x00u }, 5u);
        r->hn = 5u;
        r->body = d;
        r->bn = n;
        return true;
    case OD_NFC_REC_WELL_KNOWN_RAW:
    case OD_NFC_REC_MIME: {
        const uint8_t tl = d[0];
        if (n < (type == OD_NFC_REC_MIME ? 3u : 2u) || tl == 0u || 1u + (uint32_t)tl > n) {
            return false;
        }
        pl = (uint16_t)(n - 1u - tl);
        if (pl > 255u) {
            return false;
        }
        r->hdr[0] = type == OD_NFC_REC_MIME ? 0xD2u : 0xD1u;
        r->hdr[1] = tl;
        r->hdr[2] = (uint8_t)pl;
        r->hn = 3u;
        r->body = d + 1;
        r->bn = (uint16_t)(n - 1u);
        return true;
    }
    case OD_NFC_REC_RAW_NDEF:
        r->body = d;
        r->bn = n;
        return true;
    default:
        return false;
    }
}

/* The first record of an NDEF message back into the host's form (inverse of rec_build). */
static bool rec_parse(const uint8_t *d, uint32_t ln, uint8_t *type, uint8_t *out, uint16_t *olen,
                      uint16_t cap)
{
    if (ln < 3u || (d[0] & 0x10u) == 0u) {
        return false;   /* short records only */
    }
    const uint8_t tnf = d[0] & 0x07u;
    const uint8_t tl = d[1];
    const uint8_t pl = d[2];
    if ((d[0] & 0x08u) != 0u || (tnf != 1u && tnf != 2u)) {
        if (ln > cap) {   /* ID field or another TNF: the message verbatim */
            return false;
        }
        *type = OD_NFC_REC_RAW_NDEF;
        memcpy(out, d, ln);
        *olen = (uint16_t)ln;
        return true;
    }
    if (3u + (uint32_t)tl + pl > ln) {
        return false;
    }
    const uint8_t *t = d + 3;
    const uint8_t *p = t + tl;
    if (tnf == 1u && tl == 1u && (t[0] == 'T' || t[0] == 'U')) {
        uint32_t skip;
        if (pl < 1u) {
            return false;
        }
        if (t[0] == 'T') {
            skip = 1u + (p[0] & 0x3Fu);
            *type = OD_NFC_REC_TEXT;
        } else {
            if (p[0] != 0x00u) {
                return false;   /* abbreviated URI prefixes are not expanded */
            }
            skip = 1u;
            *type = OD_NFC_REC_URI;
        }
        if (skip > pl || pl - skip > cap) {
            return false;
        }
        memcpy(out, p + skip, pl - skip);
        *olen = (uint16_t)(pl - skip);
        return true;
    }
    if (tnf == 2u && tl == 0u) {
        return false;
    }
    if (1u + (uint32_t)tl + pl > cap) {
        return false;
    }
    *type = tnf == 2u ? OD_NFC_REC_MIME : OD_NFC_REC_WELL_KNOWN_RAW;
    out[0] = tl;
    memcpy(out + 1, t, (uint32_t)tl + pl);
    *olen = (uint16_t)(1u + tl + pl);
    return true;
}

/* ---- chip read / write ------------------------------------------------------------------------ */

static bool tnb_write(const struct rec *r, uint16_t len)
{
    uint8_t ai[16] = { 0x10u, 0x02u, 0x01u, 0x00u, 0x3Cu };
    uint8_t cur[16];
    uint16_t sum = 0;
    uint8_t blk[16];

    if (len > TNB_MAX) {
        return false;
    }
    tnb_prime();
    od_nrf_delay_ms(2u);
    ai[12] = (uint8_t)(len >> 8);
    ai[13] = (uint8_t)len;
    if (tnb_rd16(TNB_AI, 0x00u, cur) && (cur[0] & 0xF0u) == 0x10u) {
        ai[10] = cur[10];   /* keep RWFlag */
    }
    for (uint8_t i = 0; i < 14u; i++) {
        sum = (uint16_t)(sum + ai[i]);
    }
    ai[14] = (uint8_t)(sum >> 8);
    ai[15] = (uint8_t)sum;
    if (!tnb_wr16(TNB_AI, 0x00u, ai)) {
        return false;
    }
    od_nrf_delay_ms(10u);
    for (uint16_t b = 0; b * 16u < len; b++) {
        for (uint8_t i = 0; i < 16u; i++) {
            blk[i] = rec_at(r, (uint16_t)(b * 16u + i));
        }
        if (!tnb_wr16(TNB_DATA, (uint8_t)(0x10u + b * 16u), blk)) {
            return false;
        }
        od_nrf_delay_ms(10u);
    }
    return true;
}

static bool tnb_read(uint32_t *ln)
{
    uint8_t ai[16];

    tnb_prime();
    od_nrf_delay_ms(2u);
    if (!tnb_rd16(TNB_AI, 0x00u, ai) || (ai[0] & 0xF0u) != 0x10u) {
        return false;
    }
    *ln = ((uint32_t)ai[11] << 16) | ((uint32_t)ai[12] << 8) | ai[13];
    if (*ln == 0u || *ln > TNB_MAX) {
        return false;
    }
    for (uint16_t b = 0; b * 16u < *ln; b++) {
        /* the chip caches two blocks per anchor: re-anchor on the attribute block each time */
        (void)tnb_rd16(TNB_AI, 0x00u, ai);
        if (!tnb_rd16(TNB_DATA, (uint8_t)(0x10u + b * 16u), &s_rbuf[b * 16u])) {
            return false;
        }
    }
    return true;
}

/* Type 2 layout: [03][len or FF len16][message][FE]. Block 1 (the length) goes last, so a phone
 * never reads a length that runs into old bytes. */
static bool ntag_write(const struct rec *r, uint16_t len)
{
    uint8_t tl[4] = { 0x03u };
    uint8_t th;
    uint8_t blk[16];

    if (len < 0xFFu) {
        tl[1] = (uint8_t)len;
        th = 2u;
    } else {
        tl[1] = 0xFFu;
        tl[2] = (uint8_t)(len >> 8);
        tl[3] = (uint8_t)len;
        th = 4u;
    }
    const uint32_t total = (uint32_t)th + len + 1u;
    const uint16_t nblk = (uint16_t)((total + 15u) / 16u);
    if (nblk > NTAG_LAST - NTAG_FIRST + 1u) {
        return false;
    }
    for (uint16_t k = nblk; k-- > 0u;) {
        for (uint8_t i = 0; i < 16u; i++) {
            const uint32_t o = (uint32_t)k * 16u + i;
            blk[i] = o < th ? tl[o] : o < th + (uint32_t)len ? rec_at(r, (uint16_t)(o - th))
                   : o == th + (uint32_t)len ? 0xFEu : 0x00u;
        }
        if (!ntag_wr((uint8_t)(NTAG_FIRST + k), blk)) {
            return false;
        }
    }
    return true;
}

/* Finds the NDEF TLV and leaves the message at s_rbuf[0..ln). */
static bool ntag_read(uint32_t *ln)
{
    uint8_t blk[16];
    uint32_t have = 0, pos = 0, len, want = 0;
    uint8_t next = NTAG_FIRST;

    /* walk the TLVs through a small window: stream offset `pos`, bytes [0, have) are read */
    static uint8_t tlv[16 * 3];
    for (;;) {
        while (have < pos + 4u && next <= NTAG_LAST && have + 16u <= sizeof tlv) {
            if (!ntag_rd(next++, &tlv[have])) {
                return false;
            }
            have += 16u;
        }
        if (pos >= have) {
            return false;
        }
        const uint8_t t = tlv[pos];
        if (t == 0x00u) {
            pos++;
            continue;
        }
        if (t == 0xFEu || pos + 1u >= have) {
            return false;   /* empty tag, or no NDEF TLV near the start */
        }
        len = tlv[pos + 1u];
        uint32_t hdr = 2u;
        if (len == 0xFFu) {
            if (pos + 3u >= have) {
                return false;
            }
            len = ((uint32_t)tlv[pos + 2u] << 8) | tlv[pos + 3u];
            hdr = 4u;
        }
        if (t != 0x03u) {
            pos += hdr + len;
            if (pos >= sizeof tlv) {
                return false;
            }
            continue;
        }
        pos += hdr;
        want = len;
        break;
    }
    if (want == 0u || want > RBUF) {
        return false;
    }
    /* copy what the window holds, then read the rest block by block */
    uint32_t got = have > pos ? have - pos : 0u;
    if (got > want) {
        got = want;
    }
    memcpy(s_rbuf, &tlv[pos], got);
    while (got < want) {
        if (next > NTAG_LAST || !ntag_rd(next++, blk)) {
            return false;
        }
        const uint32_t k = want - got < 16u ? want - got : 16u;
        memcpy(&s_rbuf[got], blk, k);
        got += k;
    }
    *ln = want;
    return true;
}

static bool app_write(uint8_t type, const uint8_t *d, uint16_t n)
{
    struct rec r;
    bool ok;

    if (!s.on || !rec_build(type, d, n, &r)) {
        return false;
    }
    const uint16_t len = (uint16_t)(r.hn + r.bn);
    session_begin();
    ok = chip() == OD_NFC_IC_NTAG_I2C ? ntag_write(&r, len) : tnb_write(&r, len);
    session_end();
    return ok;
}

static bool app_read(uint8_t *type, uint8_t *out, uint16_t *olen)
{
    uint32_t ln = 0;
    bool ok;

    if (!s.on) {
        return false;
    }
    session_begin();
    ok = chip() == OD_NFC_IC_NTAG_I2C ? ntag_read(&ln) : tnb_read(&ln);
    session_end();
    return ok && rec_parse(s_rbuf, ln, type, out, olen, NFC_READ_MAX);
}

/* ---- 0x0083 ------------------------------------------------------------------------------------ */

static void nack(od_nrf_nfc_send_fn send, uint8_t err)
{
    const uint8_t f[4] = { RESP_NACK, RESP_NFC_ENDPOINT, 0xFFu, err };
    send(f, sizeof f);
}

static void ack(od_nrf_nfc_send_fn send, uint8_t status)
{
    const uint8_t f[3] = { RESP_ACK, RESP_NFC_ENDPOINT, status };
    send(f, sizeof f);
}

static bool type_ok(uint8_t t)
{
    return t <= OD_NFC_REC_RAW_NDEF;
}

void od_nrf_nfc_disconnected(void)
{
    s_asm.active = false;
}

void od_nrf_nfc_frame(const uint8_t *b, uint16_t n, od_nrf_nfc_send_fn send)
{
    if (b == NULL || n < 1u) {
        nack(send, NFC_ERR_MALFORMED);
        return;
    }
    switch (b[0]) {
    case NFC_SUB_READ: {
        uint8_t f[6u + NFC_READ_MAX];
        uint16_t len = 0;
        uint8_t type = 0;
        if (!app_read(&type, &f[6], &len) || len > NFC_READ_MAX) {
            nack(send, NFC_ERR_READ_FAILED);
            return;
        }
        f[0] = RESP_ACK;
        f[1] = RESP_NFC_ENDPOINT;
        f[2] = NFC_STATUS_READ_DATA;
        f[3] = type;
        f[4] = (uint8_t)(len >> 8);
        f[5] = (uint8_t)len;
        send(f, (uint16_t)(6u + len));
        return;
    }
    case NFC_SUB_WRITE: {
        if (n < 4u) {
            nack(send, NFC_ERR_MALFORMED);
            return;
        }
        const uint16_t decl = (uint16_t)((b[2] << 8) | b[3]);
        if ((uint32_t)decl + 4u > n) {   /* the length first, then the type */
            nack(send, NFC_ERR_MALFORMED);
            return;
        }
        if (!type_ok(b[1])) {
            nack(send, NFC_ERR_INVALID_REC_TYPE);
            return;
        }
        if (!app_write(b[1], b + 4, decl)) {
            nack(send, NFC_ERR_TAG_WRITE_FAILED);
            return;
        }
        ack(send, NFC_STATUS_WRITE_COMMITTED);
        return;
    }
    case NFC_SUB_WRITE_START: {
        if (n < 4u) {
            nack(send, NFC_ERR_MALFORMED);
            return;
        }
        const uint16_t total = (uint16_t)((b[2] << 8) | b[3]);
        if (!type_ok(b[1])) {
            nack(send, NFC_ERR_INVALID_REC_TYPE);
            return;
        }
        if (total == 0u || total > NFC_ASM_MAX) {
            nack(send, NFC_ERR_BAD_TOTAL_LEN);
            return;
        }
        s_asm.active = true;
        s_asm.type = b[1];
        s_asm.total = total;
        s_asm.got = 0;
        ack(send, NFC_STATUS_CHUNK_ACCEPTED);
        return;
    }
    case NFC_SUB_WRITE_DATA:
        if (!s_asm.active) {
            nack(send, NFC_ERR_CHUNK_NO_START);
            return;
        }
        if (n < 2u) {
            nack(send, NFC_ERR_MALFORMED);
            return;
        }
        if ((uint32_t)s_asm.got + (n - 1u) > s_asm.total) {
            s_asm.active = false;
            nack(send, NFC_ERR_CHUNK_OVERFLOW);
            return;
        }
        memcpy(&s_asm.data[s_asm.got], b + 1, n - 1u);
        s_asm.got = (uint16_t)(s_asm.got + n - 1u);
        ack(send, NFC_STATUS_CHUNK_ACCEPTED);
        return;
    case NFC_SUB_WRITE_END: {
        if (!s_asm.active) {
            nack(send, NFC_ERR_CHUNK_NO_START);
            return;
        }
        if (s_asm.got != s_asm.total) {
            nack(send, NFC_ERR_END_LEN_MISMATCH);   /* retryable: the assembly stays */
            return;
        }
        s_asm.active = false;
        if (!app_write(s_asm.type, s_asm.data, s_asm.total)) {
            nack(send, NFC_ERR_TAG_WRITE_FAILED);
            return;
        }
        ack(send, NFC_STATUS_WRITE_COMMITTED);
        return;
    }
    default:
        nack(send, NFC_ERR_UNKNOWN_SUBCMD);
        return;
    }
}

/* ---- field detect ------------------------------------------------------------------------------ */

static uint8_t fd_level(void)
{
    const uint32_t raw = nrf_gpio_pin_read(s.fd_pin);
    return (s.fd_high ? raw != 0u : raw == 0u) ? 1u : 0u;
}

static bool fd_refresh(bool force)
{
    const uint8_t now = fd_level();
    const uint32_t t = od_nrf_now_ms();

    if (!force && now == s.fd_state) {
        return false;
    }
    if (!force && s.fd_debounce != 0u && (uint32_t)(t - s.fd_last) < s.fd_debounce) {
        return false;
    }
    s.fd_last = t;
    if (now != 0u && s.fd_state == 0u) {
        s.fd_ctr = (uint8_t)((s.fd_ctr + 1u) & 0x7Fu);
    }
    s.fd_state = now;
    dynamicreturndata[s.fd_idx] = (uint8_t)(now | (uint8_t)(s.fd_ctr << 1));
    return true;
}

#ifndef OD_NRF_HOST_TEST
static void fd_isr(nrf_drv_gpiote_pin_t pin, nrf_gpiote_polarity_t action)
{
    (void)pin;
    (void)action;
    s.fd_irq = true;
}
#endif

static void fd_stop(void)
{
#ifndef OD_NRF_HOST_TEST
    if (s.fd_irq_on) {
        nrf_drv_gpiote_in_uninit(s.fd_pin);
    }
#endif
    s.fd_irq_on = false;
    s.fd = false;
}

static void fd_start(const struct NfcConfig *c)
{
    if (c->field_detect_mode == 0u || c->field_detect_pin == PIN_NONE ||
        c->adv_button_byte_index >= sizeof dynamicreturndata) {
        return;
    }
    s.fd = true;
    s.fd_pin = c->field_detect_pin;
    s.fd_mode = c->field_detect_mode;
    s.fd_high = c->field_detect_active != 0u;
    s.fd_debounce = c->field_detect_debounce_ms;
    s.fd_idx = c->adv_button_byte_index;
    s.fd_state = 0u;
    s.fd_ctr = 0u;
    s.fd_last = od_nrf_now_ms();
    nrf_gpio_cfg_input(s.fd_pin, s.fd_high ? NRF_GPIO_PIN_PULLDOWN : NRF_GPIO_PIN_PULLUP);
#ifndef OD_NRF_HOST_TEST
    if (s.fd_mode == 2u) {
        if (!nrf_drv_gpiote_is_init()) {
            (void)nrf_drv_gpiote_init();
        }
        nrf_drv_gpiote_in_config_t ic = GPIOTE_CONFIG_IN_SENSE_TOGGLE(false);
        ic.pull = s.fd_high ? NRF_GPIO_PIN_PULLDOWN : NRF_GPIO_PIN_PULLUP;
        if (nrf_drv_gpiote_in_init(s.fd_pin, &ic, fd_isr) == NRF_SUCCESS) {
            nrf_drv_gpiote_in_event_enable(s.fd_pin, true);
            s.fd_irq_on = true;
        }
    }
#endif
    dynamicreturndata[s.fd_idx] = 0u;
}

bool od_nrf_nfc_process(void)
{
    if (!s.fd) {
        return false;
    }
    if (s.fd_mode == 2u && s.fd_irq_on) {
        if (!s.fd_irq) {
            return false;
        }
        s.fd_irq = false;
    }
    if (fd_refresh(false)) {
        return true;
    }
    if (fd_level() != s.fd_state) {
        s.fd_irq = true;   /* held back by the debounce: look again on the next pass */
    }
    return false;
}

void od_nrf_nfc_sleep_arm(void)
{
    if (!s.fd) {
        return;
    }
#ifndef OD_NRF_HOST_TEST
    if (s.fd_irq_on) {
        nrf_drv_gpiote_in_uninit(s.fd_pin);
        s.fd_irq_on = false;
    }
    nrf_gpio_cfg_sense_input(s.fd_pin, s.fd_high ? NRF_GPIO_PIN_PULLDOWN : NRF_GPIO_PIN_PULLUP,
                             s.fd_high ? NRF_GPIO_PIN_SENSE_HIGH : NRF_GPIO_PIN_SENSE_LOW);
#endif
}

/* ---- config ------------------------------------------------------------------------------------ */

static const struct DataBus *bus_of(const struct GlobalConfig *g, uint8_t inst)
{
    const struct DataBus *hit = NULL;
    for (uint8_t i = 0; i < g->data_bus_count && i < 4u; i++) {
        if (g->data_buses[i].instance_number == inst) {
            if (hit != NULL) {
                return NULL;   /* declared twice: no bus */
            }
            hit = &g->data_buses[i];
        }
    }
    return hit;
}

static bool pin_ok(uint8_t p)
{
    return p < 32u;
}

void od_nrf_nfc_init(const struct GlobalConfig *g)
{
    const struct NfcConfig *c = NULL;
    const struct DataBus *bus;

    fd_stop();
    s_asm.active = false;
    memset(&s, 0, sizeof s);
    if (g == NULL || !g->loaded) {
        return;
    }
    for (uint8_t i = 0; i < g->nfc_config_count && i < 2u; i++) {
        if ((g->nfc_configs[i].flags & 0x01u) != 0u) {
            c = &g->nfc_configs[i];
            break;
        }
    }
    if (c == NULL) {
        return;
    }
    bus = bus_of(g, c->bus_instance);
    if (bus == NULL || bus->bus_type != 0x01u || !pin_ok(bus->pin_1) || !pin_ok(bus->pin_2)) {
        return;
    }
    if (c->nfc_ic_type != OD_NFC_IC_AUTO && c->nfc_ic_type != OD_NFC_IC_TNB132M &&
        c->nfc_ic_type != OD_NFC_IC_NTAG_I2C) {
        return;
    }
    s.scl = bus->pin_1;
    s.sda = bus->pin_2;
    s.pwr = pin_ok(c->power_pin) ? c->power_pin : pin_ok(bus->pin_3) ? bus->pin_3 : PIN_NONE;
    s.pwr_delay = c->power_on_delay_ms != 0u ? c->power_on_delay_ms : 40u;
    s.ic = c->nfc_ic_type;
    s.on = true;
    fd_start(c);

    /* init sequence: power the chip, identify it, bring a TNB132M's window up and down */
    session_begin();
    if (chip() == OD_NFC_IC_TNB132M) {
        static const uint8_t close_window[2] = { 0x21u, 0x01u };
        tnb_prime();
        od_nrf_delay_ms(20u);
        (void)od_nrf_i2c_write(TNB_CTL, close_window, 2u);
        od_nrf_delay_ms(14u);
    }
    if (s.fd) {
        (void)fd_refresh(true);
    }
    session_end();
}
