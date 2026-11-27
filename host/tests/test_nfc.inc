/* test_nfc.inc -- NFC (0x2A config, CMD_NFC_ENDPOINT 0x0083), included by test_service.c.
 * The chip is host/tests/fake_i2c.c: an NTAG I2C plus or a TNB132M behind the I2C calls. */
#include "fake_i2c.h"

#define FD_PIN 11u

static void nfc_config(uint8_t ic, uint8_t fd_mode, uint8_t enabled)
{
    struct blob x;
    struct DataBus b;
    struct NfcConfig c;

    memset(&b, 0, sizeof b);
    b.instance_number = 0;
    b.bus_type = 0x01;   /* I2C */
    b.pin_1 = 9;         /* SCL */
    b.pin_2 = 8;         /* SDA */
    b.pin_3 = 10;        /* power */
    b.pin_4 = b.pin_5 = b.pin_6 = b.pin_7 = 0xFF;
    memset(&c, 0, sizeof c);
    c.nfc_ic_type = ic;
    c.flags = enabled;
    c.field_detect_pin = fd_mode ? FD_PIN : 0xFF;
    c.field_detect_mode = fd_mode;
    c.field_detect_active = 1;
    c.power_pin = 0xFF;  /* bus pin_3 */
    c.adv_button_byte_index = 10;
    blob_start(&x);
    blob_fixed(&x, 0x24, &b, sizeof b);
    blob_fixed(&x, 0x2A, &c, sizeof c);
    blob_end(&x);
    CHECK(write_config(&x) == RESP_ACK);
}

static int nfc(const uint8_t *body, uint16_t n) { return tx(CMD_NFC_ENDPOINT, body, n); }
#define NFC(...)                                     \
    do {                                             \
        const uint8_t b_[] = { __VA_ARGS__ };        \
        nfc(b_, sizeof b_);                          \
    } while (0)
#define NACK_IS(e) LAST(0xFF, 0x83, 0xFF, (e))

/* the NDEF bytes of the fake NTAG, from block 1 */
static const uint8_t *ntag_mem(void) { return g_fi.ntag[1]; }

static void test_nfc_wire_errors(void)
{
    /* with no 0x2A config the endpoint still answers, and the tag calls fail */
    fake_i2c_reset(FAKE_NTAG);
    tx(CMD_CONFIG_CLEAR, NULL, 0);
    NFC(0x00);
    CHECK(NACK_IS(NFC_ERR_READ_FAILED));
    NFC(0x01, 0x00, 0x00, 0x02, 'h', 'i');
    CHECK(NACK_IS(NFC_ERR_TAG_WRITE_FAILED));
    CHECK(g_fi.sessions == 0);                         /* the chip was never touched */

    CHECK(nfc(NULL, 0) == 1 && NACK_IS(NFC_ERR_MALFORMED));
    NFC(0x42);
    CHECK(NACK_IS(NFC_ERR_UNKNOWN_SUBCMD));
    NFC(0x01, 0x00, 0x00);
    CHECK(NACK_IS(NFC_ERR_MALFORMED));                 /* short header */
    NFC(0x01, 0x09, 0xFF, 0xFF, 'x');
    CHECK(NACK_IS(NFC_ERR_MALFORMED));                 /* the length before the type */
    NFC(0x01, 0x09, 0x00, 0x01, 'x');
    CHECK(NACK_IS(NFC_ERR_INVALID_REC_TYPE));
    NFC(0x10, 0x09, 0x00, 0x01);
    CHECK(NACK_IS(NFC_ERR_INVALID_REC_TYPE));
    NFC(0x10, 0x00, 0x00, 0x00);
    CHECK(NACK_IS(NFC_ERR_BAD_TOTAL_LEN));
    NFC(0x10, 0x00, 0x02, 0x01);
    CHECK(NACK_IS(NFC_ERR_BAD_TOTAL_LEN));             /* 513 > 512 */
    NFC(0x11, 'a');
    CHECK(NACK_IS(NFC_ERR_CHUNK_NO_START));
    NFC(0x12);
    CHECK(NACK_IS(NFC_ERR_CHUNK_NO_START));
    NFC(0x10, 0x00, 0x00, 0x03);
    CHECK(LAST(0x00, 0x83, 0x82));
    NFC(0x11);
    CHECK(NACK_IS(NFC_ERR_MALFORMED));                 /* empty chunk */
    NFC(0x11, 'a', 'b');
    CHECK(LAST(0x00, 0x83, 0x82));
    NFC(0x12);
    CHECK(NACK_IS(NFC_ERR_END_LEN_MISMATCH));          /* retryable ... */
    NFC(0x11, 'c', 'd');
    CHECK(NACK_IS(NFC_ERR_CHUNK_OVERFLOW));            /* ... an overflow is not */
    NFC(0x12);
    CHECK(NACK_IS(NFC_ERR_CHUNK_NO_START));
    /* a disconnect drops a chunked write */
    NFC(0x10, 0x00, 0x00, 0x01);
    evt(BLE_GAP_EVT_DISCONNECTED);
    connect();
    NFC(0x11, 'a');
    CHECK(NACK_IS(NFC_ERR_CHUNK_NO_START));
}

static void test_nfc_ntag(void)
{
    fake_i2c_reset(FAKE_NTAG);
    nfc_config(OD_NFC_IC_AUTO, 0, 1);
    CHECK(g_fi.sessions == 1 && !g_fi.open);           /* boot/reload init ran and ended */
    CHECK(g_fi.scl == 9 && g_fi.sda == 8);

    /* Text: D1 01 len 'T' 02 'e' 'n' + text, in the TLV 03 len .. FE */
    NFC(0x01, OD_NFC_REC_TEXT, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o');
    CHECK(LAST(0x00, 0x83, 0x81));
    {
        const uint8_t want[] = { 0x03, 12, 0xD1, 0x01, 8, 'T', 0x02, 'e', 'n',
                                 'h', 'e', 'l', 'l', 'o', 0xFE };
        CHECK(memcmp(ntag_mem(), want, sizeof want) == 0);
    }
    CHECK(g_fi.forbidden == 0 && g_fi.closed_access == 0 && !g_fi.open);
    NFC(0x00);
    CHECK(LAST(0x00, 0x83, 0x80, OD_NFC_REC_TEXT, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o'));

    /* URI */
    NFC(0x01, OD_NFC_REC_URI, 0x00, 0x0B, 'h', 't', 't', 'p', 's', ':', '/', '/', 'o', '.', 'd');
    CHECK(LAST(0x00, 0x83, 0x81));
    CHECK(ntag_mem()[2] == 0xD1 && ntag_mem()[5] == 'U' && ntag_mem()[6] == 0x00);
    NFC(0x00);
    CHECK(LAST(0x00, 0x83, 0x80, OD_NFC_REC_URI, 0x00, 0x0B, 'h', 't', 't', 'p', 's', ':', '/',
               '/', 'o', '.', 'd'));

    /* MIME: [tl][type][body] */
    NFC(0x01, OD_NFC_REC_MIME, 0x00, 0x06, 3, 'a', '/', 'b', 0x01, 0x02);
    CHECK(LAST(0x00, 0x83, 0x81));
    CHECK(ntag_mem()[2] == 0xD2 && ntag_mem()[3] == 3 && ntag_mem()[4] == 2);
    NFC(0x00);
    CHECK(LAST(0x00, 0x83, 0x80, OD_NFC_REC_MIME, 0x00, 0x06, 3, 'a', '/', 'b', 0x01, 0x02));

    /* well-known raw */
    NFC(0x01, OD_NFC_REC_WELL_KNOWN_RAW, 0x00, 0x04, 2, 'S', 'p', 0x7A);
    CHECK(LAST(0x00, 0x83, 0x81));
    NFC(0x00);
    CHECK(LAST(0x00, 0x83, 0x80, OD_NFC_REC_WELL_KNOWN_RAW, 0x00, 0x04, 2, 'S', 'p', 0x7A));
    NFC(0x01, OD_NFC_REC_MIME, 0x00, 0x02, 0, 'x');
    CHECK(NACK_IS(NFC_ERR_TAG_WRITE_FAILED));          /* MIME without a type */

    /* chunked raw NDEF, 300 bytes: a 3-byte TLV length, block 1 written last */
    {
        static uint8_t rec[300];
        rec[0] = 0xD2; rec[1] = 1; rec[2] = 0; rec[3] = 'x';   /* not valid as a record: raw */
        for (int i = 4; i < 300; i++) rec[i] = (uint8_t)i;
        rec[2] = 0xFF;
        NFC(0x10, OD_NFC_REC_RAW_NDEF, 0x01, 0x2C);
        CHECK(LAST(0x00, 0x83, 0x82));
        for (int o = 0; o < 300; o += 200) {
            uint8_t f[201];
            const int k = 300 - o < 200 ? 300 - o : 200;
            f[0] = 0x11;
            memcpy(f + 1, rec + o, (size_t)k);
            nfc(f, (uint16_t)(k + 1));
            CHECK(LAST(0x00, 0x83, 0x82));
        }
        g_fi.nlog = 0;
        NFC(0x12);
        CHECK(LAST(0x00, 0x83, 0x81));
        CHECK(ntag_mem()[0] == 0x03 && ntag_mem()[1] == 0xFF && ntag_mem()[2] == 0x01 &&
              ntag_mem()[3] == 0x2C);
        CHECK(memcmp(&ntag_mem()[4], rec, 12) == 0 && memcmp(g_fi.ntag[2], rec + 12, 16) == 0);
        CHECK(g_fi.ntag[1 + 304 / 16][304 % 16] == 0xFE);   /* terminator after 4 + 300 */
        CHECK(g_fi.nlog == 20 && g_fi.log[g_fi.nlog - 1][1] == 1);   /* 20 blocks, block 1 last */
        CHECK(g_fi.forbidden == 0);
        NFC(0x00);
        CHECK(NACK_IS(NFC_ERR_READ_FAILED));          /* 300 > the 218 B read cap */
    }

    /* EEPROM write error and an absent chip */
    g_fi.ns_reg = 0x04;
    NFC(0x01, OD_NFC_REC_TEXT, 0x00, 0x01, 'z');
    CHECK(NACK_IS(NFC_ERR_TAG_WRITE_FAILED));
    g_fi.ns_reg = 0;
    g_fi.chip = FAKE_NONE;
    NFC(0x00);
    CHECK(NACK_IS(NFC_ERR_READ_FAILED));
    NFC(0x01, OD_NFC_REC_TEXT, 0x00, 0x01, 'z');
    CHECK(NACK_IS(NFC_ERR_TAG_WRITE_FAILED));

    /* disabled config: no chip access */
    fake_i2c_reset(FAKE_NTAG);
    nfc_config(OD_NFC_IC_AUTO, 0, 0);
    NFC(0x00);
    CHECK(NACK_IS(NFC_ERR_READ_FAILED) && g_fi.sessions == 0);
    /* unknown IC selector: refused the same way */
    nfc_config(7, 0, 1);
    NFC(0x00);
    CHECK(NACK_IS(NFC_ERR_READ_FAILED) && g_fi.sessions == 0);
}

static void test_nfc_tnb132m(void)
{
    fake_i2c_reset(FAKE_TNB);
    g_fi.tnb_ai[0] = 0x10;
    g_fi.tnb_ai[10] = 0x01;   /* RWFlag, kept across writes */
    nfc_config(OD_NFC_IC_AUTO, 0, 1);   /* AUTO: no NTAG answers, so TNB132M */
    NFC(0x01, OD_NFC_REC_URI, 0x00, 0x03, 'a', ':', 'b');
    CHECK(LAST(0x00, 0x83, 0x81));
    {
        const uint8_t rec[] = { 0xD1, 0x01, 0x04, 'U', 0x00, 'a', ':', 'b' };
        CHECK(memcmp(g_fi.tnb_data, rec, sizeof rec) == 0);
        CHECK(g_fi.tnb_ai[0] == 0x10 && g_fi.tnb_ai[1] == 0x02 && g_fi.tnb_ai[4] == 0x3C);
        CHECK(g_fi.tnb_ai[10] == 0x01 && g_fi.tnb_ai[13] == sizeof rec);
        uint16_t sum = 0;
        for (int i = 0; i < 14; i++) sum = (uint16_t)(sum + g_fi.tnb_ai[i]);
        CHECK(g_fi.tnb_ai[14] == (sum >> 8) && g_fi.tnb_ai[15] == (sum & 0xFF));
    }
    NFC(0x00);
    CHECK(LAST(0x00, 0x83, 0x80, OD_NFC_REC_URI, 0x00, 0x03, 'a', ':', 'b'));
    /* a record past the one-byte data offset is refused rather than written to the wrong place */
    {
        uint8_t f[4 + 241];
        f[0] = 0x10; f[1] = OD_NFC_REC_RAW_NDEF; f[2] = 0; f[3] = 241;
        nfc(f, 4);
        f[0] = 0x11;
        memset(f + 1, 0xD5, 241);
        nfc(f, 242);
        NFC(0x12);
        CHECK(NACK_IS(NFC_ERR_TAG_WRITE_FAILED));
    }
}

static void test_nfc_field_detect(void)
{
    fake_i2c_reset(FAKE_NTAG);
    g_fd_level = 0;
    nfc_config(OD_NFC_IC_NTAG_I2C, 1, 1);
    CHECK(dynamicreturndata[10] == 0x00);
    CHECK(!od_nrf_nfc_process());
    g_fd_level = 1;                       /* a phone */
    CHECK(od_nrf_nfc_process());
    CHECK(dynamicreturndata[10] == 0x03); /* state 1, tap 1 */
    CHECK(!od_nrf_nfc_process());
    g_fd_level = 0;
    CHECK(od_nrf_nfc_process());
    CHECK(dynamicreturndata[10] == 0x02);
    g_fd_level = 1;
    CHECK(od_nrf_nfc_process());
    CHECK(dynamicreturndata[10] == 0x05); /* tap 2 */
    g_fd_level = 0;
    (void)od_nrf_nfc_process();
    /* debounce: a change inside the window waits, and is taken once the window has passed */
    {
        struct NfcConfig *c = &globalConfig.nfc_configs[0];
        c->field_detect_debounce_ms = 200;
        od_nrf_nfc_init(&globalConfig);
        g_now += 1000;
        g_fd_level = 1;
        CHECK(od_nrf_nfc_process() && dynamicreturndata[10] == 0x03);
        g_now += 50;
        g_fd_level = 0;
        CHECK(!od_nrf_nfc_process() && dynamicreturndata[10] == 0x03);   /* held */
        g_now += 50;
        g_fd_level = 1;
        CHECK(!od_nrf_nfc_process());                                     /* back: no change */
        g_fd_level = 0;
        g_now += 200;
        CHECK(od_nrf_nfc_process() && dynamicreturndata[10] == 0x02);    /* taken late */
    }
    /* mode 0: no field detect */
    nfc_config(OD_NFC_IC_NTAG_I2C, 0, 1);
    g_fd_level = 1;
    CHECK(!od_nrf_nfc_process());
    g_fd_level = 0;
    tx(CMD_CONFIG_CLEAR, NULL, 0);
}

static void test_nfc(void)
{
    test_nfc_wire_errors();
    test_nfc_ntag();
    test_nfc_tnb132m();
    test_nfc_field_detect();
}
