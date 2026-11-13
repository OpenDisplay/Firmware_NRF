/* od_epd -- config-driven e-paper driver. See od_epd.h for the rationale.
 *
 * The whole point of this file is that it contains NO panel knowledge. Search
 * it for a panel name, a register number or a delay and you will not find one:
 * every byte it writes came out of the device config.
 */
#include "od_epd.h"

#include <string.h>

#define OD_OK           OD_EPD_RC_OK
#define OD_ERR_ARG      OD_EPD_RC_ARG
#define OD_ERR_MODE     OD_EPD_RC_MODE
#define OD_ERR_SEQ      OD_EPD_RC_SEQ
#define OD_ERR_LUT      OD_EPD_RC_LUT
#define OD_ERR_BUSY     OD_EPD_RC_BUSY
#define OD_ERR_STATE    OD_EPD_RC_STATE
#define OD_ERR_UNSUP    OD_EPD_RC_UNSUP
#define OD_ERR_IO       OD_EPD_RC_IO
#define OD_ERR_STALE    OD_EPD_RC_STALE

/* Streaming chunk for the waveform. 64 B of stack against a 535-byte upload:
 * the alternative is a resident 535-byte buffer, which is 1.7% of this part's
 * RAM held permanently for bytes that are only ever clocked straight out. */
#define LUT_CHUNK 64u

/* ------------------------------------------------------------------ helpers */

bool od_epd_is_busy(od_epd_t *e)
{
    if (!e->desc->busy_usable) {
        return false;
    }
    return e->io->busy_level() != (e->desc->busy_idle_level != 0u);
}

bool od_epd_wait_idle(od_epd_t *e, uint32_t timeout_ms)
{
    /* A panel whose BUSY line lies gets a fixed delay instead of a poll.
     * This is not a workaround bolted on for one panel -- it is a declared
     * per-panel property. The 4.2" GDEM042F52 reports busy immediately after
     * power-up with nothing sent and never releases after a refresh; polling it
     * stalls forever. bb_epaper encoded the same fact as an UNDOCUMENTED local
     * patch (BBEP_SKIP_BUSY_WAIT) to its vendored tree, which is exactly the
     * kind of hidden knowledge this driver exists to make explicit. */
    if (!e->desc->busy_usable) {
        uint32_t d = e->desc->busy_fixed_delay_ms;
        e->io->delay_ms(d ? d : timeout_ms);
        return true;
    }
    uint32_t waited = 0;
    while (od_epd_is_busy(e)) {
        if (waited >= timeout_ms) {
            return false;
        }
        e->io->delay_ms(5);
        waited += 5;
    }
    return true;
}

/* Substitute a byte that the sequence takes from the waveform's analog header.
 * PWRR/PLL/VCOM are properties of the WAVEFORM, not of the init sequence, so a
 * mode that uploads a custom waveform must drive the analog rails that waveform
 * was authored for. Sending a custom waveform with the stock rails plays the
 * right waveform at the wrong voltages -- which does not fail, it renders a
 * plausible-but-wrong image. */
static uint8_t wave_byte(const uint8_t *hdr, bool have_hdr, uint8_t idx)
{
    if (!have_hdr) {
        return 0u;
    }
    if (idx == OD_EPD_WAVE_VCOM) {
        return (uint8_t)(hdr[5] ^ 0x80u);
    }
    return (idx < 7u) ? hdr[idx] : 0u;
}

/* Bytes of escape arguments, -1 for variable (SUBST) or unknown. Shared by the
 * validator and the runtime walk so the two cannot disagree about framing. */
static int esc_arg_bytes(uint8_t esc)
{
    switch (esc) {
        case OD_EPD_SEQ_END:
        case OD_EPD_ESC_BUSY:
        case OD_EPD_ESC_IMAGE:
        case OD_EPD_ESC_LUT:           return 0;
        case OD_EPD_ESC_DELAY:
        case OD_EPD_ESC_SET_PIN:
        case OD_EPD_ESC_IMAGE_SLICE:   return 2;
        case OD_EPD_ESC_CS_SELECT:     return 1;
        case OD_EPD_ESC_READ_SCRATCH:  return 2;
        case OD_EPD_ESC_WRITE_SCRATCH: return 3;
        case OD_EPD_ESC_LUT_SLICE:     return 4;
        case OD_EPD_ESC_FILL:          return 3;
        default:                       return -1;
    }
}

/* Per-sequence state every sequence starts from: an empty scratch and CS 0.
 * CS_SELECT is sticky, so without the reset a pass that ended on cs_pin_2 would
 * route the next pass's first steps to the wrong controller. */
static void seq_start(od_epd_t *e)
{
    memset(e->scratch, 0, sizeof e->scratch);
    if (e->io->cs_select != NULL) {
        (void)e->io->cs_select(0u);
    }
}

/* ------------------------------------------------------------- the reader */

#define SRC_MODE  0u
#define SRC_SLEEP 1u

_Static_assert(OD_EPD_SEQ_WINDOW >= 64u && OD_EPD_SEQ_WINDOW <= 0xFFFFu,
               "the window must hold the largest escape argument run (32 SUBST/WINDOW pairs)");

static void seq_open(od_epd_t *e, uint8_t src, uint8_t mode, uint16_t len)
{
    e->seq_src = src;
    e->seq_mode = mode;
    e->seq_len = len;
    e->seq_pos = 0u;
    e->seq_win_off = 0u;
    e->seq_win_n = 0u;
}

static bool config_moved(const od_epd_t *e)
{
    return e->gen_on && e->io->config_gen() != e->gen;
}

/* Make bytes [at, at+need) of the sequence resident and return them, or NULL with *rc set:
 * OD_ERR_SEQ when the range runs past the sequence (a malformed step), OD_ERR_STALE when the
 * stored config changed since the pass began, OD_ERR_IO when the read fails or is short. The
 * pointer is valid until the next call. need <= OD_EPD_SEQ_WINDOW. */
static const uint8_t *seq_at(od_epd_t *e, uint16_t at, uint16_t need, int *rc)
{
    uint16_t want;
    uint16_t got;

    if ((uint32_t)at + need > e->seq_len) {
        *rc = OD_ERR_SEQ;
        return NULL;
    }
    if (at >= e->seq_win_off && (uint32_t)(at - e->seq_win_off) + need <= e->seq_win_n) {
        return &e->seq_win[at - e->seq_win_off];
    }
    if (e->seq_src == SRC_SLEEP) {
        return &e->desc->sleep_seq[at];      /* held in the descriptor; seq_len <= its size */
    }
    e->seq_win_n = 0u;
    if (config_moved(e)) {
        *rc = OD_ERR_STALE;
        return NULL;
    }
    want = (uint16_t)(e->seq_len - at);
    if (want > OD_EPD_SEQ_WINDOW) {
        want = OD_EPD_SEQ_WINDOW;
    }
    got = e->io->seq_read(e->seq_mode, at, e->seq_win, want);
    if (got != want) {
        *rc = OD_ERR_IO;
        return NULL;
    }
    e->seq_win_off = at;
    e->seq_win_n = want;
    return e->seq_win;
}

/* One decoded step. Plain: n = cmd + data length. Escape: n = 0, esc, size, and `a` points at
 * the resident arguments (fixed args, or the 2*cnt SUBST/WINDOW pair bytes). */
typedef struct {
    uint8_t        n;
    uint8_t        esc;
    uint8_t        cnt;
    uint16_t       size;
    const uint8_t *a;
} step_t;

/* Decode and check the step at `i`. The validator and the executor both walk through this, so
 * they cannot disagree about framing or about which arguments are legal: every walk re-reads the
 * bytes, and the executor indexes arrays with them. Returns OD_OK, or OD_ERR_SEQ (malformed),
 * OD_ERR_UNSUP (unknown escape, or one this io table does not implement), OD_ERR_IO /
 * OD_ERR_STALE (from the reader). */
static int step_decode(od_epd_t *e, uint16_t i, step_t *st)
{
    const uint16_t len = e->seq_len;
    const uint8_t *p;
    const uint8_t *a;
    int rc = OD_OK;
    int args;

    if ((p = seq_at(e, i, 1u, &rc)) == NULL) {
        return rc;
    }
    st->n = p[0];
    if (st->n != OD_EPD_ESC) {
        st->size = (uint16_t)(1u + st->n);
        return (uint32_t)i + st->size > len ? OD_ERR_SEQ : OD_OK;
    }
    if ((p = seq_at(e, i, 2u, &rc)) == NULL) {
        return rc;
    }
    st->esc = p[1];
    st->size = 2u;
    if (st->esc == OD_EPD_SEQ_END) {
        return OD_OK;
    }
#if !OD_EPD_WITH_WINDOW
    if (st->esc == OD_EPD_ESC_WINDOW) {
        return OD_ERR_UNSUP;
    }
#endif
    if (st->esc == OD_EPD_ESC_WAVE || st->esc == OD_EPD_ESC_WINDOW) {
        if ((p = seq_at(e, i, 3u, &rc)) == NULL) {
            return rc;
        }
        st->cnt = p[2];
        st->size = (uint16_t)(3u + (uint16_t)st->cnt * 2u);
        if (st->cnt == 0u || st->cnt > 32u || (uint32_t)i + st->size > len) {
            return OD_ERR_SEQ;
        }
        if ((a = seq_at(e, (uint16_t)(i + 3u), (uint16_t)(st->cnt * 2u), &rc)) == NULL) {
            return rc;
        }
        st->a = a;
#if OD_EPD_WITH_WINDOW
        for (uint8_t k = 0u; st->esc == OD_EPD_ESC_WINDOW && k < st->cnt; k++) {
            const uint8_t v = a[k * 2u + 1u];
            if (a[k * 2u] == OD_EPD_WIN_KIND_GEOM) {
                if ((v & 0xC0u) != 0u ||
                    ((v & OD_EPD_WIN_MIRROR) != 0u && (v & 0x07u) >= OD_EPD_WIN_WIDTH)) {
                    return OD_ERR_SEQ;
                }
            } else if (a[k * 2u] != OD_EPD_WIN_KIND_LITERAL) {
                return OD_ERR_SEQ;
            }
        }
#endif
        return OD_OK;
    }
    args = esc_arg_bytes(st->esc);
    if (args < 0) {
        /* Unknown escape -- including the reserved 0x80+ length-carrying range, which this
         * executor does not implement either. Refusing the WHOLE sequence at validation
         * (nothing has touched the panel yet) is the contract behind
         * OD_ERR_DRIVE_SEQ_UNSUPPORTED. */
        return OD_ERR_UNSUP;
    }
    st->size = (uint16_t)(2u + (uint16_t)args);
    if ((uint32_t)i + st->size > len) {
        return OD_ERR_SEQ;
    }
#if !OD_EPD_WITH_WINDOW
    if (st->esc == OD_EPD_ESC_FILL) {
        return OD_ERR_UNSUP;   /* after the length check, as the validator always ordered it */
    }
#endif
    /* Known but not implemented by THIS io table. */
    if ((st->esc == OD_EPD_ESC_SET_PIN && e->io->set_pin == NULL) ||
        (st->esc == OD_EPD_ESC_CS_SELECT && e->io->cs_select == NULL) ||
        (st->esc == OD_EPD_ESC_READ_SCRATCH && e->io->read_bytes == NULL)) {
        return OD_ERR_UNSUP;
    }
    if ((p = seq_at(e, i, st->size, &rc)) == NULL) {
        return rc;
    }
    a = st->a = p + 2;
    switch (st->esc) {
        case OD_EPD_ESC_CS_SELECT:     return a[0] > 1u ? OD_ERR_SEQ : OD_OK;   /* cs_pin / cs_pin_2 */
        case OD_EPD_ESC_READ_SCRATCH:  return (a[1] == 0u || a[1] > OD_EPD_SCRATCH_LEN)
                                              ? OD_ERR_SEQ : OD_OK;
        case OD_EPD_ESC_WRITE_SCRATCH: return (uint32_t)a[1] + a[2] > OD_EPD_SCRATCH_LEN
                                              ? OD_ERR_SEQ : OD_OK;
        case OD_EPD_ESC_IMAGE_SLICE:   return (a[1] == 0u || a[0] >= a[1]) ? OD_ERR_SEQ : OD_OK;
        case OD_EPD_ESC_SET_PIN:       return a[1] > 2u ? OD_ERR_SEQ : OD_OK;   /* 0, 1, 2 = Hi-Z */
        case OD_EPD_ESC_FILL:          return ((a[2] & 0x03u) > 2u || (a[2] & 0x7Cu) != 0u)
                                              ? OD_ERR_SEQ : OD_OK;
        default:                       return OD_OK;
    }
}

int od_epd_validate(od_epd_t *e)
{
    uint16_t i = 0;
    uint16_t steps = 0;
    step_t st;

    if (e == NULL || e->io == NULL) {
        return OD_ERR_ARG;
    }
    e->seq_has_window = false;
    e->seq_tail = 0u;

    while (i < e->seq_len) {
        if (++steps > OD_EPD_MAX_SEQ_STEPS) {
            return OD_ERR_SEQ;
        }
        int rc = step_decode(e, i, &st);
        if (rc != OD_OK) {
            return rc;
        }
        i = (uint16_t)(i + st.size);
        if (st.n == 0u) {
            if (st.esc == OD_EPD_SEQ_END) {
                return OD_OK;
            }
            if (st.esc == OD_EPD_ESC_IMAGE || st.esc == OD_EPD_ESC_IMAGE_SLICE) {
                e->seq_tail = i;
            }
            e->seq_has_window = e->seq_has_window || st.esc == OD_EPD_ESC_WINDOW;
        }
    }
    /* Running off the end without an END escape is legal -- the runtime walk
     * treats it as end-of-sequence, so the validator must agree with it. */
    return OD_OK;
}

/* Stream the active pass's waveform straight to the panel.
 *
 * vsn1 patching happens here rather than at authoring time because the same
 * waveform slot is shared by more than one pass with DIFFERENT patches: the
 * 16-colour mode's passes 1 and 2 both use the edit waveform but patch byte 3
 * to 0x14 and 0x41 respectively. Storing them pre-patched would cost a second
 * 535-byte copy in the config to hold one differing byte. */
static int stream_lut(od_epd_t *e, uint8_t slot, uint8_t vsn1,
                      uint16_t start, uint16_t len)
{
    uint8_t buf[LUT_CHUNK];
    uint16_t off = start;
    uint16_t end = (uint16_t)(start + len);

    while (off < end) {
        uint16_t want = (uint16_t)((uint16_t)(end - off) < (uint16_t)LUT_CHUNK
                                 ? (uint16_t)(end - off) : (uint16_t)LUT_CHUNK);
        if (config_moved(e)) {
            return OD_ERR_STALE;
        }
        uint16_t got = e->io->lut_read(slot, off, buf, want);
        if (got != want) {
            return OD_ERR_LUT;
        }
        /* The vsn1 patch targets ABSOLUTE slot offset 3 -- also when the slot
         * is streamed in register-sized slices (LUT_SLICE). */
        if (vsn1 != 0u && off <= 3u && (uint16_t)(off + got) > 3u) {
            buf[3u - off] = vsn1;
        }
        e->io->data(buf, (size_t)got);
        off += got;
    }
    return OD_OK;
}

/* Forward-only walk over a length-prefixed sequence.
 *
 * Deliberately NOT a bytecode VM. Sequences arrive in the config, which is
 * parsed pre-auth, so this is untrusted input. There are no jumps, no loops and
 * no addressing: the walk only moves forward, every step is bounded by the
 * sequence length, and the step count is capped. The worst a malformed sequence
 * can do is clock out nonsense and time out -- which the raw-SPI debug command
 * can already do deliberately.
 *
 * Returns OD_OK at end of sequence, 1 when it paused on the image marker, or a
 * negative error. `e->seq_pos` is where to resume.
 */
#if OD_EPD_WITH_WINDOW
static uint16_t win_value(const od_epd_t *e, uint8_t desc)
{
    const uint8_t sel = (uint8_t)(desc & 0x07u);
    uint32_t v;
    uint32_t dim;

    switch (sel) {
        case OD_EPD_WIN_X0:     v = e->win_x; break;
        case OD_EPD_WIN_X1:     v = (uint32_t)e->win_x + e->win_w - 1u; break;
        case OD_EPD_WIN_Y0:     v = e->win_y; break;
        case OD_EPD_WIN_Y1:     v = (uint32_t)e->win_y + e->win_h - 1u; break;
        case OD_EPD_WIN_W_LAST: v = (uint32_t)e->desc->width - 1u; break;
        case OD_EPD_WIN_H_LAST: v = (uint32_t)e->desc->height - 1u; break;
        case OD_EPD_WIN_WIDTH:  v = e->win_w; break;
        default:                v = e->win_h; break;
    }
    if ((desc & OD_EPD_WIN_MIRROR) != 0u) {
        dim = (sel == OD_EPD_WIN_Y0 || sel == OD_EPD_WIN_Y1 || sel == OD_EPD_WIN_H_LAST)
            ? e->desc->height : e->desc->width;
        v = (v < dim) ? dim - 1u - v : 0u;
    }
    if ((desc & OD_EPD_WIN_DIV8) != 0u) {
        v >>= 3;
    }
    return (uint16_t)v;
}

static void run_fill(od_epd_t *e, uint8_t cmd, uint8_t value, uint8_t flags)
{
    static const uint8_t bpp_of[3] = { 1u, 2u, 4u };
    const bool rect = (flags & OD_EPD_FILL_RECT) != 0u;
    const uint32_t w = rect ? e->win_w : e->desc->width;
    const uint32_t h = rect ? e->win_h : e->desc->height;
    uint32_t left = ((w * bpp_of[flags & 0x03u] + 7u) / 8u) * h;
    uint8_t buf[32];

    memset(buf, value, sizeof buf);
    e->io->cmd(cmd);
    while (left > 0u) {
        const uint32_t n = left < sizeof buf ? left : (uint32_t)sizeof buf;
        e->io->data(buf, n);
        left -= n;
    }
}
#endif

/* cmd + data of a plain step [n][cmd][data...] at `i`. The first window's worth is read before
 * the command byte goes out, so a step that fits the window is one cmd() and one data() call; a
 * longer step continues in window-sized data() calls. */
static int run_plain(od_epd_t *e, uint16_t i, uint8_t n)
{
    uint16_t at = (uint16_t)(i + 1u);
    uint16_t left = n;
    bool first = true;
    int rc = OD_OK;

    while (left > 0u) {
        const uint16_t c = left < OD_EPD_SEQ_WINDOW ? left : (uint16_t)OD_EPD_SEQ_WINDOW;
        const uint8_t *p = seq_at(e, at, c, &rc);
        if (p == NULL) {
            return rc;
        }
        if (first) {
            e->io->cmd(p[0]);
            if (c > 1u) {
                e->io->data(&p[1], (size_t)(c - 1u));
            }
            first = false;
        } else {
            e->io->data(p, c);
        }
        at = (uint16_t)(at + c);
        left = (uint16_t)(left - c);
    }
    return OD_OK;
}

static int run_sequence(od_epd_t *e)
{
    const uint16_t len = e->seq_len;
    uint16_t i = e->seq_pos;
    uint16_t steps = 0;
    uint8_t  buf[32];
    step_t   st;
    int rc;

    while (i < len) {
        if (++steps > OD_EPD_MAX_SEQ_STEPS) {
            e->seq_pos = i;
            return OD_ERR_SEQ;
        }
        if ((rc = step_decode(e, i, &st)) != OD_OK) {
            return rc;
        }
        const uint8_t *a = st.a;
        bool ok = true;

        if (st.n != 0u) {
            /* plain step: [len][cmd][data...] */
            if ((rc = run_plain(e, i, st.n)) != OD_OK) {
                return rc;
            }
            i = (uint16_t)(i + st.size);
            continue;
        }
        switch (st.esc) {
            case OD_EPD_SEQ_END:
                e->seq_pos = len;
                return OD_OK;
            case OD_EPD_ESC_IMAGE:
            case OD_EPD_ESC_IMAGE_SLICE:
                e->img_part = st.esc == OD_EPD_ESC_IMAGE_SLICE ? a[0] : 0u;
                e->img_of = st.esc == OD_EPD_ESC_IMAGE_SLICE ? a[1] : 1u;
                e->seq_pos = (uint16_t)(i + st.size);
                return 1;        /* caller streams frame_bytes / img_of bytes, then resumes */
            case OD_EPD_ESC_BUSY:
                if (!od_epd_wait_idle(e, e->desc->busy_timeout_ms)) {
                    return OD_ERR_BUSY;
                }
                break;
            case OD_EPD_ESC_DELAY:
                e->io->delay_ms((uint32_t)a[0] | ((uint32_t)a[1] << 8));
                break;
            /* Validation keeps a NULL hook from ever landing on these three; a false return
             * means the reference is unwired on this board. */
            case OD_EPD_ESC_SET_PIN:
                ok = e->io->set_pin(a[0], a[1]);
                break;
            case OD_EPD_ESC_CS_SELECT:
                ok = e->io->cs_select(a[0]);
                break;
            case OD_EPD_ESC_READ_SCRATCH:
                ok = e->io->read_bytes(a[0], e->scratch, a[1]);
                break;
            case OD_EPD_ESC_WRITE_SCRATCH:
                e->io->cmd(a[0]);
                if (a[2] > 0u) {
                    e->io->data(&e->scratch[a[1]], a[2]);
                }
                break;
            case OD_EPD_ESC_LUT:
            case OD_EPD_ESC_LUT_SLICE: {
                /* Loud, not silent: a mode whose sequence uploads a waveform but whose pass
                 * resolved no slot would otherwise refresh with whatever the panel had in its
                 * waveform register. */
                uint16_t s_off = 0u;
                uint16_t s_len = e->lut_len;
                if (st.esc == OD_EPD_ESC_LUT_SLICE) {
                    s_off = (uint16_t)(a[0] | ((uint16_t)a[1] << 8));
                    s_len = (uint16_t)(a[2] | ((uint16_t)a[3] << 8));
                }
                if (!e->lut_have) {
                    return OD_ERR_LUT;
                }
                if ((uint32_t)s_off + s_len > e->lut_len) {
                    return OD_ERR_SEQ;   /* slice runs past the stored slot */
                }
                if ((rc = stream_lut(e, e->lut_slot, e->lut_vsn1, s_off, s_len)) != OD_OK) {
                    return rc;
                }
                break;
            }
#if OD_EPD_WITH_WINDOW
            case OD_EPD_ESC_FILL:
                run_fill(e, a[0], a[1], a[2]);
                break;
#endif
            default:   /* SUBST, WINDOW: one command built from (kind, value) pairs */
                for (uint8_t k = 0; k < st.cnt; k++) {
                    const uint8_t kind = a[k * 2u];
                    const uint8_t v = a[k * 2u + 1u];
#if OD_EPD_WITH_WINDOW
                    if (st.esc == OD_EPD_ESC_WINDOW) {
                        const uint16_t w = kind == OD_EPD_WIN_KIND_GEOM ? win_value(e, v) : v;
                        buf[k] = (uint8_t)((kind == OD_EPD_WIN_KIND_GEOM &&
                                            (v & OD_EPD_WIN_HIGH) != 0u) ? (w >> 8) : w);
                        continue;
                    }
#endif
                    buf[k] = (kind == 0xFFu) ? wave_byte(e->lut_hdr, e->lut_have, v) : v;
                }
                e->io->cmd(buf[0]);
                if (st.cnt > 1u) {
                    e->io->data(&buf[1], (size_t)(st.cnt - 1u));
                }
                break;
        }
        if (!ok) {
            return OD_ERR_UNSUP;
        }
        i = (uint16_t)(i + st.size);
    }
    e->seq_pos = len;
    return OD_OK;
}

/* -------------------------------------------------------------------- API */

int od_epd_init(od_epd_t *e, const od_panel_desc_t *d, const od_epd_io_t *io)
{
    if (!e || !d || !io || !io->cmd || !io->data || !io->reset || !io->delay_ms ||
        !io->busy_level || !io->seq_read || !io->mode_read) {
        return OD_ERR_ARG;
    }
    memset(e, 0, sizeof(*e));
    e->desc = d;
    e->io = io;
    return OD_OK;
}

int od_epd_select_mode(od_epd_t *e, uint8_t mode)
{
    if (!e || mode >= e->desc->mode_count || !e->io->mode_read) {
        return OD_ERR_MODE;
    }
    if (!e->io->mode_read(mode, &e->active)) {
        return OD_ERR_MODE;
    }
    e->mode = mode;
    e->pass = 0;
    e->paused = false;
    od_epd_set_window(e, 0u, 0u, e->desc->width, e->desc->height);
    return OD_OK;
}

/* Resolve a pass's waveform. Only the 7-byte analog header is read into RAM -- the body is
 * streamed later, at the marker. An absent slot is not an error here; a LUT step that needs
 * one is (run_sequence). */
static int resolve_lut(od_epd_t *e, uint8_t slot, uint8_t vsn1)
{
    uint16_t lut_len = 0u;

    e->lut_have = false;
    e->lut_slot = slot;
    e->lut_vsn1 = vsn1;
    e->lut_len = 0u;
    if (slot != 0xFFu && e->io->lut_info && e->io->lut_read &&
        e->io->lut_info(slot, &lut_len)) {
        if (lut_len < 7u) {
            return OD_ERR_LUT;   /* too short to carry an analog header */
        }
        if (e->io->lut_read(slot, 0u, e->lut_hdr, 7u) != 7u) {
            return OD_ERR_LUT;
        }
        if (vsn1 != 0u) {
            e->lut_hdr[3] = vsn1;
        }
        e->lut_len = lut_len;
        e->lut_have = true;
    }
    return OD_OK;
}

void od_epd_set_window(od_epd_t *e, uint16_t x, uint16_t y, uint16_t w, uint16_t h)
{
    if (e == NULL) {
        return;
    }
    e->win_x = x;
    e->win_y = y;
    e->win_w = w;
    e->win_h = h;
}

#if OD_EPD_WITH_WINDOW
static bool window_is_panel(const od_epd_t *e)
{
    return e->win_x == 0u && e->win_y == 0u &&
           e->win_w == e->desc->width && e->win_h == e->desc->height;
}
#endif

/* A storage failure once the panel has seen I/O: put it to sleep from the descriptor's copy of
 * the sleep sequence (RAM, so it cannot fail the same way), then report the failure. The
 * caller's own od_epd_sleep() that normally follows a failed pass is absorbed, so the panel
 * sees the sleep sequence once. */
static int pass_failed(od_epd_t *e, int rc)
{
    e->paused = false;
    if ((rc == OD_ERR_IO || rc == OD_ERR_STALE) && e->io_started) {
        (void)od_epd_sleep(e);
        e->slept_on_fail = true;
    }
    return rc;
}

int od_epd_begin_pass(od_epd_t *e, uint8_t pass)
{
    const od_epd_mode_t *m = &e->active;

    if (pass >= m->passes) {
        return OD_ERR_MODE;
    }
    if (m->seq_len == 0u) {
        return OD_ERR_SEQ;
    }
    e->pass = pass;
    e->paused = false;
    e->io_started = false;
    e->slept_on_fail = false;
    e->gen_on = e->io->config_gen != NULL;
    e->gen = e->gen_on ? e->io->config_gen() : 0u;
    seq_open(e, SRC_MODE, e->mode, m->seq_len);

    /* Capability + structure pre-scan BEFORE any panel I/O, over the same reader the walk
     * uses. A sequence using an escape this target does not implement is refused wholesale
     * here -- no reset, no power, nothing half-executed (wire: SEQ_UNSUPPORTED). */
    {
        int vrc = od_epd_validate(e);
        if (vrc != OD_OK) {
            return vrc;
        }
    }
#if OD_EPD_WITH_WINDOW
    if (!window_is_panel(e) && !e->seq_has_window) {
        return OD_ERR_UNSUP;
    }
#endif
    seq_start(e);
    {
        int lrc = resolve_lut(e, m->lut_slot[pass], m->vsn1[pass]);
        if (lrc != OD_OK) {
            return lrc;
        }
    }

    e->io_started = true;
    e->io->reset(10);
    if (!od_epd_wait_idle(e, e->desc->busy_timeout_ms)) {
        return OD_ERR_BUSY;
    }

    int rc = run_sequence(e);
    if (rc < 0) {
        return pass_failed(e, rc);
    }
    if (rc == 1) {
        e->paused = true;        /* stopped on the image marker, as expected */
        return OD_OK;
    }
    /* A sequence with no image marker is a programming error in the config,
     * not something to paper over: the frame would have nowhere to go. */
    return OD_ERR_SEQ;
}

int od_epd_write_image_chunk(od_epd_t *e, const uint8_t *buf, size_t n)
{
    if (!e || (!buf && n)) {
        return OD_ERR_ARG;
    }
    if (!e->paused) {
        return OD_ERR_STATE;
    }
    if (n) {
        e->io->data(buf, n);   /* streamed; never buffered */
    }
    return OD_OK;
}

/* Resume a paused walk. The bytes ahead are read from storage again, so the config must still be
 * the one the pass began on. */
static int resume(od_epd_t *e)
{
    int rc;

    e->paused = false;
    if (config_moved(e)) {
        return pass_failed(e, OD_ERR_STALE);
    }
    rc = run_sequence(e);
    return rc < 0 ? pass_failed(e, rc) : rc;
}

int od_epd_next_plane(od_epd_t *e)
{
    /* Panels that take two 1bpp planes (3-colour black/white/red) have a second
     * image command between them -- bb_epaper spelled this startWrite(PLANE_1).
     * Here it is a second image marker in the same sequence, so the register
     * that opens plane 1 is config data like every other byte. */
    if (!e || !e->paused) {
        return OD_ERR_STATE;
    }
    int rc = resume(e);
    if (rc < 0) {
        return rc;
    }
    if (rc != 1) {
        return OD_ERR_SEQ;      /* caller wanted another plane; sequence has none */
    }
    e->paused = true;
    return OD_OK;
}

int od_epd_finish_pass(od_epd_t *e)
{
    if (!e || !e->paused) {
        return OD_ERR_STATE;
    }
    /* The tail -- power-on, refresh opcode, BUSY wait -- is the remainder of
     * the same sequence. A panel needing a different refresh command or an
     * extra register poke after the frame needs no code change here. */
    int rc = resume(e);
    return (rc < 0) ? rc : OD_OK;
}

int od_epd_finish_with_tail(od_epd_t *e, uint8_t mode)
{
    od_epd_mode_t m;
    int rc;

    if (!e || !e->paused) {
        return OD_ERR_STATE;
    }
    if (mode >= e->desc->mode_count || !e->io->mode_read(mode, &m) || m.seq_len == 0u) {
        return OD_ERR_MODE;
    }
    e->paused = false;
    if (config_moved(e)) {
        return pass_failed(e, OD_ERR_STALE);
    }
    seq_open(e, SRC_MODE, mode, m.seq_len);
    rc = od_epd_validate(e);
    if (rc != OD_OK) {
        return pass_failed(e, rc);
    }
    if (e->seq_tail == 0u) {
        return OD_ERR_SEQ;      /* a tail is defined by the image marker it follows */
    }
    rc = resolve_lut(e, m.lut_slot[0], m.vsn1[0]);
    if (rc != OD_OK) {
        return rc;
    }
    e->seq_pos = e->seq_tail;
    rc = run_sequence(e);
    if (rc == 1) {
        return OD_ERR_SEQ;      /* only the last marker's tail may run here */
    }
    return (rc < 0) ? pass_failed(e, rc) : OD_OK;
}

int od_epd_sleep(od_epd_t *e)
{
    if (e != NULL && e->slept_on_fail) {
        e->slept_on_fail = false;
        return OD_OK;            /* the failed pass already ran it */
    }
    if (!e || e->desc->sleep_seq_len == 0u) {
        return OD_OK;            /* panel declares no sleep sequence */
    }
    if (e->desc->sleep_seq_len > OD_EPD_SLEEP_SEQ_MAX) {
        return OD_ERR_SEQ;
    }
    seq_open(e, SRC_SLEEP, 0u, e->desc->sleep_seq_len);
    e->paused = false;
    e->lut_have = false;
    /* The sleep sequence is config data like any mode sequence: same validator, before any
     * panel I/O. run_sequence() relies on it (FILL's bpp code, CS_SELECT's range). It is held
     * in the descriptor, so it does not depend on the stored config staying put. */
    int rc = od_epd_validate(e);
    if (rc != OD_OK) {
        return rc;
    }
    seq_start(e);
    rc = run_sequence(e);
    if (rc == 1) {
        return OD_ERR_SEQ;      /* an image marker has no frame to take here */
    }
    return (rc < 0) ? rc : OD_OK;
}
