/* od_epd -- config-driven e-paper driver. ZERO panel constants compiled in.
 *
 * WHY THIS REPLACES bb_epaper
 * ---------------------------
 * Panel behaviour used to be a property of a vendored C library version: init
 * byte arrays, LUTs, BUSY quirks and colour order all lived in bb_epaper, were
 * mirrored by hand into py-opendisplay's display_palettes.py, and were selected
 * through a per-target switch. Nothing forced those three to agree, and a
 * library bump silently changed init traffic on four shipped panels
 * (Firmware_Unified targets/nordic-zephyr/PANEL_DIVERGENCE.md) while compiling
 * cleanly and passing every gate.
 *
 * Here, EVERYTHING the driver needs arrives in the device config. There is no
 * panel table, no panel enum, and no per-target mapping switch. A new panel is
 * a config change, not a firmware release.
 *
 * WHAT THE DRIVER KNOWS vs WHAT CONFIG TELLS IT
 *   knows:   how to clock bytes out of SPI, toggle D/C, RST and CS, read BUSY
 *   told:    every command byte, every data byte, which register accepts the
 *            waveform, where the waveform upload sits relative to power-on,
 *            where the image goes, how many passes, the colour code map,
 *            whether BUSY is trustworthy and which level means idle
 *
 * NO FRAMEBUFFER. Image data streams row-by-row from the transport straight to
 * the panel, as bb_epaper did. A 800x480 2bpp frame is 96000 bytes; this target
 * has 32 KB of RAM.
 *
 * NO RESIDENT CONFIG. The stored config lives in NVM3 and nowhere else (see
 * od_cfg_index.h). Sequences and waveforms are therefore fetched through
 * callbacks, not pointed at: a 535-byte waveform is streamed to the panel in
 * chunks rather than copied into RAM first.
 *
 * SEQUENCES ARE STREAMED TOO. The interpreter holds a reference to the
 * active sequence (its source and length) and a position, and pulls bytes
 * through io->seq_read into a fixed window as it walks. Its length is bounded
 * by the packet that carries it, i.e. by the config size, not by RAM.
 *
 * SAFETY. Sequences are now UNTRUSTED INPUT on the pre-auth config path. The
 * interpreter is deliberately not a VM: it is a forward-only walk over
 * length-prefixed steps with a hard cap on step count, no jumps, no loops, no
 * addressing. The worst a malformed sequence can do is clock out garbage and
 * time out -- which raw SPI can already do. Every walk re-reads, so the
 * executor re-checks every argument it indexes with rather than trusting the
 * validator's earlier read.
 */
#ifndef OD_EPD_H
#define OD_EPD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Sequence window: the bytes of the active sequence resident at once. A step is [n][cmd][data]
 * with n up to 255; one whose cmd + data fits here goes to the bus as one cmd() and one data()
 * call, a longer one continues in window-sized data() calls, the way a waveform slot and the
 * frame already reach the bus. 128 holds every escape whole (the largest, SUBST/WINDOW with 32
 * pairs, is 67 B) and every step of 70 of the 77 database panels; the other seven have one 0x32
 * waveform-register step of 154 or 229 B (cmd + data), which goes out in two data() calls. Same
 * value on every target. */
#ifndef OD_EPD_SEQ_WINDOW
#define OD_EPD_SEQ_WINDOW     128u
#endif
/* Runaway bound, not a RAM cap: a walk is forward-only over a bounded packet, so this limits
 * how long a malformed sequence can keep the panel (each step may be a 65 s DELAY or a BUSY wait).
 * The largest real sequence has 79 steps (panels/generated, 0x0042 dual-controller Spectra 6). */
#define OD_EPD_MAX_SEQ_STEPS  128u
#define OD_EPD_LUT_BYTES      535u   /* 7-byte analog header + 528-byte body */
/* 20: the longest sleep sequence is the 4.2in SSD16xx's discharge plus its 200 ms bleed DELAY
 * (19 B; panels/tools/pdlib.py POST_SLEEP_BLEED). */
#define OD_EPD_SLEEP_SEQ_MAX   20u
#define OD_EPD_SCRATCH_LEN     16u   /* READ_SCRATCH/WRITE_SCRATCH buffer, zeroed per sequence */

/* Sequence step encoding, produced by the host from panels.yaml.
 *
 *   [len][cmd][data...]        len counts cmd+data, len >= 1
 *   0x00 0x01                  wait for BUSY to clear
 *   0x00 0x02 [n] [pairs...]   step with wave-header substitutions; n pairs of
 *                              (is_wave, value): is_wave=0xFF -> value is an
 *                              index into the waveform's 7-byte analog header,
 *                              0xFF index means VCOM = header[5] ^ 0x80
 *   0x00 0x03                  STREAM THE IMAGE HERE (walk pauses)
 *   0x00 0x04                  STREAM THE WAVEFORM HERE
 *   0x00 0x05 [lo] [hi]        wait N ms (little-endian)
 *   0x00 0x00                  end of sequence
 *
 * The explicit delay exists because a BUSY wait is not a substitute for it.
 * The 4.2" GDEM042F52's BUSY line is unusable, so its sequence needs a SHORT
 * settle after power-on (2 s) and a LONG wait after refresh (35 s); a single
 * per-panel fixed delay cannot be both. Without this step the only way to
 * express the short one would be to hard-code it in the driver.
 *
 * A zero length is otherwise impossible (a step always has a command byte), so
 * it is free as an escape marker.
 *
 * ONE SEQUENCE IS THE WHOLE RECIPE FOR A PASS: registers, waveform upload,
 * image, power-on, refresh. That is deliberate, and it is what let an entire
 * `lut_placement` enum be deleted.
 *
 * The 7.5" GDEM075F52 discards a waveform uploaded before power-on SILENTLY --
 * two different waveforms then render identically to within 0.2/255, which
 * looks like conclusive proof the panel ignores custom waveforms and is not.
 * It must be uploaded after the entire init, booster tail included. The 2.9"
 * and 4.2" need it before power-on. Encoding that as a driver-side enum meant
 * the driver had to know which panel it was talking to; encoding it as the
 * POSITION OF 0x00 0x04 IN THE SEQUENCE means the fact is written down exactly
 * where it takes effect, and the driver needs no opinion at all.
 *
 * The register that accepts the waveform is likewise not a field: the sequence
 * contains a plain `[1][0x20]` step immediately before the marker.
 */
/* Local executor names (OD_EPD_*): the wire values are canonical in
 * opendisplay_structs.h's DriveSeqEscape enum; this header stays standalone
 * (no includes), so it carries its own macros with the same values. The
 * seq_conformance suite asserts the two sets agree. */
#define OD_EPD_ESC                 0x00u
#define OD_EPD_ESC_BUSY            0x01u
#define OD_EPD_ESC_WAVE            0x02u   /* substitutions (canonical: SUBST) */
#define OD_EPD_ESC_IMAGE           0x03u
#define OD_EPD_ESC_LUT             0x04u
#define OD_EPD_ESC_DELAY           0x05u
#define OD_EPD_ESC_SET_PIN         0x06u   /* [pin_ref][level 0/1/2=Hi-Z] */
#define OD_EPD_ESC_IMAGE_SLICE     0x07u   /* [part][of] of the frame */
#define OD_EPD_ESC_CS_SELECT       0x08u   /* [0=cs, 1=cs_2]; sticky, a sequence starts at 0 */
#define OD_EPD_ESC_READ_SCRATCH    0x09u   /* [pin_ref][len<=16] clock bytes into scratch */
#define OD_EPD_ESC_WRITE_SCRATCH   0x0Au   /* [cmd][off][len] cmd + scratch[off..off+len) */
#define OD_EPD_ESC_LUT_SLICE       0x0Bu   /* [off:2 LE][len:2 LE] of the slot */
/* OD_SEQ_ESC_WINDOW / OD_SEQ_ESC_FILL in opendisplay_structs.h (3.0).
 *
 * WINDOW: [n][(kind,val) * n] -- one step whose n bytes (cmd first, n = 1..32) are each a
 *   literal (kind 0x00, val = the byte) or a GEOMETRY byte (kind 0x01, val = descriptor):
 *     bits 2..0  value: 0 x0, 1 x1, 2 y0, 3 y1 (window, inclusive), 4 W-1, 5 H-1 (panel),
 *                6 window width, 7 window height
 *     bit 3      divide by 8 (byte-addressed RAM X)
 *     bit 4      mirror: dim-1-v, applied BEFORE the divide (x values against W, y against H;
 *                refused on 6/7)
 *     bit 5      take the high byte (else the low byte)
 *   The window is the partial rectangle on a partial update and the whole panel otherwise, so
 *   one sequence serves both. SSD16xx 0x44/0x45/0x4E/0x4F, mirrored-RAM variants and UC81xx
 *   0x90 are all expressible.
 * FILL: [cmd][value][flags] -- cmd, then a whole plane of `value`: ceil(w*bpp/8)*h bytes, with
 *   bpp from flags bits 1..0 (0=1, 1=2, 2=4) and w,h the PANEL, or the window when flags bit 7
 *   is set. What bb_epaper's bbepFill() did before a partial update (old == new outside the
 *   window, so a differential waveform leaves it alone). */
#define OD_EPD_ESC_WINDOW          0x0Cu
#define OD_EPD_ESC_FILL            0x0Du
#define OD_EPD_SEQ_END             0x00u
#define OD_EPD_WAVE_VCOM           0xFFu

#define OD_EPD_MAX_PASSES          8u

/* WINDOW/FILL cost code a target may not have room for (BG22). 0 makes the validator refuse
 * them as OD_EPD_RC_UNSUP, which is the honest wire answer for a target without them. */
#ifndef OD_EPD_WITH_WINDOW
#define OD_EPD_WITH_WINDOW 1
#endif

#define OD_EPD_WIN_KIND_LITERAL    0x00u
#define OD_EPD_WIN_KIND_GEOM       0x01u
#define OD_EPD_WIN_X0              0u
#define OD_EPD_WIN_X1              1u
#define OD_EPD_WIN_Y0              2u
#define OD_EPD_WIN_Y1              3u
#define OD_EPD_WIN_W_LAST          4u
#define OD_EPD_WIN_H_LAST          5u
#define OD_EPD_WIN_WIDTH           6u
#define OD_EPD_WIN_HEIGHT          7u
#define OD_EPD_WIN_DIV8            0x08u
#define OD_EPD_WIN_MIRROR          0x10u
#define OD_EPD_WIN_HIGH            0x20u
#define OD_EPD_FILL_RECT           0x80u

/* Public return codes (negative), so callers can tell "this target does not
 * implement an escape the sequence uses" (NACK SEQ_UNSUPPORTED on the wire)
 * from a malformed sequence or a hardware failure. */
#define OD_EPD_RC_OK          0
#define OD_EPD_RC_ARG        -1
#define OD_EPD_RC_MODE       -2
#define OD_EPD_RC_SEQ        -3
#define OD_EPD_RC_LUT        -4
#define OD_EPD_RC_BUSY       -5
#define OD_EPD_RC_STATE      -6
#define OD_EPD_RC_UNSUP      -7   /* sequence refused at validation: unknown or
                                   * unimplemented escape. NOTHING was sent to
                                   * the panel. */
#define OD_EPD_RC_IO         -8   /* a sequence read failed or came back short */
#define OD_EPD_RC_STALE      -9   /* the stored config changed under the pass
                                   * (io->config_gen moved since it began) */

/* One drive mode. */
typedef struct {
    char     name[12];
    uint8_t  passes;             /* 1 for normal refresh, 3 for 16-colour */
    uint8_t  color_scheme;       /* what the mode renders; 0xFF = panel's own */
    uint8_t  lut_slot[OD_EPD_MAX_PASSES]; /* per-pass waveform slot, 0xFF = none */
    uint8_t  vsn1[OD_EPD_MAX_PASSES];     /* per-pass waveform byte 3 patch, 0 = none */
    uint16_t seq_len;
    int8_t   temp_min_c;         /* window enforced by the DEVICE per temp_policy */
    int8_t   temp_max_c;
    uint8_t  temp_policy;        /* 0 advisory, 1 substitute, 2 reject */
} od_epd_mode_t;

/* Everything the driver needs about a panel. Populated from config ONLY. */
typedef struct {
    uint16_t width, height;
    uint8_t  colour_scheme;
    uint8_t  code_map[4];        /* logical colour -> panel 2-bit code */
    bool     busy_usable;        /* false: this panel's BUSY line lies */
    uint8_t  busy_idle_level;    /* pin level that means "not busy" */
    uint32_t busy_timeout_ms;
    uint32_t busy_fixed_delay_ms;
    uint8_t  sleep_seq[OD_EPD_SLEEP_SEQ_MAX];
    uint8_t  sleep_seq_len;
    /* How many modes the config declares. NOT an array bound: modes are read
     * one at a time through io->mode_read, so the count is limited only by how
     * many 0x2E packets fit in the config. An earlier revision held
     * modes[OD_EPD_MAX_MODES] resident, which capped a device at four update
     * modes for no reason other than a fixed array -- and spent RAM on three
     * modes that were not being driven. */
    uint8_t  mode_count;
} od_panel_desc_t;

/* Target-provided hardware access plus config-backed reads.
 *
 * The reads are callbacks rather than pointers because there is no resident
 * copy of the config to point at -- NVM3 is the only source of truth. A
 * waveform is 535 bytes; on a 32 KB part it is streamed, never buffered. */
typedef struct {
    void (*cmd)(uint8_t c);
    void (*data)(const uint8_t *d, size_t n);
    void (*reset)(uint32_t hold_ms);
    bool (*busy_level)(void);           /* RAW pin level; idle sense is config */
    void (*delay_ms)(uint32_t ms);
    uint16_t (*seq_read)(uint8_t mode, uint16_t off, uint8_t *dst, uint16_t len);
    /* Load one mode's header. Called when a mode is selected, not at init, so
     * only the ACTIVE mode is ever resident. */
    bool     (*mode_read)(uint8_t index, od_epd_mode_t *out);
    bool     (*lut_info)(uint8_t slot, uint16_t *len_out);
    uint16_t (*lut_read)(uint8_t slot, uint16_t off, uint8_t *dst, uint16_t len);
    /* OPTIONAL capabilities. NULL means "this target does not implement the
     * matching escape" -- a sequence using it is then refused at validation
     * (OD_EPD_RC_UNSUP), BEFORE any panel I/O. This is how one executor serves
     * targets with different hardware honestly: capability is declared by the
     * io table, not guessed at runtime.
     *
     * set_pin: drive a CONFIG-REFERENCED pin (DriveSeqPinRef, never a GPIO
     * number) to 0/1, or 2 = release to input/Hi-Z. Returns false if the
     * reference is unwired on this board. */
    bool     (*set_pin)(uint8_t pin_ref, uint8_t level);
    /* cs_select: route subsequent command/data bytes to CS n (0 = cs_pin,
     * 1 = cs_pin_2). Sticky until changed; a pass starts at 0. */
    bool     (*cs_select)(uint8_t cs);
    /* read_bytes: clock n bytes in on the panel SCK, sampling the CONFIG-
     * REFERENCED pin_ref as the data-in line (dc_pin doubles as MISO on some
     * boards; a waveform EEPROM has its own MISO on an aux pin). Returns false
     * if the reference is unwired. Backs READ_SCRATCH; WRITE_SCRATCH needs no
     * hook beyond cmd/data. */
    bool     (*read_bytes)(uint8_t pin_ref, uint8_t *dst, uint8_t n);
    /* config_gen: OPTIONAL. A value that changes whenever the stored bytes behind seq_read /
     * lut_read may have changed. Sampled when a pass begins and compared before every storage
     * read and on every resume after the image marker; a difference fails the pass with
     * OD_EPD_RC_STALE instead of walking on into another config's bytes. */
    uint32_t (*config_gen)(void);
} od_epd_io_t;

typedef struct {
    const od_panel_desc_t *desc;
    const od_epd_io_t     *io;
    uint8_t                mode;
    uint8_t                pass;
    od_epd_mode_t          active;   /* the selected mode, read from config */
    /* The sequence being walked: a reference into storage (mode `seq_mode` through
     * io->seq_read, or the descriptor's sleep_seq), its length and the resume position. The
     * walk PAUSES at the image marker and resumes after the frame has been streamed; only the
     * reference and position need to outlive that gap, not the bytes. */
    uint8_t                seq_src;
    uint8_t                seq_mode;
    uint16_t               seq_len;
    uint16_t               seq_pos;
    /* Window over the sequence: seq_win[0..seq_win_n) holds bytes [seq_win_off, +n). */
    uint8_t                seq_win[OD_EPD_SEQ_WINDOW];
    uint16_t               seq_win_off;
    uint16_t               seq_win_n;
    /* Filled by od_epd_validate(): whether the sequence has a WINDOW step, and the offset just
     * past its last image marker (0 = none). */
    bool                   seq_has_window;
    uint16_t               seq_tail;
    /* io->config_gen at pass start (gen_on: the hook exists and a pass sampled it). */
    uint32_t               gen;
    bool                   gen_on;
    /* The panel has seen I/O in this pass (reset onward); a failed read after that point runs
     * the sleep sequence, and the caller's next od_epd_sleep() is then absorbed. */
    bool                   io_started;
    bool                   slept_on_fail;
    bool                   paused;
    /* Which image stream the walk is paused on: IMAGE pauses as part 0 of 1;
     * IMAGE_SLICE pauses with its [part][of] args. The caller sizes the bytes
     * it streams before resuming as frame_bytes * 1/img_of. */
    uint8_t                img_part;
    uint8_t                img_of;
    /* READ_SCRATCH lands here and WRITE_SCRATCH sends from here. Zeroed when a
     * sequence starts (each pass, and the sleep sequence), kept across the
     * image pause within one pass. */
    uint8_t                scratch[OD_EPD_SCRATCH_LEN];
    /* The active pass's waveform, resolved at begin and KEPT across the image pause, so a
     * LUT/LUT_SLICE/SUBST step after the image marker (bb_epaper sends several panels' fast
     * waveform as part of the refresh) has the same slot as one before it. */
    uint8_t                lut_hdr[7];
    bool                   lut_have;
    uint8_t                lut_slot;
    uint8_t                lut_vsn1;
    uint16_t               lut_len;
    /* WINDOW/FILL geometry: the whole panel unless od_epd_set_window() narrowed it. Reset by
     * od_epd_select_mode(). */
    uint16_t               win_x, win_y, win_w, win_h;
} od_epd_t;

int  od_epd_init(od_epd_t *e, const od_panel_desc_t *d, const od_epd_io_t *io);
int  od_epd_select_mode(od_epd_t *e, uint8_t mode);

/* Static pre-scan of the referenced sequence, read through the same window as
 * execution: structure (step bounds, arg counts) plus CAPABILITY (every escape
 * known AND implemented by this io table). Returns OD_EPD_RC_OK,
 * OD_EPD_RC_SEQ (malformed), OD_EPD_RC_UNSUP, or OD_EPD_RC_IO / _STALE when
 * the bytes cannot be read. Runs inside od_epd_begin_pass before any panel
 * I/O, so a refused sequence executes NOTHING -- the wire contract behind
 * OD_ERR_DRIVE_SEQ_UNSUPPORTED. Public so the conformance suite can exercise
 * it directly. */
int  od_epd_validate(od_epd_t *e);

/* Run a pass up to the image marker: reset, registers, waveform upload. The
 * caller then streams the frame with od_epd_write_image_chunk and calls
 * od_epd_finish_pass to run the tail (power-on, refresh, BUSY wait). */
int  od_epd_begin_pass(od_epd_t *e, uint8_t pass);
/* A storage read that fails (IO) or finds the config changed (STALE) after the panel has seen
 * I/O ends the pass: the sleep sequence (held in the descriptor, not in storage) runs at once,
 * the next od_epd_sleep() is absorbed, and every resume returns OD_EPD_RC_STATE. */
int  od_epd_write_image_chunk(od_epd_t *e, const uint8_t *buf, size_t n);
/* Advance to the next image marker, for panels that take two 1bpp planes. */
int  od_epd_next_plane(od_epd_t *e);
int  od_epd_finish_pass(od_epd_t *e);
/* Like od_epd_finish_pass, but runs ANOTHER mode's tail: the steps after the last image marker
 * of `mode`'s sequence, with that mode's pass-0 waveform. The frame already in controller RAM is
 * refreshed the way `mode` refreshes. This is how a 0x0072 refresh byte asking for FAST selects a
 * config-declared fast mode after the frame went in under mode 0 -- the same split bb_epaper had
 * (init at START, refresh-mode-specific init at END). */
int  od_epd_finish_with_tail(od_epd_t *e, uint8_t mode);
/* Narrow WINDOW/FILL to a rectangle for the next pass (partial update). */
void od_epd_set_window(od_epd_t *e, uint16_t x, uint16_t y, uint16_t w, uint16_t h);
int  od_epd_sleep(od_epd_t *e);
bool od_epd_wait_idle(od_epd_t *e, uint32_t timeout_ms);
bool od_epd_is_busy(od_epd_t *e);

/* Decode a panel descriptor out of the stored config. Returns 0 on success,
 * negative when the config carries no drive data for this display -- there is
 * no built-in table to fall back to, and saying so is the honest answer. */
int  od_epd_desc_from_config(od_panel_desc_t *out, uint8_t display_instance);

/* Why the last od_epd_desc_from_config() call failed, packed for a one-byte
 * debug channel: (-rc) in bits 7..5, indexed packet count in bits 4..0.
 *
 * This exists because all four failure branches are invisible from the host:
 * CMD_SPI_RAW and CMD_DIRECT_WRITE_START both collapse them into one NACK, and
 * the only other diagnostic is printf over RTT -- which needs a wired
 * programmer. On a BLE-only device that made "the panel does not come up"
 * unbisectable. */
uint8_t od_epd_desc_diag(void);

#ifdef __cplusplus
}
#endif
#endif /* OD_EPD_H */
