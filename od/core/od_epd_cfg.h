/* od_epd_cfg -- the config-driven panel driver bound to the stored config.
 *
 * od_epd holds the panel state machine and reads everything through an od_epd_io_t. This module
 * supplies the config half of that io (mode heads, sequences, waveforms, all read on demand
 * through od_cfg_index) and leaves the wire half -- D/C, CS, RST, BUSY and the SPI bytes -- to
 * the target through od_epd_cfg_bus_t. One session at a time; it is module state because od_epd's
 * io callbacks carry no context pointer.
 *
 * Used by every config-driven display path: ordinary uploads, partial updates, the boot screen
 * and the image store (od_display.c), plus CMD_DRIVE_WRITE_START (0x0085) and CMD_SPI_RAW
 * (0x0084). A device whose config carries no drive packets loads nothing and drives nothing.
 */
#ifndef OD_EPD_CFG_H
#define OD_EPD_CFG_H

#include "od_color.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct DisplayConfig;

/* "No temperature reading": skips temp_policy. Same value as OD_DRIVE_TEMP_UNKNOWN. */
#define OD_EPD_CFG_TEMP_UNKNOWN ((int8_t)0x7F)

typedef struct {
    /* One command byte: D/C low, CS framed around it. */
    void (*cmd)(uint8_t c);
    /* Data bytes: D/C high, CS framed around them. */
    void (*data)(const uint8_t *d, size_t n);
    /* High, low for hold_ms, high, then hold_ms settle. No-op without a reset pin. */
    void (*reset)(uint32_t hold_ms);
    /* BUSY pin level, or -1 when the display has no BUSY pin. */
    int  (*busy_read)(void);
    void (*delay_ms)(uint32_t ms);
    /* Monotonic milliseconds, for the raw BUSY wait's elapsed time. */
    uint32_t (*now_ms)(void);
    /* Optional: true once the bus has failed a transfer. NULL means it never does. */
    bool (*faulted)(void);
    /* --- optional escapes. NULL refuses the escape at validation (SEQ_UNSUPPORTED). ------
     * Pins arrive RESOLVED: od_epd_cfg maps the sequence's DriveSeqPinRef onto the DisplayConfig
     * pin byte, so these see the same pin encoding as every other GPIO call on the target. */
    /* SET_PIN: drive `pin` low (0) / high (1), or release it to input (2). */
    bool (*pin_write)(uint8_t pin, uint8_t level);
    /* CS_SELECT: route the following cmd/data to cs_pin (0) or cs_pin_2 (1). Only offered to
     * od_epd when the display has a distinct cs_pin_2. */
    bool (*cs_select)(uint8_t which);
    /* READ_SCRATCH: clock n bytes in on the panel SCK, sampling `pin` as data-in. */
    bool (*read_bytes)(uint8_t pin, uint8_t *dst, uint8_t n);
} od_epd_cfg_bus_t;

typedef struct {
    uint8_t passes;
    uint8_t color_scheme;   /* 0xFF = the panel's own */
    int8_t  temp_min_c;
    int8_t  temp_max_c;
    uint8_t temp_policy;
} od_epd_cfg_mode_t;

/* Indexes the stored config and loads the panel descriptor for display `d`. Call once per
 * session: index entries are offsets and a config write invalidates them. False when the config
 * carries no drive packets for this display. `bus` must outlive the session. */
bool    od_epd_cfg_load(const struct DisplayConfig *d, const od_epd_cfg_bus_t *bus);
bool    od_epd_cfg_loaded(void);
/* The panel's BUSY idle level, for configuring the pin's pull. Valid after a load. */
uint8_t od_epd_cfg_busy_idle_level(void);
/* Whether the loaded panel's BUSY line can be believed (OD_PANEL_FLAG_BUSY_USABLE). */
bool    od_epd_cfg_busy_usable(void);

bool    od_epd_cfg_select(uint8_t mode, od_epd_cfg_mode_t *out);
uint8_t od_epd_cfg_mode_count(void);
/* The 0xB1 code_map (logical colour -> panel 2-bit code) of the loaded panel. Exposed, never
 * applied: frame bytes reach the panel as the host sent them. Whether firmware should remap is
 * an open protocol decision (docs/CONFIG_DRIVEN_DISPLAY.md). */
bool    od_epd_cfg_code_map(uint8_t out[4]);

/* Whether the stored config carries drive data (a 0xB1 and at least one 0xAE) for display `d`.
 * Cheap enough for a START path: one index build, no descriptor load. False is the "needs
 * migration" state of a 2.x config on 3.x firmware. */
bool    od_epd_cfg_has_drive_data(const struct DisplayConfig *d);

/* mode_index of the loaded display's mode whose 0xAE mode_name equals `name` (case-insensitive,
 * NUL-padded), or -1. Modes are identified by their packet's mode_index, never by packet order;
 * the first packet carrying an index wins. Conventions (docs/CONFIG_DRIVEN_DISPLAY.md): index 0
 * is the panel's default full refresh; the names "fast" and "partial" are reserved. */
int     od_epd_cfg_find_mode(const char *name);
/* As od_epd_cfg_find_mode, but -1 also when the mode's temperature window excludes `temp_c`
 * under REJECT or SUBSTITUTE: the caller then falls back to mode 0. */
int     od_epd_cfg_find_usable_mode(const char *name, int8_t temp_c);

/* Select `*mode`, then apply its temp_policy against `temp_c` (OD_DRIVE_TEMP_UNKNOWN skips it):
 * REJECT refuses, SUBSTITUTE moves `*mode` to mode 0 when mode 0's window covers temp_c.
 * Returns 0 or an OD_ERR_DRIVE_* code (BAD_MODE, TEMP_RANGE). */
uint8_t od_epd_cfg_select_policy(uint8_t *mode, int8_t temp_c, od_epd_cfg_mode_t *out);

/* WINDOW/FILL rectangle for the next begin_pass (partial update). select() resets it to the
 * whole panel. */
void    od_epd_cfg_set_window(uint16_t x, uint16_t y, uint16_t w, uint16_t h);
/* Finish the open pass with `mode`'s post-image tail instead of the active mode's own. */
bool    od_epd_cfg_finish_with_tail(uint8_t mode);
bool    od_epd_cfg_begin_pass(uint8_t pass);
bool    od_epd_cfg_write(const uint8_t *data, size_t len);
bool    od_epd_cfg_next_plane(void);
bool    od_epd_cfg_finish(void);
void    od_epd_cfg_sleep(void);
/* CMD_SPI_RAW with panel init: the walk paused at the image marker is never resumed (the host
 * owns the panel from there), so the config-write hold ends here rather than at CLOSE. */
void    od_epd_cfg_raw_detach(void);
/* The od_epd return code of the last failed begin_pass. */
int     od_epd_cfg_last_rc(void);

/* --- multi-pass stream ---------------------------------------------------------------------- */

/* One CMD_DRIVE_WRITE_START transfer: `passes` frames back to back. A frame boundary is a pass
 * boundary, and the refresh at that boundary blocks inside the write, which is also the flow
 * control -- the ACK of the chunk landing on it arrives once the pass is off the glass. */
/* Every image marker the walk pauses on consumes a budget of the frame. IMAGE takes one
 * controller plane on a CONTROLLER_PLANES frame and the whole frame otherwise. IMAGE_SLICE
 * part/of takes frame/of -- the protocol's "slices divide the frame" -- except on SPLIT_HALVES,
 * where x/2 takes that half's exact size. So a two-plane frame reads the same as IMAGE, IMAGE or
 * IMAGE_SLICE 0/2, 1/2, which is how the partial OLD/NEW planes are encoded. The writer advances to the next marker when a budget is spent, so a
 * sequence that declares fewer markers than the layout needs fails loudly mid-stream. */
typedef struct {
    uint32_t frame_bytes;
    uint32_t plane_size;   /* 0 unless the layout is CONTROLLER_PLANES */
    uint32_t total_bytes;
    uint32_t part_bytes[2];
    uint32_t marker_end;   /* absolute stream offset where the current marker's budget ends */
    uint8_t  layout;       /* od_color_layout_t */
    uint8_t  passes;
    uint8_t  pass;
} od_epd_cfg_stream_t;

/* Validates passes*frame against the START tail (a compressed stream's 4-byte declared length
 * must equal it, so a host with the wrong pass count is told at START) and fills `s`. */
bool od_epd_cfg_stream_init(od_epd_cfg_stream_t *s, const od_color_geometry_t *frame,
                            uint8_t passes, bool compressed, const uint8_t *tail,
                            uint16_t tail_len);

/* `phase` is told true before a mid-stream refresh and false once the next pass is open, so a
 * target can move its watchdog phase. May be NULL. */
bool od_epd_cfg_stream_write(od_epd_cfg_stream_t *s, uint32_t stream_offset,
                             const uint8_t *data, size_t len, void (*phase)(bool refreshing));

/* --- raw session (CMD_SPI_RAW) -------------------------------------------------------------- */

/* Bytes straight to the bus, bypassing the pass state machine. `data[0]` is the command. */
void od_epd_cfg_raw_cmd(const uint8_t *data, uint16_t len);
void od_epd_cfg_raw_data(const uint8_t *data, uint16_t len);
/* Waits for BUSY to release or the timeout. still_busy is re-read after the wait, so a release
 * at the timeout is told apart from a timeout. */
void od_epd_cfg_raw_busy(uint32_t timeout_ms, uint16_t *elapsed_ms_out, bool *still_busy_out);
void od_epd_cfg_raw_reset(uint8_t hold_ms);

#ifdef __cplusplus
}
#endif

#endif /* OD_EPD_CFG_H */
