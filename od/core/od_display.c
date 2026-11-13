/* See od_display.h. */
#include "od_display.h"

#include "od_boot_screen.h"
#include "od_display_app.h"
#include "od_drive_app.h"
#include "od_epd.h"
#include "od_epd_cfg.h"
#include "od_log.h"
#include "opendisplay_protocol.h"
#include "opendisplay_structs.h"

#include <string.h>

/* 0x0072 refresh byte values. */
#define REFRESH_FAST 1u

typedef enum {
    SESSION_IDLE = 0,
    SESSION_FULL,
    SESSION_PARTIAL,
    SESSION_DRIVE,
    SESSION_BOOT,
} session_t;

static session_t s_session;
static uint8_t s_mode;
static od_epd_cfg_stream_t s_stream;
/* Boot rows arrive without offsets; this is where the next one goes. */
static uint32_t s_boot_offset;

static void phase(od_display_phase_t p)
{
    od_display_app_phase(p);
}

static void stream_phase(bool refreshing)
{
    phase(refreshing ? OD_DISPLAY_PHASE_REFRESH : OD_DISPLAY_PHASE_STREAM);
}

static void end_session(void)
{
    if (s_session != SESSION_IDLE) {
        od_epd_cfg_sleep();
        od_drive_app_panel_down();
        phase(OD_DISPLAY_PHASE_IDLE);
    }
    s_session = SESSION_IDLE;
    memset(&s_stream, 0, sizeof s_stream);
}

void od_display_abort(void)
{
    end_session();
}

bool od_display_active(void)
{
    return s_session != SESSION_IDLE;
}

bool od_display_needs_migration(void)
{
    const struct DisplayConfig *d = od_drive_app_display();

    return d != NULL && !od_epd_cfg_has_drive_data(d);
}

static od_display_rc_t load(const struct DisplayConfig *d)
{
    if (d == NULL) {
        return OD_DISPLAY_NO_DISPLAY;
    }
    if (!od_epd_cfg_load(d, od_drive_app_bus())) {
        if (!od_epd_cfg_has_drive_data(d)) {
            od_log_warn("display: config has no drive packets (0xAE-0xB1); needs migration");
            return OD_DISPLAY_NEEDS_MIGRATION;
        }
        return OD_DISPLAY_PANEL;
    }
    return OD_DISPLAY_OK;
}

/* Select `*mode` under its temp_policy. `advisory` turns REJECT into a plain select (boot). */
static od_display_rc_t select_mode(uint8_t *mode, bool advisory, od_epd_cfg_mode_t *hdr)
{
    uint8_t err = od_epd_cfg_select_policy(mode, od_drive_app_temp_c(), hdr);

    if (err == OD_ERR_DRIVE_TEMP_RANGE && advisory) {
        err = od_epd_cfg_select(*mode, hdr) ? 0u : OD_ERR_DRIVE_BAD_MODE;
    }
    if (err == OD_ERR_DRIVE_TEMP_RANGE) {
        return OD_DISPLAY_TEMP_RANGE;
    }
    return err == 0u ? OD_DISPLAY_OK : OD_DISPLAY_BAD_MODE;
}

static od_display_rc_t load_and_select(const struct DisplayConfig *d, uint8_t *mode,
                                       bool advisory, od_epd_cfg_mode_t *hdr)
{
    const od_display_rc_t rc = load(d);

    return rc != OD_DISPLAY_OK ? rc : select_mode(mode, advisory, hdr);
}

/* A single-pass mode that renders the panel's own scheme -- the only kind an ordinary upload's
 * wire geometry (from 0x20) can feed. */
static bool plain_mode(const struct DisplayConfig *d, const od_epd_cfg_mode_t *hdr)
{
    return hdr->passes == 1u &&
           (hdr->color_scheme == 0xFFu || hdr->color_scheme == d->color_scheme);
}

static od_display_rc_t open_pass(const struct DisplayConfig *d, const od_color_geometry_t *g,
                                 session_t kind)
{
    phase(OD_DISPLAY_PHASE_INIT);
    if (!od_drive_app_panel_up(d)) {
        return OD_DISPLAY_PANEL;
    }
    if (!od_epd_cfg_begin_pass(0u)) {
        const int rc = od_epd_cfg_last_rc();
        const bool unsup = rc == OD_EPD_RC_UNSUP;

        od_log_error("display: pass 0 begin failed rc=%d", rc);
        od_epd_cfg_sleep();
        od_drive_app_panel_down();
        phase(OD_DISPLAY_PHASE_IDLE);
        return unsup ? OD_DISPLAY_SEQ_UNSUPPORTED
                     : rc == OD_EPD_RC_BUSY ? OD_DISPLAY_PANEL_BUSY : OD_DISPLAY_PANEL;
    }
    if (!od_epd_cfg_stream_init(&s_stream, g, 1u, false, NULL, 0u)) {
        od_epd_cfg_sleep();
        od_drive_app_panel_down();
        phase(OD_DISPLAY_PHASE_IDLE);
        return OD_DISPLAY_PANEL;
    }
    s_session = kind;
    phase(OD_DISPLAY_PHASE_STREAM);
    return OD_DISPLAY_OK;
}

od_display_rc_t od_display_begin_full(const od_color_geometry_t *geometry)
{
    const struct DisplayConfig *d = od_drive_app_display();
    od_epd_cfg_mode_t hdr;
    od_display_rc_t rc;

    end_session();
    if (geometry == NULL || geometry->total_bytes == 0u) {
        return OD_DISPLAY_BAD_MODE;
    }
    s_mode = 0u;
    rc = load_and_select(d, &s_mode, false, &hdr);
    if (rc != OD_DISPLAY_OK) {
        return rc;
    }
    if (!plain_mode(d, &hdr)) {
        od_log_error("display: mode %u is not a single-pass mode of the panel scheme",
                     (unsigned)s_mode);
        return OD_DISPLAY_BAD_MODE;
    }
    return open_pass(d, geometry, SESSION_FULL);
}

bool od_display_partial_available(void)
{
    const struct DisplayConfig *d = od_drive_app_display();

    if (s_session != SESSION_IDLE || d == NULL || !od_epd_cfg_load(d, od_drive_app_bus())) {
        return false;
    }
    return od_epd_cfg_find_usable_mode("partial", od_drive_app_temp_c()) >= 0;
}

od_display_rc_t od_display_begin_partial(uint16_t x, uint16_t y, uint16_t w, uint16_t h,
                                         uint32_t plane_bytes)
{
    const struct DisplayConfig *d = od_drive_app_display();
    od_color_geometry_t g;
    od_epd_cfg_mode_t hdr;
    od_display_rc_t rc;
    int m;

    end_session();
    if (d == NULL) {
        return OD_DISPLAY_NO_DISPLAY;
    }
    if (plane_bytes == 0u || plane_bytes > UINT32_MAX / 2u) {
        return OD_DISPLAY_BAD_MODE;
    }
    rc = load(d);
    if (rc != OD_DISPLAY_OK) {
        return rc;
    }
    m = od_epd_cfg_find_usable_mode("partial", od_drive_app_temp_c());
    if (m < 0) {
        return OD_DISPLAY_BAD_MODE;
    }
    s_mode = (uint8_t)m;
    rc = select_mode(&s_mode, false, &hdr);
    if (rc != OD_DISPLAY_OK) {
        return rc;
    }
    if (hdr.passes != 1u) {
        return OD_DISPLAY_BAD_MODE;
    }
    od_epd_cfg_set_window(x, y, w, h);

    memset(&g, 0, sizeof g);
    g.layout = OD_COLOR_LAYOUT_CONTROLLER_PLANES;
    g.bits_per_pixel = 1u;
    g.part_count = 2u;
    g.part_width[0] = w;
    g.part_width[1] = w;
    g.row_bytes[0] = (uint32_t)(w + 7u) / 8u;
    g.row_bytes[1] = g.row_bytes[0];
    g.part_bytes[0] = plane_bytes;
    g.part_bytes[1] = plane_bytes;
    g.total_bytes = plane_bytes * 2u;
    return open_pass(d, &g, SESSION_PARTIAL);
}

bool od_display_adopt_drive(const od_color_geometry_t *frame, uint8_t passes, bool compressed,
                            od_span_t tail)
{
    if (!od_epd_cfg_stream_init(&s_stream, frame, passes, compressed, tail.p, (uint16_t)tail.n)) {
        /* The handler brought the panel up; no session owns it yet, so take it down here. */
        od_epd_cfg_sleep();
        od_drive_app_panel_down();
        phase(OD_DISPLAY_PHASE_IDLE);
        return false;
    }
    s_session = SESSION_DRIVE;
    phase(OD_DISPLAY_PHASE_STREAM);
    return true;
}

bool od_display_write(uint32_t stream_offset, const uint8_t *data, size_t len)
{
    if (s_session == SESSION_IDLE || data == NULL) {
        return false;
    }
    return od_epd_cfg_stream_write(&s_stream, stream_offset, data, len, stream_phase);
}

bool od_display_refresh(uint8_t refresh_mode)
{
    bool ok;

    if (s_session == SESSION_IDLE) {
        return false;
    }
    phase(OD_DISPLAY_PHASE_REFRESH);
    if (s_session == SESSION_FULL && refresh_mode == REFRESH_FAST) {
        /* No "fast" mode, or one whose window excludes the reading: mode 0's own tail. */
        const int fast = od_epd_cfg_find_usable_mode("fast", od_drive_app_temp_c());

        if (fast >= 0 && (uint8_t)fast != s_mode) {
            ok = od_epd_cfg_finish_with_tail((uint8_t)fast);
        } else {
            ok = od_epd_cfg_finish();
        }
    } else {
        /* A partial or drive session already names its waveform; the byte selects nothing. */
        ok = od_epd_cfg_finish();
    }
    if (!ok) {
        od_log_error("display: refresh failed");
    }
    end_session();
    return ok;
}

/* --- boot screen ---------------------------------------------------------------------------- */

static od_display_rc_t boot_pass(const struct od_config *cfg, const struct SecurityConfig *sec,
                                 enum od_setup_screen kind, uint32_t code,
                                 const struct od_boot_bufs *bufs)
{
    const struct DisplayConfig *d = od_drive_app_display();
    od_color_geometry_t g;
    od_epd_cfg_mode_t hdr;
    od_display_rc_t rc;
    bool ok;

    end_session();
    if (d == NULL) {
        return OD_DISPLAY_NO_DISPLAY;
    }
    s_mode = 0u;
    rc = load_and_select(d, &s_mode, true, &hdr);
    if (rc != OD_DISPLAY_OK) {
        return rc;
    }
    if (!plain_mode(d, &hdr) ||
        od_color_direct_geometry(d->color_scheme, d->pixel_width, d->pixel_height, &g)
            != OD_COLOR_OK) {
        return OD_DISPLAY_BAD_MODE;
    }
    rc = open_pass(d, &g, SESSION_BOOT);
    if (rc != OD_DISPLAY_OK) {
        return rc;
    }
    s_boot_offset = 0u;
    ok = kind == OD_SETUP_SCREEN_NORMAL ? od_boot_screen_render(cfg, sec, bufs)
                                        : od_boot_screen_render_setup(cfg, kind, code, bufs);
    /* A short frame would refresh whatever the controller RAM held in the rest. */
    if (!ok || s_boot_offset != g.total_bytes) {
        od_log_error("display: boot render %s (%u of %u B)", ok ? "short" : "failed",
                     (unsigned)s_boot_offset, (unsigned)g.total_bytes);
        end_session();
        return OD_DISPLAY_PANEL;
    }
    phase(OD_DISPLAY_PHASE_REFRESH);
    ok = od_epd_cfg_finish();
    end_session();
    return ok ? OD_DISPLAY_OK : OD_DISPLAY_PANEL;
}

od_display_rc_t od_display_boot(const struct od_config *cfg, const struct SecurityConfig *sec,
                                const struct od_boot_bufs *bufs)
{
    return boot_pass(cfg, sec, OD_SETUP_SCREEN_NORMAL, 0u, bufs);
}

od_display_rc_t od_display_setup_screen(const struct od_config *cfg, enum od_setup_screen kind,
                                        uint32_t code, const struct od_boot_bufs *bufs)
{
    if (kind == OD_SETUP_SCREEN_NORMAL) {
        return OD_DISPLAY_BAD_MODE;
    }
    return boot_pass(cfg, NULL, kind, code, bufs);
}

/* The renderer's panel half of od_boot_app.h. The target still supplies the identity half
 * (device id, version, battery, temperature). Planes and halves need no addressing here: the
 * stream advances to the sequence's next image marker when a plane's budget is spent.
 *
 * A target that also renders the boot screen into a panel this module does not drive (ESP32's
 * IT8951 and parallel panels) builds with OD_DISPLAY_SHARED_BOOT_SINK=0: these functions then
 * carry the od_display_boot_sink_ prefix (od_display.h) and the target's od_boot_app_* picks
 * one sink per frame. */
#if OD_DISPLAY_SHARED_BOOT_SINK
#define BOOT_SINK(name) od_boot_app_##name
#else
#define BOOT_SINK(name) od_display_boot_sink_##name
#endif

int BOOT_SINK(begin_frame)(uint16_t width, uint16_t height, uint8_t segments)
{
    (void)width;
    (void)height;
    (void)segments;
    return s_session == SESSION_BOOT ? 0 : -1;
}

int BOOT_SINK(begin_plane)(int plane)
{
    (void)plane;
    return s_session == SESSION_BOOT ? 0 : -1;
}

int BOOT_SINK(write_row)(uint16_t y, uint8_t segment, const uint8_t *row, uint16_t len)
{
    (void)y;
    (void)segment;
    if (s_session != SESSION_BOOT ||
        !od_epd_cfg_stream_write(&s_stream, s_boot_offset, row, len, NULL)) {
        return -1;
    }
    s_boot_offset += len;
    return 0;
}

int BOOT_SINK(end_plane)(int plane)
{
    (void)plane;
    return 0;
}

int BOOT_SINK(end_frame)(void)
{
    return 0;
}

/* Must match the wire packing (od_color_direct_geometry), because the boot frame streams
 * through the same markers an upload does. */
int BOOT_SINK(bits_per_pixel)(uint8_t color_scheme)
{
    switch (color_scheme) {
        case OD_COLOR_SCHEME_BWGBRY:
        case OD_COLOR_SCHEME_BWGBRY_SPLIT:
        case OD_COLOR_SCHEME_GRAY16:
        case OD_COLOR_SCHEME_SEVEN_COLOR:
            return 4;
        case OD_COLOR_SCHEME_BWRY:
        case OD_COLOR_SCHEME_GRAY4:
            return 2;
        case OD_COLOR_SCHEME_MONO:
        case OD_COLOR_SCHEME_BWR:
        case OD_COLOR_SCHEME_BWY:
            return 1;
        default:
            return 0;
    }
}

int BOOT_SINK(default_plane)(uint8_t color_scheme)
{
    (void)color_scheme;
    return 0;
}

/* GRAY4 goes out as two 1bpp planes, the wire's CONTROLLER_PLANES layout. */
bool BOOT_SINK(direct_2bpp)(void)
{
    return false;
}

uint8_t BOOT_SINK(segments)(void)
{
    const struct DisplayConfig *d = od_drive_app_display();

    return (d != NULL && d->color_scheme == OD_COLOR_SCHEME_BWGBRY_SPLIT) ? 2u : 1u;
}
