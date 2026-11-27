/* Target seam for the shared CMD_DRIVE_WRITE_START handler (shared/core/od_cmd_drive.c).
 *
 * The handler owns the wire: argument checks, mode selection, temp_policy, geometry and the
 * reply. The target owns the panel's rail, bus and pins, and the transfer state the shared
 * od_xfer layer writes into through od_xfer_app_write(). BG22 keeps its own handler.
 */
#ifndef OD_DRIVE_APP_H
#define OD_DRIVE_APP_H

#include "od_color.h"
#include "od_epd_cfg.h"
#include "od_span.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct DisplayConfig;

/* Temperature the handler reports, and skips policy on, when there is no reading. */
#define OD_DRIVE_TEMP_UNKNOWN ((int8_t)0x7F)

/* The display a drive transfer targets; NULL when none is configured. */
const struct DisplayConfig *od_drive_app_display(void);
/* The wire half of od_epd_cfg for that display. Must outlive the session. */
const od_epd_cfg_bus_t *od_drive_app_bus(void);
/* Ends any transfer or raw session holding the panel. */
void od_drive_app_abort(void);
/* Rail up, bus acquired, D/C CS RST BUSY claimed (BUSY pulled toward
 * od_epd_cfg_busy_idle_level()). False leaves the panel down. */
bool od_drive_app_panel_up(const struct DisplayConfig *d);
void od_drive_app_panel_down(void);
/* Takes over transfer state for a drive stream; pass 0 is already open. Returns false if the
 * size check in od_epd_cfg_stream_init() refuses it. */
bool od_drive_app_adopt(const od_color_geometry_t *frame, uint8_t passes, bool compressed,
                        od_span_t tail);
/* Glass temperature estimate in whole degrees C, or OD_DRIVE_TEMP_UNKNOWN. */
int8_t od_drive_app_temp_c(void);

#ifdef __cplusplus
}
#endif

#endif /* OD_DRIVE_APP_H */
