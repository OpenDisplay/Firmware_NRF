/* Target seam for od_display, beyond what od_drive_app.h already asks for (display, bus, rail
 * and pins, temperature). */
#ifndef OD_DISPLAY_APP_H
#define OD_DISPLAY_APP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    OD_DISPLAY_PHASE_INIT = 0,   /* sequence head running: reset, registers, waveform */
    OD_DISPLAY_PHASE_STREAM,     /* frame bytes going into controller RAM */
    OD_DISPLAY_PHASE_REFRESH,    /* refresh tail, including its BUSY wait */
    OD_DISPLAY_PHASE_IDLE,       /* panel down */
} od_display_phase_t;

/* Watchdog breadcrumbs. A target without phases implements it empty. */
void od_display_app_phase(od_display_phase_t phase);

#ifdef __cplusplus
}
#endif

#endif /* OD_DISPLAY_APP_H */
