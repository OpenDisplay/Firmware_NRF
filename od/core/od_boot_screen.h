#ifndef OD_BOOT_SCREEN_H
#define OD_BOOT_SCREEN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "od_claim_app.h"
#include "od_config.h"

#ifdef __cplusplus
extern "C" {
#endif

struct od_boot_bufs {
  uint8_t *row;
  size_t row_len;
  uint8_t *qr;
  size_t qr_len;
};

/* The NORMAL boot screen. `security` is unused (kept for the callers): what the key lines and the
 * QR say comes only from od_boot_screen_key() (od_boot_payload.h, SECURITY_V2 10.7). */
bool od_boot_screen_render(const struct od_config *cfg,
                           const struct SecurityConfig *security,
                           const struct od_boot_bufs *bufs);

/* One screen of the setup family (SECURITY_V2 7.8: SETUP, CODE, RESET) into the same sink. A
 * fixed layout of firmware text (od_setup_content_build): no 0x2C header, no footer, no swatches;
 * the only variable inputs are the device id, the firmware version and target, the code digits
 * and, inside the QR only, the simple-config indices. kind NORMAL is refused (false). */
bool od_boot_screen_render_setup(const struct od_config *cfg, enum od_setup_screen kind,
                                 uint32_t code, const struct od_boot_bufs *bufs);

#ifdef __cplusplus
}
#endif

#endif
