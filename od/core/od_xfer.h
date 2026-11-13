/* od_xfer.h -- shared legacy direct/partial transfer command policy. */
#ifndef OD_XFER_H
#define OD_XFER_H

#include "od_caps.h"
#include "od_cmd.h"
#include "od_color.h"
#include "od_span.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

od_cmd_result_t od_xfer_direct_start(const od_cmd_ctx_t *ctx, od_span_t body);
od_cmd_result_t od_xfer_data(const od_cmd_ctx_t *ctx, od_span_t body);
od_cmd_result_t od_xfer_end(const od_cmd_ctx_t *ctx, od_span_t body);
od_cmd_result_t od_xfer_partial_start(const od_cmd_ctx_t *ctx, od_span_t body);

/* Adopt a full-frame transfer whose panel the APP has ALREADY brought up.
 *
 * For CMD_DRIVE_WRITE_START (0x0085), which names a config-declared drive mode: resolving that
 * mode, enforcing its temp_policy and powering the glass are the target's to do, and they must
 * all happen before the byte count is even known (it is passes x frame). So unlike
 * od_xfer_direct_start this does NOT call od_xfer_app_begin_full -- the hardware is adopted,
 * not started -- and it sends no reply, because 0x0085 answers with its own
 * [mode][passes][temp_c] ACK rather than the direct-write one.
 *
 * `inline_data` is the stream tail already present in the START frame, past any
 * uncompressed-size field. DATA (0x0071) and END (0x0072) then continue the transfer unchanged.
 * Returns false having already failed the transfer and powered down. */
#if OD_CAP_DRIVE_WRITE
bool od_xfer_adopt_full(const od_reply_t *owner, const od_color_geometry_t *geometry,
                        uint32_t expected_bytes, bool compressed, od_span_t inline_data);
#endif

/* End the active transfer, if any, as replaced (aborting its hardware through the app).
 * For a START handler that is about to take the panel itself, as 0x0085 does before
 * od_xfer_adopt_full: refused or not, the old transfer cannot outlive its panel. */
void od_xfer_replace_active(void);

void od_xfer_reset(void);
bool od_xfer_active(void);
bool od_xfer_owns_hardware(void);
bool od_xfer_frames_may_arrive(void);
bool od_xfer_owner(od_reply_t *out);
/* Reports a strict elapsed > limit timeout without clearing state. A true result must be followed
 * immediately by the caller's existing full teardown path. */
bool od_xfer_report_timeout(uint32_t now_ms, uint32_t limit_ms);

/* True once an active transfer has begun consuming DATA frames. Safe to call from a radio
 * callback while the loop task owns the transfer state. */
bool od_xfer_log_quiet(uint16_t opcode);

#ifdef __cplusplus
}
#endif

#endif /* OD_XFER_H */
