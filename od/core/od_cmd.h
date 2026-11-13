/* od_cmd.h -- what a handler returns, and what the dispatcher concluded about a frame.
 *
 * TYPES ONLY. The four here are genuinely shared: every target's handlers speak od_cmd_result_t,
 * every dispatch produces an od_frame_outcome_t, and od_frame_policy_t is what that outcome MEANS.
 * The per-command target seam is od_cmd_app.h and the opcode map is od_dispatch.c's; neither
 * belongs here. Do not grow this file into a command registry.
 */

#ifndef OD_CMD_H
#define OD_CMD_H

#include "od_txq.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* What a handler concluded. FOUR, and each distinction earns its place:
 *
 *  - AUTH_REJECTED is separate from NACK because a handler can refuse for want of authentication
 *    itself; without it a TLS client's refused CONFIG_WRITE stamps activity and holds the
 *    exclusive link forever.
 *  - UNKNOWN is separate from NACK because an unrecognised opcode must not be ACTIVITY. Folded
 *    into either of the others, unknown-command traffic would refresh the owner's idle clock and
 *    keep the exclusive link alive indefinitely. */
typedef enum {
    OD_CMD_OK,
    OD_CMD_NACK,
    OD_CMD_AUTH_REJECTED,
    OD_CMD_UNKNOWN          /* the target has no handler for this opcode */
} od_cmd_result_t;

/* What the dispatcher concluded about one inbound frame. The target turns this into policy in
 * od_core_frame_done(); see the table there for which outcomes stamp activity and which move the
 * auth-abuse run. The distinctions are load-bearing, not cosmetic:
 *
 *  - AUTH_CONTROL and DISCOVERY exist because a handshake or a version poll must NOT stamp
 *    activity. Treating either as ACCEPTED lets a discovery poll hold the exclusive link forever.
 *  - AUTH_ESTABLISHED is separate again: it resets the abuse run but still does not stamp.
 *  - AUTH_REQUIRED and CRYPTO_FAILED are separate because only the first advances the abuse run.
 *    od_sec2 already counts a bad tag toward its own three-strike rule; dispatch must not add
 *    a second strike for the same frame.
 *  - CRYPTO_DROPPED is the deliberate silence: a replayed or out-of-window PIPE data frame is
 *    ordinary packet loss, and answering it with a fatal NACK kills the upload.
 */
typedef enum {
    OD_FRAME_ACCEPTED,
    OD_FRAME_HANDLER_NACK,
    OD_FRAME_AUTH_CONTROL,      /* challenge or refused handshake; plaintext, not activity */
    OD_FRAME_AUTH_ESTABLISHED,  /* plaintext success; resets abuse, still not activity */
    OD_FRAME_DISCOVERY,         /* FIRMWARE_VERSION; plaintext, not activity */
    OD_FRAME_AUTH_REQUIRED,     /* answered [0x00][cmd][0xFE] -- gate OR handler */
    OD_FRAME_CRYPTO_FAILED,     /* crypto refusal answered [0x00][cmd][0xFF] */
    OD_FRAME_CRYPTO_DROPPED,    /* PIPE replay/out-of-window: logged, deliberately silent */
    OD_FRAME_REJECTED_FRAME,
    OD_FRAME_UNKNOWN_OPCODE,
    OD_FRAME_STALE_TAG,
    OD_FRAME_DEFERRED           /* the ONLY outcome that does not consume the RX entry */
} od_frame_outcome_t;

/* Everything a handler needs to answer: WHERE the reply goes and WHAT capacity it may spend.
 *
 * One struct rather than two parameters because the rewrite touches 78 call sites and a
 * transposed pair of pointers is not something the compiler can catch. `rp` is a COPY -- the reply
 * context is immutable for the dispatch -- while `r` is a pointer because units are spent as
 * replies are made. Making both pointers would invite a handler to keep `ctx` past its dispatch,
 * which is exactly what od_txq's token generation exists to catch. */
typedef struct {
    od_reply_t           rp;
    od_tx_reservation_t *r;
    uint16_t              wire_len;       /* complete request length before session open */
    bool                  was_protected;  /* this request successfully crossed CCM open */
} od_cmd_ctx_t;

/* What one outcome MEANS, as data rather than as a switch in each target. The two targets got this
 * wrong in different ways before it was written down, and the failure is quiet: an outcome that
 * wrongly stamps activity lets a discovery poll hold the exclusive link forever, and one that
 * wrongly does not stops an active client's idle clock and disconnects it mid-session. */
typedef struct {
    bool stamp_activity;   /* refresh the owner idle clock -- EVERY origin */
    bool reset_abuse;      /* clear the consecutive-auth-refusal run -- BLE only */
    bool increment_abuse;  /* advance that run -- BLE only */
    bool consume_rx;       /* false ONLY for DEFERRED: the frame must be re-offered unchanged */
} od_frame_policy_t;

/* Total over od_frame_outcome_t. The caller still owns the ORIGIN SCOPING, which is not in this
 * struct because it is not a property of the outcome: the stamp applies to every origin, the abuse
 * run is BLE-only, and both additionally require the tag to still own the link. */
od_frame_policy_t od_frame_policy(od_frame_outcome_t outcome);

/* Implemented by the target. Applies od_frame_policy() with that scoping. */
void od_core_frame_done(const od_reply_t *rp, od_frame_outcome_t outcome);

#ifdef __cplusplus
}
#endif

#endif /* OD_CMD_H */
