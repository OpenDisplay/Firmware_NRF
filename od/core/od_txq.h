/* od_txq.h -- the response queue, its capacity reservation, and the drain.
 *
 * WHY A RESERVATION EXISTS AT ALL. Handlers mutate state before they reply: a config write commits
 * to storage and then acks. If the queue is full at ack time the device has done the work and the
 * host is never told, which is indistinguishable from the work not happening. So capacity is
 * claimed BEFORE the handler runs, and a handler that cannot be answered is never invoked.
 *
 * WHY A COUNTER AND NOT RESERVED SLOTS. A reserved-but-unwritten slot is a hole in a FIFO, and the
 * pre-refresh flush would stall on it -- exactly the failure the barrier exists to prevent, since
 * a 0x72 END holds its reservation across a refresh that can take a minute. A counter has no
 * holes. The cost is one memcpy of the finished frame instead of composing in place.
 *
 * WHY A TOKEN AND NOT A BARE COUNTER. Ownership. A config producer and an incoming command can
 * both be mid-flight across loop passes, and "some reply consumed a unit" is not the same as "THIS
 * reply consumed one of ITS units". The token makes borrowing another frame's capacity an
 * invariant failure rather than an accident that shows up as a lost ack under load.
 *
 * CONTEXT: single loop/main task, like od_adv_control and od_sec2. No locks. The token supplies
 * the ownership a bare global counter did not; it does not make this reentrant.
 */

#ifndef OD_TXQ_H
#define OD_TXQ_H

#include "od_hal_radio.h"
#include "opendisplay_protocol.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Storage width of one entry. OD_BLE_MAX_FRAME is the whole ATT frame -- opcode(1) + handle(2) +
 * value -- so the largest VALUE a BLE entry may carry is 253, which od_txq_commit() enforces.
 * Storing 256 is not permission to send 256; see OD_TXQ_VALUE_MAX_BLE. */
#define OD_TX_FRAME_MAX      OD_BLE_MAX_FRAME              /* 256 */
#define OD_TXQ_VALUE_MAX_BLE (OD_BLE_MAX_FRAME - 3u)       /* 253 */

/* Depth. OD_PIPE_MAX_W + 2 leaves usable capacity (SLOTS - 1) for a full window plus END.
 * od_pipe.h asserts the relationship for PIPE-capable builds. */
#ifndef OD_TXQ_SLOTS
#define OD_TXQ_SLOTS 34u
#endif

typedef enum {
    OD_TXQ_OK = 0,
    OD_TXQ_FULL,        /* reserve only, and always BEFORE any handler mutation */
    OD_TXQ_GONE,        /* the tag died; nothing was queued */
    OD_TXQ_BUSY,        /* flush only: not drained yet, deadline NOT reached -- call again */
    OD_TXQ_TIMEOUT,     /* flush only: deadline reached, entries LEFT QUEUED, never dropped */
    OD_TXQ_TOO_LARGE,   /* value above what the origin or the session can carry */
    OD_TXQ_SEAL_FAILED, /* sealing failed; a plaintext hard NACK is ALREADY QUEUED in its place */
    OD_TXQ_INVARIANT    /* a bug in the caller: no token, no units left, null frame */
} od_txq_status_t;

/* Capacity claimed by one dispatch, and the units it has left. Deliberately a struct rather than a
 * bare count so it cannot be confused with a slot index or silently copied around as an int.
 *
 * `gen` is what makes a token die with the queue it was taken from. Without it a token that
 * survives od_txq_reset() -- a link teardown, od_core_reset() -- can still commit into the fresh
 * ring, and each such commit decrements a reserved count that reset already zeroed, wrapping it to
 * 255 and refusing every reserve afterwards until the next reset. Do not construct one by hand. */
typedef struct { uint8_t remaining; uint8_t gen; } od_tx_reservation_t;

/* Where a reply is going. Carried separately from the frame because the frame is bytes and this is
 * addressing -- the same bytes may be legal for one link and refused for another. */
typedef struct {
    od_origin_t origin;
    uint32_t    tag;
} od_reply_t;

/* Are two reply identities the same link? C cannot compare aggregates, so every owner check would
 * otherwise be hand-written field by field -- and the day this struct gains a third member, each
 * of those sites silently keeps comparing two. One helper beside the type makes that a single
 * edit. Not memcmp: the struct has padding, and comparing it would depend on the compiler having
 * zeroed bytes nobody assigned. */
static inline bool od_reply_same(const od_reply_t *a, const od_reply_t *b)
{
    return a->origin == b->origin && a->tag == b->tag;
}

/* Drop every entry and zero the reserved count. For od_core_reset() and for test setup. Does NOT
 * touch the session: teardown goes through the target's session owner, never a memset here. */
void od_txq_reset(void);

/* Claim `count` units. FULL when free capacity minus everything already reserved cannot cover it,
 * which is the only moment a frame may be refused without side effects. */
od_txq_status_t od_txq_reserve(uint8_t count, od_tx_reservation_t *r);

/* Return a token's UNUSED units. Idempotent and NULL-safe; every dispatch path must call it,
 * including the ones that returned early, or capacity leaks until the next reset. */
void od_txq_release(od_tx_reservation_t *r);

/* Queue one finished frame, spending exactly one unit from `r`. The bytes are copied, so the
 * caller's buffer is free immediately.
 *
 * Spending a unit the token does not have is OD_TXQ_INVARIANT, not permission to borrow: it means
 * a handler emitted more replies than its opcode's reservation allows, and the honest outcome is
 * to drop the frame and say so rather than to steal capacity another dispatch is relying on. */
od_txq_status_t od_txq_commit(od_tx_reservation_t *r, const od_reply_t *rp,
                              const uint8_t *frame, uint16_t len);

/* One drain pass. Per-entry, by od_radio_result_t:
 *   SENT   advance
 *   RETRY  keep the entry and STOP this pass -- the transport is not accepting, and continuing
 *          would reorder the queue behind an entry that must go first
 *   GONE   drop every entry for that tag, then continue with the rest
 *   ERROR  drop THIS entry only, log at the target, continue -- a permanent refusal must not be
 *          retried (a retry loop on a permanent error is how a drain becomes a spin) and is not
 *          grounds for tearing the link down
 * A dead tag is dropped without a send attempt. Returns the number of entries retired. */
uint16_t od_txq_process(void);

/* ONE drain attempt against a deadline. The pre-refresh barrier: a panel refresh can take a
 * minute, and an END ack that leaves after it looks to the host like a transfer that hung.
 *
 * ON EXPIRY ENTRIES STAY QUEUED and TIMEOUT is returned. That is the resolved divergence: ESP32
 * delivers late under backpressure, Nordic dropped. Late is recoverable; dropped is not. Callers
 * must treat TIMEOUT as "proceed with the refresh", not as an error to report on the wire.
 *
 * This module owns no clock and must not block, so it cannot wait out the deadline itself: one
 * call is one drain attempt, and the caller re-enters with an advanced now_ms. That keeps the
 * waiting in the loop that also feeds the watchdog. */
od_txq_status_t od_txq_flush(uint32_t now_ms, uint32_t deadline_ms);

/* IMPLEMENTED BY THE TARGET, IN ADDITION to the line od_txq.c has already logged. Called when
 * the drain discards an entry that can never be sent -- a permanent radio refusal, or a link that
 * died with frames still queued. MUST NOT queue, block, or re-enter od_txq.
 *
 * It was built on the belief that shared/ may not include a log header, which was wrong. What
 * keeps it is BG22, which implements it with printf and has no other diagnostic for this event;
 * a target whose only transport is od_log implements this empty.
 *
 * A dropped response is invisible from the wire -- the host simply waits -- so without this the
 * only symptom of a permanently refusing transport is a client timing out for no stated reason. */
void od_txq_app_dropped(const od_reply_t *rp, uint16_t len, od_radio_result_t why);

/* Observability, for tests and for a target's diagnostics. */
uint16_t od_txq_depth(void);      /* entries currently queued */
uint8_t  od_txq_reserved(void);   /* units claimed by live tokens and not yet spent */

#ifdef __cplusplus
}
#endif

#endif /* OD_TXQ_H */
