/* od_hal_radio.h -- the transport a queued response leaves through.
 *
 * The fourth shared HAL, after od_hal_adv, od_hal_wdt and od_hal_crypto. Division of labour: this
 * header owns nothing but the act of handing bytes to a link and asking whether that link is still
 * the one that asked. Queue policy, reservation, sealing and drain ordering are od_txq's; framing
 * is od_sec2's; who may talk is the target's connection policy.
 *
 * NOT ISR-SAFE, and not intended to be. Every caller runs on the single loop/main context that
 * owns the queue, the same contract od_adv_control and od_sec2 already state.
 */

#ifndef OD_HAL_RADIO_H
#define OD_HAL_RADIO_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
/* The targets compile C++ (NimBLE, bb_epaper); shared/ is C99. Everything crossing this boundary
 * is a link-time C function, per CLAUDE.md architectural decision 1. */
extern "C" {
#endif

/* Which transport a frame belongs to. Mirrors esp32-idf's enum CommandOrigin by value so the
 * target can cast rather than translate; Nordic has BLE only and never names the others.
 *
 * It is here rather than in od_txq.h because it is what makes a queue entry ADDRESSABLE -- the
 * queue holds frames for more than one link, and a drain has to know which one to hand each to. */
typedef enum {
    OD_ORIGIN_BLE       = 0,
    OD_ORIGIN_LAN_PLAIN = 1,
    OD_ORIGIN_LAN_TLS   = 2
} od_origin_t;

/* The outcome of one attempt to put one frame on one link. The four are NOT interchangeable and
 * the drain does something different with each -- see od_txq_process().
 *
 * RETRY vs ERROR is the distinction that matters: RETRY means "not now, ask again", ERROR means
 * "this call will never work". Collapsing them turns a drain into a spin. */
typedef enum {
    OD_RADIO_SENT,   /* accepted by the stack; the entry is done */
    OD_RADIO_RETRY,  /* transport busy or unwritable; the SAME entry must be offered again */
    OD_RADIO_GONE,   /* the tag is dead; every entry for it is undeliverable */
    OD_RADIO_ERROR   /* malformed call or a permanent stack refusal; never retried */
} od_radio_result_t;

/* Hand one frame to the link identified by (origin, tag). `len` is the ATT value length, which for
 * BLE is at most OD_BLE_MAX_FRAME - 3 (253) -- the storage width of a queue entry is larger and is
 * not permission to exceed that.
 *
 * MUST NOT BLOCK. A busy transport returns RETRY; sleeping here stalls the loop that also feeds
 * the watchdog and drains the RX ring. */
od_radio_result_t od_hal_radio_send(od_origin_t origin, uint32_t tag,
                                    const uint8_t *frame, uint16_t len);

/* Is the connection this tag names still the live one? BLE connection handles are reused, so a tag
 * is an instance identity rather than a handle: a frame queued by a dead instance must not be
 * delivered to whoever inherited its slot. Called before spending a drain pass on an entry. */
bool od_hal_radio_tag_is_live(od_origin_t origin, uint32_t tag);

#ifdef __cplusplus
}
#endif

#endif /* OD_HAL_RADIO_H */
