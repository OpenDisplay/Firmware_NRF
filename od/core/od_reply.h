/* od_reply.h -- the two ways a response leaves, and the explicit choice between them.
 *
 * CONFIDENTIALITY IS SELECTED BY THE CALL, NOT INFERRED FROM THE BYTES. Every target used to
 * decide whether to seal a response by inspecting it: ESP32 read the status from byte 2 with a
 * carve-out for PIPE ACKs, Nordic read byte 0 and so never recognised its own rejection frames --
 * it sealed them, and py-opendisplay decrypts any 31+ byte response and returns before its
 * raw[2] guards, so the host validated a refused command as an ACK. That was a silent false
 * success on the wire.
 *
 * The lesson is not "read a different byte". A response is a bag of bytes whose meaning depends on
 * the opcode, and 0xFE/0xFF appear inside legitimate payloads -- a 7-byte PIPE data ACK carries a
 * rolling highest_seen that hits both on any image of 255+ chunks. So the producer says which it
 * meant, once, at the call:
 *
 *   od_reply_plain()  control and error frames: AUTHENTICATE, FIRMWARE_VERSION, auth-required,
 *                     decrypt-failure, every hard NACK. Never sealed, whatever the session state.
 *   od_reply()        application responses, including all PIPE ACKs. Sealed when a live session
 *                     and the origin require it.
 *
 * No handler may choose by looking at its own payload.
 */

#ifndef OD_REPLY_H
#define OD_REPLY_H

#include "od_txq.h"

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Queue an application response. On a claimed device over BLE it is sealed as one SEC2 D->H
 * record ([E5][ctr][C][T], the whole frame is the plaintext); with no live session it becomes a
 * hard NACK, never cleartext. Unclaimed devices, LAN and the plaintext scope send it as is.
 *
 * Spends exactly one unit of `r`. Errors, and what the caller must do:
 *   OK          queued
 *   TOO_LARGE   the frame exceeds what the session or the origin can carry. The unit is spent on
 *               a plaintext hard NACK, already queued -- DO NOT emit a second reply.
 *   SEAL_FAILED sealing failed. Same: the hard NACK is queued, the unit is spent.
 *   GONE        the tag died; nothing queued.
 *   INVARIANT   caller bug (no token, no units, null frame); nothing queued.
 * A queued entry is immutable: a radio RETRY re-sends the same bytes and spends NO further nonce. */
od_txq_status_t od_reply(od_tx_reservation_t *r, const od_reply_t *rp,
                         const uint8_t *frame, uint16_t len);

/* Queue a control or error response verbatim. Never seals, never consults the session. Same unit
 * accounting and the same OD_TXQ_* results, minus the sealing ones. */
od_txq_status_t od_reply_plain(od_tx_reservation_t *r, const od_reply_t *rp,
                               const uint8_t *frame, uint16_t len);

/* The dispatcher brackets the plaintext-set handlers (0x0043, 0x0044, 0x0046; section 6 rule 1)
 * with on/off, so od_reply() inside them never seals. */
void od_reply_plain_scope(bool on);

#ifdef __cplusplus
}
#endif

#endif /* OD_REPLY_H */
