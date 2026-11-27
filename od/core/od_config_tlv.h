/* od_config_tlv.h -- walking the stored config blob, shared by every target.
 *
 * WHY THIS IS THE PART WORTH PROMOTING. The config parser is the PRE-AUTH ATTACK SURFACE: the
 * blob is parsed at boot from storage a client can write, and on a device with encryption
 * disabled the write path has no authentication gate at all. Its risk is concentrated entirely
 * in the frame walk -- the offset arithmetic and the `does this packet fit` checks -- and not
 * in the memcpy that follows. The ESP32 spelled those checks out fifteen times, once per
 * packet type, each an independent chance to write `<=` where `<` was meant.
 *
 * This module decides where a packet starts, how long it is, and whether it fits; the callback
 * receives a body whose bounds are already guaranteed. od_config.c owns the shared aggregate,
 * instance caps and outcome logging above this structural walk.
 *
 * TWO RANGES, TWO RULES FOR AN UNKNOWN ID.
 *
 *   0x00-0x7F  FROZEN at 0x2D. No length on the wire, so the size comes from the table below
 *              and an id this build does not know ABANDONS THE REST OF THE BLOB -- the walk
 *              cannot find the next packet without a size. (The size-table skip model that
 *              would change this for legacy ids is still deferred, D4.)
 *   0x80-0xFF  [number][id][length:2 LE][body]. An unknown id is STEPPED OVER by its declared
 *              length and the walk continues. This is why every packet added after 0x2D lives
 *              here: it is what lets a config carrying a new packet still load on firmware
 *              that predates it.
 *
 * The declared length is attacker-controlled -- see the pre-auth note above. It is never added
 * to an offset; od_span_split compares against what remains, so an oversized declaration
 * truncates rather than reaching past the body region.
 *
 * Plain C99. No allocation, no storage access, no logging: this module reads a buffer and
 * reports. It cannot alter what it parses.
 */
#ifndef OD_CONFIG_TLV_H
#define OD_CONFIG_TLV_H

#include <stdbool.h>
#include <stdint.h>

#include "od_span.h"
#include "opendisplay_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The outer blob is [reserved:2][version:1] ... [crc:2 LE]. Both ends are fixed overhead the
 * walk must not mistake for packet data -- getting the trailing two wrong is how a CRC gets
 * parsed as a packet header. */
#define OD_CFG_TLV_HEADER_LEN 3u
#define OD_CFG_TLV_CRC_LEN    2u

/* Ids at or above this carry their own length; below it the size comes from the table. */
#define OD_CFG_TLV_LEN_PREFIXED_MIN 0x80u

/* OD_PKT_ACTION_TABLE (0xB2) is canonical at structs 2.3 (opendisplay_structs.h). */

/* The drive packet ids are OD_PKT_DISPLAY_{MODE,LUT,CALIB,PANEL} in the canonical contract
 * (opendisplay_structs.h) and are not redefined here. They are variable-length, so they have
 * no size-table entry; 0x2E-0x31 were burned by pre-release lab builds carrying fixed-size
 * drafts of them and must never be reused. */

/* Burned ids and the fixed sizes those lab builds wrote. Sized so a stale config walks past
 * them; never delivered to a walk callback, never indexed. Sizes match Firmware_Silabs
 * opendisplay_constants.h CONFIG_PKT_BURNED_*_SIZE. */
#define OD_CFG_TLV_BURNED_2E       0x2Eu
#define OD_CFG_TLV_BURNED_2F       0x2Fu
#define OD_CFG_TLV_BURNED_30       0x30u
#define OD_CFG_TLV_BURNED_31       0x31u
#define OD_CFG_TLV_BURNED_2E_SIZE  157u
#define OD_CFG_TLV_BURNED_2F_SIZE  541u
#define OD_CFG_TLV_BURNED_30_SIZE  116u
#define OD_CFG_TLV_BURNED_31_SIZE  36u

enum od_config_tlv_result {
    OD_CFG_TLV_OK = 0,
    OD_CFG_TLV_TOO_SHORT,    /* smaller than header + CRC; nothing to parse */
    OD_CFG_TLV_TRUNCATED,    /* a packet claims more bytes than the blob holds */
    OD_CFG_TLV_REJECTED      /* the callback refused a packet */
};

/* Receives ONE packet as a span of exactly its body: body.n is the declared size for packet_id
 * and every byte of it lies inside the blob. The callback cannot be handed a length that does
 * not belong to the pointer, because it is not handed a length at all -- that pairing is what
 * od_span_t exists to remove (CLAUDE.md decision 1).
 *
 * Return false to abort the walk (OD_CFG_TLV_REJECTED). Returning true for a packet the target
 * does not implement is correct and expected -- capability differences are not parse errors.
 */
typedef bool (*od_config_tlv_packet_fn)(void *ctx, uint8_t packet_id, od_span_t body);

/* Declared body size for a LEGACY (< 0x80) packet id, or 0 if this build does not know it.
 *
 * Returns 0 for every length-prefixed id as well: those carry their size on the wire, so there
 * is nothing for a table to say about them. Callers must not read a 0 here as "unknown"
 * without first checking the range. Sizes come from the canonical structs, never from a
 * hand-written number.
 */
uint16_t od_config_tlv_body_size(uint8_t packet_id);

/* True for the reserved 0x2E-0x31: sized so a walk can step over them, never consumed. */
bool od_config_tlv_is_burned(uint8_t packet_id);

/* Walk the blob, calling fn once per packet whose body could be bounded.
 *
 * version_out receives the outer version byte when the blob is long enough to have one.
 *
 * AN UNKNOWN LEGACY ID ENDS THE WALK; an unknown length-prefixed id does not -- see the two
 * rules in the header comment. The walk stops cleanly and returns OD_CFG_TLV_OK: a config
 * carrying a packet this build does not know is not corrupt, it is newer.
 *
 * fn is called for length-prefixed packets whether or not this build knows them, because the
 * body is bounded either way and a consumer that ignores one simply returns true. The walker
 * keeps no list of which 0x80+ ids are "real".
 *
 * unknown_id_out, when supplied, receives the legacy id that ended the walk, or 0 if it ran to
 * the end. Skipped length-prefixed ids are NOT reported here -- they did not end anything, and
 * reporting them would make a forward-compatible config look like a truncated one. The walk
 * deliberately does no logging of its own: od_config_parse() owns the complete outcome.
 */
enum od_config_tlv_result od_config_tlv_walk(od_span_t blob,
                                             od_config_tlv_packet_fn fn, void *ctx,
                                             uint8_t *version_out,
                                             uint8_t *unknown_id_out);

/* CRC-16/CCITT over the body, matching the toolbox, nRF and Silabs firmware.
 *
 * ADVISORY ONLY at every call site today: a mismatch is warned about, never enforced. Promoted
 * as-is rather than tightened, because making it authoritative is a behaviour change that would
 * reject configs currently accepted across the whole fleet -- a deliberate decision to take
 * separately, not a side effect of moving the function.
 */
uint16_t od_config_tlv_crc16(od_span_t data);

#ifdef __cplusplus
}
#endif

#endif /* OD_CONFIG_TLV_H */
