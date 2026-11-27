/* od_config_asm.h -- chunked CONFIG_WRITE reassembly, shared by every target.
 *
 * THE DEFECT THIS EXISTS TO FIX (correctness review F3). The ESP32 implementation treated any
 * payload over 200 bytes as chunked, never checked the declared total against what actually
 * arrived, and committed on a CHUNK COUNT rather than a byte count. Four consequences, all
 * reachable from a malformed client:
 *
 *   - a 201-byte start was ACKed as an active one-chunk transfer and never saved;
 *   - a start frame longer than 202 bytes silently discarded the excess;
 *   - a declared total of 201 followed by a 200-byte continuation committed 400 bytes,
 *     because the chunk count reached the expected two; and
 *   - a declared total above OD_CONFIG_MAX_SIZE was not rejected at the start, so the transfer
 *     failed later for an indirect reason.
 *
 * The third is the one that matters: a byte sequence inconsistent with its own declared length
 * was written to NVS. Even where downstream CRC parsing rejects it, storage has already
 * changed -- and on a device with encryption disabled the config-write path has no
 * authentication gate at all, so any client that can connect can reach it.
 *
 * WHY THIS MODULE TOUCHES NO STORAGE. Reassembly reports a result; the caller saves. That is
 * not tidiness -- it is what makes "never alter storage on a rejected sequence" structural
 * rather than a rule someone has to remember at three call sites. There is no NVS symbol here
 * to misuse.
 *
 * Plain C99, no allocation, no blocking, one static buffer. Single-context: the caller owns
 * the struct and must not drive it from two tasks.
 */
#ifndef OD_CONFIG_ASM_H
#define OD_CONFIG_ASM_H

#include <stdbool.h>
#include <stdint.h>

#include "od_span.h"

/* CONFIG_CHUNK_SIZE, CONFIG_CHUNK_SIZE_WITH_PREFIX, MAX_CONFIG_CHUNKS. */
#include "opendisplay_protocol.h"
/* OD_STATIC_ASSERT, including the C99 fallback used by the Silabs build. */
#include "opendisplay_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* THE TRANSFERABLE CEILING IS 4,000 BYTES, NOT 4,096, and that is a live inconsistency rather
 * than a design choice. Where OD_CONFIG_MAX_SIZE is 4096, MAX_CONFIG_CHUNKS is 20 and
 * 20 x 200 = 4000, so the last 96 bytes cannot be transferred. (It does not arise on the 2048
 * profile, whose whole cap is below the transferable ceiling.) The decision (2026-08-05,
 * NEXT_STEPS_2026-08-05.md D4) is to raise the chunk count to 21; the canonical header is
 * frozen, so until it changes this is the honest limit and the tests assert it. Do not paper
 * over it by relaxing the check here -- a device that accepts 21 chunks while the canonical
 * header says 20 is a wire divergence a host cannot discover. */
#define OD_CONFIG_ASM_MAX_TRANSFERABLE ((uint32_t)MAX_CONFIG_CHUNKS * CONFIG_CHUNK_SIZE)

/* THE STORED-CONFIG CAP. This is its only definition, and the `#ifndef` is how a target
 * overrides it: shared/profiles.cmake sets 2048 for the EFR32BG22, where 4096 would cost +2 KB
 * of NVM3 record against a ~10.5 KB heap. Everything else takes the 4096 default.
 *
 * IT BELONGS IN shared/protocol/opendisplay_protocol.h and is not there, because that header is
 * frozen and is a byte-for-byte copy of ../opendisplay-protocol. Flagged rather than quietly
 * duplicated -- a second spelling of this number in a target header is exactly the divergence
 * nothing would detect.
 *
 * The value changes the ABI of struct od_config_asm below and of the stored record that
 * overlays it on BG22, so a host archive compiled with a different cap is a different layout
 * (see tests/host/CMakeLists.txt's separate od_shared_silabs). It is a per-target cap that a
 * host cannot interrogate, which is why od_config_asm_start() REFUSES an over-size declaration
 * rather than truncating it: silent truncation is invisible to the client.
 */
#ifndef OD_CONFIG_MAX_SIZE
#define OD_CONFIG_MAX_SIZE 4096u
#endif

/* Product policy rather than a parser invariant: all supported profiles can carry at least two
 * ordinary CONFIG chunks. The runtime declaration check in od_config_asm_start() is the actual
 * memory-safety boundary for smaller target buffers. */
OD_STATIC_ASSERT(OD_CONFIG_MAX_SIZE >= CONFIG_CHUNK_SIZE * 2u,
                 "project policy requires at least 400-byte config capacity");

enum od_config_asm_result {
    /* Not a chunked transfer: the caller should save `payload` as the whole record. */
    OD_CONFIG_ASM_SINGLE = 0,
    /* Chunk stored; more expected. Caller ACKs and stores nothing. */
    OD_CONFIG_ASM_ACCEPTED,
    /* The declared total has been reached EXACTLY. buffer/total_size hold the record. */
    OD_CONFIG_ASM_COMPLETE,
    /* Malformed. State has been reset. THE CALLER MUST NOT TOUCH STORAGE. */
    OD_CONFIG_ASM_REJECTED
};

struct od_config_asm {
    bool     active;
    uint32_t total_size;      /* declared by the start frame */
    uint32_t received;        /* bytes actually in `buffer` */
    uint32_t chunks;          /* frames accepted, start frame included */
    uint8_t  buffer[OD_CONFIG_MAX_SIZE];
};

/* Abandon any transfer in progress. Idempotent; safe from a teardown path.
 *
 * The buffer is deliberately not zeroed: `active = false` makes it unreachable and clearing
 * OD_CONFIG_MAX_SIZE on every disconnect is pointless work on a battery device. */
void od_config_asm_reset(struct od_config_asm *s);

/* Feed a CMD_CONFIG_WRITE (0x0041) payload -- the bytes AFTER the two opcode bytes.
 *
 * Shape rules, straight from the canonical header, on payload.n:
 *   0                             -> REJECTED
 *   <= CONFIG_CHUNK_SIZE          -> SINGLE   (an ordinary one-frame config)
 *   201                           -> SINGLE   (the header's documented short-first-chunk
 *                                              fallback: too long to be a chunk payload, too
 *                                              short to be a chunked start)
 *   CONFIG_CHUNK_SIZE_WITH_PREFIX (202) -> chunked start
 *   > 202                         -> REJECTED (neither legal shape; the old code silently
 *                                              truncated these)
 *
 * A chunked start additionally requires CONFIG_CHUNK_SIZE < total <= the transferable ceiling,
 * so a nonsensical or oversized declaration is refused HERE rather than failing later for an
 * indirect reason.
 *
 * The length arrived as a uint16_t before the span. Anything above 65535 used to wrap at the
 * call boundary into a value that could look like a legal shape; now it is simply > 202 and
 * REJECTED. No legal frame changes meaning -- every shape above is well under the old limit.
 */
enum od_config_asm_result od_config_asm_start(struct od_config_asm *s, od_span_t payload);

/* Feed a CMD_CONFIG_CHUNK (0x0042) payload -- again, after the opcode bytes.
 *
 * Rejects: no active transfer, an empty or over-long chunk, bytes beyond the declared total, a
 * short chunk that does not complete the total, and exceeding MAX_CONFIG_CHUNKS.
 *
 * COMMITS ON received == total_size, never on a chunk count. That is the F3 fix in one line.
 */
enum od_config_asm_result od_config_asm_chunk(struct od_config_asm *s, od_span_t payload);

#ifdef __cplusplus
}
#endif

#endif /* OD_CONFIG_ASM_H */
