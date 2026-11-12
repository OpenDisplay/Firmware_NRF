/* od_config_store -- the stored config record: framing, CRC and bounds, once.
 *
 * All three targets already agreed on the record byte-for-byte -- 0xDEADBEEF, version 1, a
 * CRC-32 over the payload, a 16-byte little-endian header -- and each carried its own copy of
 * the code that writes and checks it. This is that code. What is below it, the medium, is
 * shared/hal/od_hal_nvs.h; what is above it, the parse, is od_config.
 *
 * On-medium layout, unchanged and not this module's to change:
 *
 *     offset 0   magic     u32  0xDEADBEEF
 *     offset 4   version   u32  written as 1, CARRIED AND NOT CHECKED (see below)
 *     offset 8   crc       u32  CRC-32 of the payload only
 *     offset 12  data_len  u32  payload length
 *     offset 16  payload   data_len bytes
 *
 * THE WORKSPACE IS THE CALLER'S. od_config_store_save() fills a contiguous span the caller
 * owns -- header at offset 0, payload at offset 16 -- and hands the whole span to the HAL in
 * one write. BG22 points that at a union with its config assembler, which is why it needs no
 * staging buffer on a 32 KB part; the other two point it at the one they already keep. If the
 * payload already sits at offset 16 it is not copied over itself.
 *
 * VERSION IS RESERVED, NOT ENFORCED. Every target writes 1 and none has ever read it back.
 * Checking it here would be a new rejection wearing a refactor's clothes: a device holding a
 * record this firmware did not write would stop booting on its stored config. If the field is
 * ever to mean something, that is a deliberate change with a compatibility story and a
 * DIVERGENCE_MATRIX row.
 */

#ifndef OD_CONFIG_STORE_H
#define OD_CONFIG_STORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "opendisplay_protocol.h"

#include "od_config_asm.h"   /* OD_CONFIG_MAX_SIZE, OD_STATIC_ASSERT, struct od_config_asm */

#ifdef __cplusplus
extern "C" {
#endif

#define OD_CONFIG_STORE_MAGIC       0xDEADBEEFu
#define OD_CONFIG_STORE_VERSION     1u
#define OD_CONFIG_STORE_HEADER_SIZE 16u

/* The largest span a workspace has to hold on this target. */
#define OD_CONFIG_STORE_MAX_RECORD  (OD_CONFIG_STORE_HEADER_SIZE + OD_CONFIG_MAX_SIZE)

/* BG22 overlays the record on struct od_config_asm, and the overlay is only sound because both
 * put their byte array at the same offset. Asserted here, where both are visible, so the
 * arrangement cannot be broken by an edit to a struct in another file. */
OD_STATIC_ASSERT(offsetof(struct od_config_asm, buffer) == OD_CONFIG_STORE_HEADER_SIZE,
                 "config assembler buffer must sit at the record's payload offset");

enum od_config_store_result {
    OD_CONFIG_STORE_OK = 0,
    /* Nothing stored. An unprovisioned device, not a failure -- boot on defaults. */
    OD_CONFIG_STORE_EMPTY,
    /* Magic, declared length or CRC rejected the record. Boot on defaults, not on garbage. */
    OD_CONFIG_STORE_CORRUPT,
    /* Refused: larger than this build's cap or than the caller's buffer. Nothing was stored
     * and nothing was copied out. A cap a host cannot query is refused loudly, never
     * truncated (docs/MEMORY_CONSTRAINTS.md item 3). */
    OD_CONFIG_STORE_TOO_BIG,
    /* The medium failed. */
    OD_CONFIG_STORE_IO,
    /* Refused, nothing written: a display pass is paused on the stored bytes
     * (od_config_store_hold_writes). The write NACKs like any other refused write. */
    OD_CONFIG_STORE_BUSY
};

/* Where the payload lives inside a caller's workspace. */
static inline uint8_t *od_config_store_payload(void *workspace)
{
    return (uint8_t *)workspace + OD_CONFIG_STORE_HEADER_SIZE;
}

/* Bring the medium up. Safe to call more than once; every call below does it on demand. */
enum od_config_store_result od_config_store_init(void);

/* Frame `len` payload bytes into `workspace` and store the whole record.
 *
 * `payload` may point at od_config_store_payload(workspace), in which case the bytes are
 * already in place and are not copied. `workspace_cap` is the span's size and must hold
 * OD_CONFIG_STORE_HEADER_SIZE + len. */
enum od_config_store_result od_config_store_save(void *workspace, uint32_t workspace_cap,
                                                 const uint8_t *payload, uint32_t len);

/* Read the stored payload into `payload`. `*len` carries the caller's capacity in and the
 * stored length out; it is set to 0 on every non-OK return. */
enum od_config_store_result od_config_store_load(uint8_t *payload, uint32_t *len);

/* Remove the stored record. Succeeds when there was nothing to remove. Never held: the erase
 * ahead of an unauthenticated rewrite is a security step, so a pass reading through it fails on
 * the generation check instead. */
enum od_config_store_result od_config_store_clear(void);

/* Bumped by every save attempt that reaches the medium (before and after the write, so a reader
 * that sampled it mid-write still sees a change) and by every clear. A reader that streams
 * stored bytes across a pause compares it with the value it started from: equal means the bytes
 * under its offsets are the ones it validated. */
uint32_t od_config_store_generation(void);

/* A target whose display pass and config writes run on different threads (Nordic: the boot
 * render runs on a work queue) sets OD_CONFIG_STORE_LOCKING=1 and implements the two hooks with
 * its own mutex. The hold flag and a save's check-then-write are taken under it, so a write
 * either completes before a pass takes the hold or sees the hold. Without it they are no-ops. */
#ifndef OD_CONFIG_STORE_LOCKING
#define OD_CONFIG_STORE_LOCKING 0
#endif
#if OD_CONFIG_STORE_LOCKING
void od_config_store_app_lock(void);
void od_config_store_app_unlock(void);
#else
#define od_config_store_app_lock()   ((void)0)
#define od_config_store_app_unlock() ((void)0)
#endif

/* While held, od_config_store_save() refuses with OD_CONFIG_STORE_BUSY before touching the
 * workspace (BG22's workspace is the live config assembler). Held by the display binding for
 * exactly the span of a pass, which streams its sequence from the medium and pauses at the image
 * marker while the frame arrives. */
void od_config_store_hold_writes(bool held);

/* The config-write NACK data byte ([FF][41|42][err][00]) for the most recent failed save, read
 * once (the call clears it):
 * OD_ERR_CONFIG_WRITE_BUSY when the hold refused it (transient: retry once the refresh is
 * done), else OD_ERR_CONFIG_WRITE_FAILED. */
uint8_t od_config_store_save_error(void);

/* Set the byte od_config_store_save_error() reports next: a refusal decided before the store was
 * reached (the SEC2 config policy's 0x10 / 0x11, od_cfg_policy.h). */
void od_config_store_set_save_error(uint8_t err);

/* CRC-32 (reflected, polynomial 0xEDB88320) over the payload. Bit-serial deliberately: a table
 * costs 1 KB of flash on a part with 480 B of RAM headroom, and this runs once per config
 * write. Exposed because it is the record's checksum, not an implementation detail -- host
 * tests and tooling build records with it. */
uint32_t od_config_store_crc32(const uint8_t *data, uint32_t len);

/* The same CRC-32, resumable. Seed with 0 and feed consecutive spans; the value returned is
 * final at every step. Here rather than in the caller because this file is the one home for
 * the polynomial -- a second copy is what tools/check.sh's ratchet exists to catch. */
uint32_t od_config_store_crc32_update(uint32_t crc, const uint8_t *data, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* OD_CONFIG_STORE_H */
