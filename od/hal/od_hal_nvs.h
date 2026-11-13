/* od_hal_nvs -- persistent storage for the one config record, as bytes.
 *
 * The HAL owns the medium and nothing else. Magic, version, length bounds and CRC-32 are
 * shared/core's (od_config_store); this seam sees an opaque byte range and offsets into it.
 * A target implements the five functions below over NVS, Zephyr settings, NVM3 or whatever
 * else it has.
 *
 * READ TAKES AN OFFSET because BG22 reads the 16-byte header, validates it, and only then
 * reads the payload -- nvm3_readPartialData does that with no staging buffer at all, on a
 * part whose whole heap is ~10.5 KB. A whole-record read would force it to find a second
 * 2 KB it does not have. Neither ESP-IDF NVS nor Zephyr settings can read at an offset
 * (settings has no csi_load_one for the NVS backend, and nvs_read starts at byte 0), so
 * those two serve offsets from a record they hold; that is their cost to pay, not the
 * contract's.
 *
 * WRITE TAKES ONE CONTIGUOUS SPAN, not a header pointer plus a payload pointer. BG22's
 * single nvm3_writeData works because a union puts header and payload adjacent, and two
 * unrelated pointers would force exactly the copy this shape exists to avoid. So the caller
 * supplies a contiguous workspace -- record header at offset 0, payload after it -- and the
 * core fills it in place.
 */

#ifndef OD_HAL_NVS_H
#define OD_HAL_NVS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* shared/hal convention: 0 on success, negative on failure. */
#define OD_HAL_NVS_OK        0
#define OD_HAL_NVS_ENOENT   -2   /* no stored record -- an empty device, not an error */
#define OD_HAL_NVS_EIO      -5
#define OD_HAL_NVS_E2BIG    -7   /* the requested span runs past the stored record */

/* One-time init. Safe to call more than once. Every other entry point below may be called
 * without it and must init on demand. */
int od_hal_nvs_init(void);

/* Size of the stored record in bytes.
 *
 * OD_HAL_NVS_ENOENT when nothing is stored, which callers must treat as "unprovisioned
 * device", never as a failure. On any failure *len_out is set to 0. */
int od_hal_nvs_size(uint32_t *len_out);

/* Copy len bytes from `offset` within the stored record into buf.
 *
 * OD_HAL_NVS_E2BIG when offset + len runs past the stored record; nothing is copied, and the
 * caller learns the real size from od_hal_nvs_size(). OD_HAL_NVS_ENOENT when nothing is
 * stored. On any non-OK return the contents of buf are unspecified and must not be read. A
 * zero-length read is still a question about the record and answers ENOENT and E2BIG the same
 * way; it is not a no-op that always succeeds.
 *
 * An implementation may serve this from a cache. The core must not assume one exists. */
int od_hal_nvs_read(uint32_t offset, void *buf, uint32_t len);

/* Replace the stored record with the len bytes at `record`, one contiguous span.
 *
 * On success a subsequent od_hal_nvs_read() returns these bytes.
 *
 * On OD_HAL_NVS_EIO WHATEVER REMAINS READABLE MUST BE A WHOLE RECORD -- the complete previous
 * one, the complete new one, or nothing on a device that had none. Never a partial write: a
 * half-written config is a device that boots on garbage.
 *
 * Which of the three it is, is the medium's business, and an implementation must not assume it
 * is the old record -- ESP-IDF's nvs_set_blob() writes the new entry and only then erases the
 * previous, so its failure code can arrive after the new bytes are already visible. AN
 * IMPLEMENTATION THAT CACHES MUST THEREFORE INVALIDATE ON FAILURE, so that the next read
 * reports the medium rather than a guess. */
int od_hal_nvs_write(const void *record, uint32_t len);

/* Remove the stored record. Succeeds when there was nothing to remove.
 *
 * On OD_HAL_NVS_EIO the record may or may not still be present, and the same rule applies: A
 * CACHE MUST BE INVALIDATED, NEVER CLEARED TO EMPTY. Invalidating re-reads the medium, so a
 * config that survived is still served. Clearing to empty is the failure this rule exists to
 * prevent -- a device reporting itself unconfigured while the medium still holds its config,
 * and coming back configured on the next boot. */
int od_hal_nvs_erase(void);

#ifdef __cplusplus
}
#endif

#endif /* OD_HAL_NVS_H */
