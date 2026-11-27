/* Framing, CRC and bounds for the stored config record. See od_config_store.h. */

#include "od_config_store.h"

#include <string.h>

#include "od_hal_nvs.h"
#include "od_log.h"

/* The header is written and read byte-wise rather than as a struct. The bytes are the same on
 * every target this repo builds -- all little-endian -- but the record is a persistence format
 * with deployed devices behind it, and a format is not something to leave to a struct layout
 * that a padding rule or a compiler flag can move. */
static void put_u32le(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFFu);
    p[1] = (uint8_t)((v >> 8) & 0xFFu);
    p[2] = (uint8_t)((v >> 16) & 0xFFu);
    p[3] = (uint8_t)((v >> 24) & 0xFFu);
}

static uint32_t get_u32le(const uint8_t *p)
{
    return (uint32_t)p[0]
         | ((uint32_t)p[1] << 8)
         | ((uint32_t)p[2] << 16)
         | ((uint32_t)p[3] << 24);
}

uint32_t od_config_store_crc32_update(uint32_t crc_in, const uint8_t *data, uint32_t len)
{
    /* The running value is the FINALISED one, so a caller can stop and resume without
     * tracking whether the inversion has been applied. Streaming consumers need that: the
     * image store CRCs a frame it never holds in one piece. */
    uint32_t crc = ~crc_in;

    for (uint32_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

uint32_t od_config_store_crc32(const uint8_t *data, uint32_t len)
{
    uint32_t crc = 0xFFFFFFFFu;

    for (uint32_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            if (crc & 1u) {
                crc = (crc >> 1) ^ 0xEDB88320u;
            } else {
                crc >>= 1;
            }
        }
    }
    return ~crc;
}

static uint32_t s_generation;
static bool     s_writes_held;
static bool     s_last_save_busy;
static uint8_t  s_last_save_err = OD_ERR_CONFIG_WRITE_FAILED;

uint32_t od_config_store_generation(void)
{
    return s_generation;
}

void od_config_store_hold_writes(bool held)
{
    od_config_store_app_lock();
    s_writes_held = held;
    od_config_store_app_unlock();
}

uint8_t od_config_store_save_error(void)
{
    const bool busy = s_last_save_busy;
    const uint8_t err = s_last_save_err;

    s_last_save_busy = false;
    s_last_save_err = OD_ERR_CONFIG_WRITE_FAILED;
    return busy ? OD_ERR_CONFIG_WRITE_BUSY : err;
}

void od_config_store_set_save_error(uint8_t err)
{
    s_last_save_busy = false;
    s_last_save_err = err;
}

static enum od_config_store_result from_hal(int rc)
{
    switch (rc) {
    case OD_HAL_NVS_OK:     return OD_CONFIG_STORE_OK;
    case OD_HAL_NVS_ENOENT: return OD_CONFIG_STORE_EMPTY;
    case OD_HAL_NVS_E2BIG:  return OD_CONFIG_STORE_TOO_BIG;
    default:                return OD_CONFIG_STORE_IO;
    }
}

enum od_config_store_result od_config_store_init(void)
{
    const enum od_config_store_result rc = from_hal(od_hal_nvs_init());

    if (rc != OD_CONFIG_STORE_OK) {
        od_log_error("Config storage initialization failed");
    }
    return rc;
}

enum od_config_store_result od_config_store_save(void *workspace, uint32_t workspace_cap,
                                                 const uint8_t *payload, uint32_t len)
{
    uint8_t *ws = (uint8_t *)workspace;
    uint8_t *slot;
    uint32_t total;
    uint32_t crc;

    s_last_save_busy = false;
    s_last_save_err = OD_ERR_CONFIG_WRITE_FAILED;
    if (ws == NULL || payload == NULL) {
        od_log_error("Config save rejected: invalid arguments");
        return OD_CONFIG_STORE_IO;
    }
    if (len > OD_CONFIG_MAX_SIZE) {
        od_log_warn("Config save rejected: %u bytes exceed the %u-byte limit",
                    (unsigned)len, (unsigned)OD_CONFIG_MAX_SIZE);
        return OD_CONFIG_STORE_TOO_BIG;
    }
    total = OD_CONFIG_STORE_HEADER_SIZE + len;
    if (workspace_cap < total) {
        od_log_error("Config save rejected: workspace is %u bytes, need %u",
                     (unsigned)workspace_cap, (unsigned)total);
        return OD_CONFIG_STORE_TOO_BIG;
    }
    /* From the hold check to the end of the write under one lock, so a pass cannot take the
     * hold between the check and the medium write. */
    od_config_store_app_lock();
    if (s_writes_held) {
        od_config_store_app_unlock();
        od_log_warn("Config save refused: a display pass is reading the stored config");
        s_last_save_busy = true;
        return OD_CONFIG_STORE_BUSY;
    }

    /* Before the header is written: on a target whose workspace overlays the config assembler,
     * the four words this is about to overwrite are that assembler's live state, and the
     * payload may be its buffer. */
    crc = od_config_store_crc32(payload, len);

    slot = od_config_store_payload(ws);
    if (payload != slot && len > 0u) {
        /* memmove, not memcpy: a caller may legitimately stage the payload somewhere that
         * overlaps the workspace. */
        memmove(slot, payload, len);
    }

    put_u32le(ws + 0,  OD_CONFIG_STORE_MAGIC);
    put_u32le(ws + 4,  OD_CONFIG_STORE_VERSION);
    put_u32le(ws + 8,  crc);
    put_u32le(ws + 12, len);

    {
        enum od_config_store_result rc;

        ++s_generation;
        rc = from_hal(od_hal_nvs_write(ws, total));
        ++s_generation;
        od_config_store_app_unlock();

        if (rc == OD_CONFIG_STORE_OK) {
            od_log_info("Config stored: %u bytes", (unsigned)len);
        } else if (rc == OD_CONFIG_STORE_TOO_BIG) {
            od_log_warn("Config storage rejected a %u-byte record", (unsigned)total);
        } else {
            od_log_error("Config storage write failed");
        }
        return rc;
    }
}

enum od_config_store_result od_config_store_load(uint8_t *payload, uint32_t *len)
{
    uint8_t header[OD_CONFIG_STORE_HEADER_SIZE];
    uint32_t cap;
    uint32_t stored = 0;
    uint32_t data_len;
    int rc;

    if (len == NULL) {
        od_log_error("Config load rejected: invalid length pointer");
        return OD_CONFIG_STORE_IO;
    }
    cap = *len;
    *len = 0;
    if (payload == NULL) {
        od_log_error("Config load rejected: invalid destination");
        return OD_CONFIG_STORE_IO;
    }

    rc = od_hal_nvs_size(&stored);
    if (rc != OD_HAL_NVS_OK) {
        const enum od_config_store_result result = from_hal(rc);

        if (result == OD_CONFIG_STORE_EMPTY) {
            od_log_info("No stored config found");
        } else {
            od_log_error("Config storage size query failed");
        }
        return result;
    }
    if (stored < OD_CONFIG_STORE_HEADER_SIZE) {
        /* Too short to carry a header at all: not a record this firmware wrote. */
        od_log_error("Stored config is corrupt: record is only %u bytes", (unsigned)stored);
        return OD_CONFIG_STORE_CORRUPT;
    }
    if (stored > OD_CONFIG_STORE_MAX_RECORD) {
        /* Longer than any record this build can produce, so refuse before trusting a header
         * inside it. The medium can hold one -- BG22's NVM3 objects go to 2112 bytes against a
         * 2064-byte record cap -- and a device provisioned by a larger-cap build is exactly
         * how one arrives. Bounding `stored` here is what keeps this decision the core's
         * rather than each medium's: two of the three HALs happen to refuse it first, and
         * BG22's does not. */
        od_log_warn("Stored config record is too large: %u bytes", (unsigned)stored);
        return OD_CONFIG_STORE_TOO_BIG;
    }

    rc = od_hal_nvs_read(0, header, OD_CONFIG_STORE_HEADER_SIZE);
    if (rc != OD_HAL_NVS_OK) {
        od_log_error("Config storage header read failed");
        return from_hal(rc);
    }
    if (get_u32le(header + 0) != OD_CONFIG_STORE_MAGIC) {
        od_log_error("Stored config is corrupt: bad magic");
        return OD_CONFIG_STORE_CORRUPT;
    }
    /* header + 4 is `version`, carried and deliberately not checked. */
    data_len = get_u32le(header + 12);

    if (data_len > OD_CONFIG_MAX_SIZE || data_len > cap) {
        od_log_warn("Stored config payload is too large: %u bytes", (unsigned)data_len);
        return OD_CONFIG_STORE_TOO_BIG;
    }
    if (stored - OD_CONFIG_STORE_HEADER_SIZE < data_len) {
        /* The header declares more payload than the medium is holding. */
        od_log_error("Stored config is corrupt: truncated payload");
        return OD_CONFIG_STORE_CORRUPT;
    }

    if (data_len > 0u) {
        rc = od_hal_nvs_read(OD_CONFIG_STORE_HEADER_SIZE, payload, data_len);
        if (rc != OD_HAL_NVS_OK) {
            od_log_error("Config storage payload read failed");
            return from_hal(rc);
        }
    }
    if (od_config_store_crc32(payload, data_len) != get_u32le(header + 8)) {
        od_log_error("Stored config is corrupt: CRC mismatch");
        return OD_CONFIG_STORE_CORRUPT;
    }

    *len = data_len;
    od_log_info("Config loaded from storage: %u bytes", (unsigned)data_len);
    return OD_CONFIG_STORE_OK;
}

enum od_config_store_result od_config_store_clear(void)
{
    enum od_config_store_result rc;

    ++s_generation;
    rc = from_hal(od_hal_nvs_erase());
    ++s_generation;
    if (rc == OD_CONFIG_STORE_OK) {
        od_log_info("Stored config cleared");
    } else {
        od_log_error("Config storage erase failed");
    }
    return rc;
}
