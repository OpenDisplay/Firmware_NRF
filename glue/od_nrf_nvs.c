/* od_nrf_nvs.c -- od_hal_nvs (od/hal/od_hal_nvs.h) on the nRF5 SDK Flash Data Storage.
 *
 * ONE RECORD. The config lives in a single FDS record (file 0x1111, key 0x2222), the same file
 * and key the 2.x firmware used, and od_config_store writes the same 16-byte header the 2.x
 * firmware wrote (magic 0xDEADBEEF, version 1, crc32, data_len). A device updated from 2.x
 * therefore boots with its stored config intact.
 *
 * READS ARE MEMORY-MAPPED. FDS records are plain flash, so od_hal_nvs_read() is a memcpy from
 * the record's data pointer. Nothing is cached in RAM; od_cfg_index reads drive packets in place.
 *
 * DUPLICATES. fds_record_update() writes the new record and then deletes the old one. A power cut
 * between the two leaves both valid. The newest (highest record_id) is the live one; init deletes
 * the others, so the reader never sees two.
 *
 * WRITES BLOCK. The 2.x firmware already waited for the FDS completion event by pumping the
 * SoftDevice event queue, and this keeps that behaviour (od_config_store expects a synchronous
 * write). An out-of-space update runs one garbage collection and retries once. */
#include "od_hal_nvs.h"

#include <string.h>

#include "fds.h"
#include "od_nrf_glue.h"

#define NVS_FILE_ID 0x1111u
#define NVS_REC_KEY 0x2222u
#define NVS_WAIT_MS 3000u

static bool s_init;
static volatile bool s_pending;
static volatile ret_code_t s_result;
static volatile fds_evt_id_t s_wait_for;

static void fds_evt(fds_evt_t const *e)
{
    if (e->id == FDS_EVT_INIT) {
        s_result = e->result;
        if (s_wait_for == FDS_EVT_INIT) {
            s_pending = false;
        }
        return;
    }
    if (s_pending && e->id == s_wait_for) {
        s_result = e->result;
        s_pending = false;
    }
}

static int wait_evt(void)
{
    uint32_t waited = 0u;

    while (s_pending && waited < NVS_WAIT_MS) {
        od_nrf_pump_events();
        od_nrf_delay_ms(1u);
        waited++;
    }
    if (s_pending) {
        s_pending = false;
        return OD_HAL_NVS_EIO;
    }
    return s_result == NRF_SUCCESS ? OD_HAL_NVS_OK : OD_HAL_NVS_EIO;
}

static int run(fds_evt_id_t id, ret_code_t rc)
{
    if (rc != NRF_SUCCESS) {
        s_pending = false;
        return rc == FDS_ERR_NO_SPACE_IN_FLASH ? OD_HAL_NVS_E2BIG : OD_HAL_NVS_EIO;
    }
    (void)id;
    return wait_evt();
}

static void arm(fds_evt_id_t id)
{
    s_wait_for = id;
    s_result = NRF_ERROR_TIMEOUT;
    s_pending = true;
}

/* The live record: the newest one. Older duplicates are deleted when `prune`. */
static bool find_live(fds_record_desc_t *out, bool prune)
{
    fds_find_token_t tok;
    fds_record_desc_t d;
    bool found = false;

    memset(&tok, 0, sizeof tok);
    while (fds_record_find(NVS_FILE_ID, NVS_REC_KEY, &d, &tok) == NRF_SUCCESS) {
        if (!found || d.record_id > out->record_id) {
            if (found && prune) {
                arm(FDS_EVT_DEL_RECORD);
                (void)run(FDS_EVT_DEL_RECORD, fds_record_delete(out));
            }
            *out = d;
            found = true;
        } else if (prune) {
            arm(FDS_EVT_DEL_RECORD);
            (void)run(FDS_EVT_DEL_RECORD, fds_record_delete(&d));
        }
    }
    return found;
}

static bool open_live(fds_record_desc_t *d, fds_flash_record_t *fr)
{
    if (!s_init || !find_live(d, false)) {
        return false;
    }
    return fds_record_open(d, fr) == NRF_SUCCESS;
}

int od_hal_nvs_init(void)
{
    fds_record_desc_t d;

    if (s_init) {
        return OD_HAL_NVS_OK;
    }
    if (fds_register(fds_evt) != NRF_SUCCESS) {
        return OD_HAL_NVS_EIO;
    }
    arm(FDS_EVT_INIT);
    if (run(FDS_EVT_INIT, fds_init()) != OD_HAL_NVS_OK) {
        return OD_HAL_NVS_EIO;
    }
    s_init = true;
    (void)find_live(&d, true);
    return OD_HAL_NVS_OK;
}

int od_hal_nvs_size(uint32_t *len_out)
{
    fds_record_desc_t d;
    fds_flash_record_t fr;

    if (len_out == NULL) {
        return OD_HAL_NVS_EIO;
    }
    if (!open_live(&d, &fr)) {
        return OD_HAL_NVS_ENOENT;
    }
    *len_out = (uint32_t)fr.p_header->length_words * 4u;
    (void)fds_record_close(&d);
    return OD_HAL_NVS_OK;
}

int od_hal_nvs_read(uint32_t offset, void *buf, uint32_t len)
{
    fds_record_desc_t d;
    fds_flash_record_t fr;
    uint32_t size;

    if (buf == NULL && len != 0u) {
        return OD_HAL_NVS_EIO;
    }
    if (!open_live(&d, &fr)) {
        return OD_HAL_NVS_ENOENT;
    }
    size = (uint32_t)fr.p_header->length_words * 4u;
    if (offset > size || len > size - offset) {
        (void)fds_record_close(&d);
        return OD_HAL_NVS_E2BIG;
    }
    memcpy(buf, (const uint8_t *)fr.p_data + offset, len);
    (void)fds_record_close(&d);
    return OD_HAL_NVS_OK;
}

static int write_once(const void *record, uint32_t len)
{
    fds_record_t r;
    fds_record_desc_t d;
    const bool have = find_live(&d, false);

    r.file_id = NVS_FILE_ID;
    r.key = NVS_REC_KEY;
    r.data.p_data = record;
    r.data.length_words = (len + 3u) / 4u;
    if (have) {
        arm(FDS_EVT_UPDATE);
        return run(FDS_EVT_UPDATE, fds_record_update(&d, &r));
    }
    arm(FDS_EVT_WRITE);
    return run(FDS_EVT_WRITE, fds_record_write(&d, &r));
}

int od_hal_nvs_write(const void *record, uint32_t len)
{
    int rc;

    /* FDS reads whole words, so the caller's buffer must be word-aligned and a multiple of 4
     * long or the tail bytes come from past its end. The config workspace is both. */
    if (!s_init || record == NULL || len == 0u || ((uintptr_t)record & 3u) != 0u) {
        return OD_HAL_NVS_EIO;
    }
    rc = write_once(record, len);
    if (rc == OD_HAL_NVS_E2BIG) {
        arm(FDS_EVT_GC);
        if (run(FDS_EVT_GC, fds_gc()) != OD_HAL_NVS_OK) {
            return OD_HAL_NVS_EIO;
        }
        rc = write_once(record, len);
    }
    return rc;
}

int od_hal_nvs_erase(void)
{
    fds_record_desc_t d;

    if (!s_init) {
        return OD_HAL_NVS_EIO;
    }
    while (find_live(&d, false)) {
        arm(FDS_EVT_DEL_RECORD);
        if (run(FDS_EVT_DEL_RECORD, fds_record_delete(&d)) != OD_HAL_NVS_OK) {
            return OD_HAL_NVS_EIO;
        }
    }
    arm(FDS_EVT_GC);
    (void)run(FDS_EVT_GC, fds_gc());
    return OD_HAL_NVS_OK;
}
