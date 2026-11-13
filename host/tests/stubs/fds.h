/* Host test: the subset of the nRF5 SDK fds.h that glue/od_nrf_nvs.c uses, backed by the flash
 * simulator in host/tests/fds_sim.c. Types and field names follow SDK 17.1.0. */
#ifndef HOST_FDS_H
#define HOST_FDS_H
#include <stdbool.h>
#include <stdint.h>
#include "sdk_errors.h"

#define FDS_ERR_NO_SPACE_IN_FLASH 0x860Bu

typedef struct {
    uint16_t record_key;
    uint16_t length_words;
    uint16_t file_id;
    uint16_t crc16;
    uint32_t record_id;
} fds_header_t;

typedef struct {
    uint32_t record_id;
    uint32_t const *p_record;
    uint16_t gc_run_count;
    bool record_is_open;
} fds_record_desc_t;

typedef struct {
    fds_header_t const *p_header;
    void const *p_data;
} fds_flash_record_t;

typedef struct {
    uint16_t file_id;
    uint16_t key;
    struct {
        void const *p_data;
        uint32_t length_words;
    } data;
} fds_record_t;

typedef struct {
    uint32_t const *p_addr;
    uint16_t page;
} fds_find_token_t;

typedef enum {
    FDS_EVT_INIT, FDS_EVT_WRITE, FDS_EVT_UPDATE, FDS_EVT_DEL_RECORD, FDS_EVT_DEL_FILE, FDS_EVT_GC
} fds_evt_id_t;

typedef struct {
    fds_evt_id_t id;
    ret_code_t result;
} fds_evt_t;

typedef void (*fds_cb_t)(fds_evt_t const *p_evt);

ret_code_t fds_register(fds_cb_t cb);
ret_code_t fds_init(void);
ret_code_t fds_record_write(fds_record_desc_t *p_desc, fds_record_t const *p_record);
ret_code_t fds_record_update(fds_record_desc_t *p_desc, fds_record_t const *p_record);
ret_code_t fds_record_delete(fds_record_desc_t *p_desc);
ret_code_t fds_record_find(uint16_t file_id, uint16_t record_key, fds_record_desc_t *p_desc,
                           fds_find_token_t *p_token);
ret_code_t fds_record_open(fds_record_desc_t *p_desc, fds_flash_record_t *p_flash_record);
ret_code_t fds_record_close(fds_record_desc_t *p_desc);
ret_code_t fds_gc(void);
#endif
