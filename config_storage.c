#include "config_storage.h"

#include <string.h>

#include "app_scheduler.h"
#include "constants.h"
#include "fds.h"
#include "nordic_common.h"
#include "nrf_delay.h"
#include "nrf_log.h"
#if defined(S112)
#include "nrf_sdh.h"
#else
#include "nrf_soc.h"
#endif

#define CONFIG_FILE_ID 0x1111  // Different from EPD_config to avoid conflicts
#define CONFIG_REC_KEY 0x2222

static bool fds_initialized = false;
static volatile bool fds_write_pending = false;
static volatile bool fds_write_success = false;

static void fds_evt_handler(fds_evt_t const* const p_fds_evt) {
    if (p_fds_evt->result != NRF_SUCCESS) {
        NRF_LOG_ERROR("FDS event %d failed: %d\n", p_fds_evt->id, p_fds_evt->result);
    }
    if (p_fds_evt->id == FDS_EVT_WRITE || p_fds_evt->id == FDS_EVT_UPDATE) {
        if (p_fds_evt->write.file_id == CONFIG_FILE_ID && 
            p_fds_evt->write.record_key == CONFIG_REC_KEY) {
            fds_write_pending = false;
            fds_write_success = (p_fds_evt->result == NRF_SUCCESS);
            NRF_LOG_DEBUG("FDS write completed: %s\n", fds_write_success ? "success" : "failed");
        }
    }
}

bool initConfigStorage(void) {
    ret_code_t ret;
    
    if (fds_initialized) {
        return true;
    }
    
    ret = fds_register(fds_evt_handler);
    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("fds_register failed: %d\n", ret);
        return false;
    }
    
    ret = fds_init();
    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("fds_init failed: %d\n", ret);
        return false;
    }
    
    fds_initialized = true;
    
    ret = fds_gc();
    if (ret != NRF_SUCCESS && ret != FDS_ERR_NO_SPACE_IN_FLASH) {
        NRF_LOG_DEBUG("fds_gc returned: %d\n", ret);
    }
    
    return true;
}

bool saveConfig(uint8_t* configData, uint32_t len) {
    if (len > MAX_CONFIG_SIZE) {
        NRF_LOG_ERROR("Config data too large: %d bytes\n", len);
        return false;
    }
    
    if (!fds_initialized) {
        NRF_LOG_ERROR("FDS not initialized\n");
        return false;
    }
    
    config_storage_t config;
    config.magic = 0xDEADBEEF;
    config.version = 1;
    config.data_len = len;
    config.crc = calculateConfigCRC(configData, len);
    memcpy(config.data, configData, len);
    
    size_t headerSize = sizeof(config_storage_t) - MAX_CONFIG_SIZE;
    size_t totalSize = headerSize + len;
    
    fds_record_t record;
    fds_record_desc_t record_desc;
    fds_find_token_t ftok;
    
    record.file_id = CONFIG_FILE_ID;
    record.key = CONFIG_REC_KEY;
    
#ifdef S112
    record.data.p_data = (void*)&config;
    record.data.length_words = BYTES_TO_WORDS(totalSize);
#else
    fds_record_chunk_t record_chunk;
    record_chunk.p_data = &config;
    record_chunk.length_words = BYTES_TO_WORDS(totalSize);
    record.data.p_chunks = &record_chunk;
    record.data.num_chunks = 1;
#endif
    
    memset(&ftok, 0x00, sizeof(fds_find_token_t));
    ret_code_t ret = fds_record_find(CONFIG_FILE_ID, CONFIG_REC_KEY, &record_desc, &ftok);
    
    fds_write_pending = true;
    fds_write_success = false;
    
    if (ret == NRF_SUCCESS) {
        ret = fds_record_update(&record_desc, &record);
        if (ret != NRF_SUCCESS) {
            NRF_LOG_ERROR("fds_record_update failed: %d\n", ret);
            fds_write_pending = false;
            if (ret == FDS_ERR_NO_SPACE_IN_FLASH) {
                fds_gc();
            }
            return false;
        }
    } else {
        ret = fds_record_write(&record_desc, &record);
        if (ret != NRF_SUCCESS) {
            NRF_LOG_ERROR("fds_record_write failed: %d\n", ret);
            fds_write_pending = false;
            if (ret == FDS_ERR_NO_SPACE_IN_FLASH) {
                fds_gc();
            }
            return false;
        }
    }
    
    uint32_t timeout = FDS_WRITE_TIMEOUT_MS;
    while (fds_write_pending && timeout > 0) {
        #if defined(S112)
        nrf_sdh_evts_poll();
        #else
        sd_app_evt_wait();
        #endif
        nrf_delay_ms(FDS_POLL_INTERVAL_MS);
        timeout -= FDS_POLL_INTERVAL_MS;
    }
    
    if (fds_write_pending) {
        NRF_LOG_ERROR("FDS write timeout\n");
        fds_write_pending = false;
        return false;
    }
    
    if (!fds_write_success) {
        NRF_LOG_ERROR("FDS write failed\n");
        return false;
    }
    
    NRF_LOG_DEBUG("Config saved: %d bytes\n", totalSize);
    return true;
}

bool loadConfig(uint8_t* configData, uint32_t* len) {
    if (!fds_initialized) {
        return false;
    }
    
    fds_flash_record_t flash_record;
    fds_record_desc_t record_desc;
    fds_find_token_t ftok;
    
    memset(&ftok, 0x00, sizeof(fds_find_token_t));
    
    ret_code_t ret = fds_record_find(CONFIG_FILE_ID, CONFIG_REC_KEY, &record_desc, &ftok);
    if (ret != NRF_SUCCESS) {
        NRF_LOG_DEBUG("Config record not found\n");
        return false;
    }
    
    ret = fds_record_open(&record_desc, &flash_record);
    if (ret != NRF_SUCCESS) {
        NRF_LOG_ERROR("fds_record_open failed: %d\n", ret);
        return false;
    }
    
#ifdef S112
    uint32_t record_len = flash_record.p_header->length_words * sizeof(uint32_t);
#else
    uint32_t record_len = flash_record.p_header->tl.length_words * sizeof(uint32_t);
#endif
    
    config_storage_t config;
    size_t headerSize = sizeof(config_storage_t) - MAX_CONFIG_SIZE;
    
    if (record_len < headerSize) {
        NRF_LOG_ERROR("Config record too short: %d bytes\n", record_len);
        fds_record_close(&record_desc);
        return false;
    }
    
    memcpy(&config, flash_record.p_data, MIN(sizeof(config_storage_t), record_len));
    
    if (config.magic != 0xDEADBEEF) {
        NRF_LOG_ERROR("Invalid config magic: 0x%08X\n", config.magic);
        fds_record_close(&record_desc);
        return false;
    }
    
    if (config.data_len > MAX_CONFIG_SIZE) {
        NRF_LOG_ERROR("Config data too large: %d bytes\n", config.data_len);
        fds_record_close(&record_desc);
        return false;
    }
    
    if (config.data_len > *len) {
        NRF_LOG_ERROR("Config data larger than buffer: %d > %d\n", config.data_len, *len);
        fds_record_close(&record_desc);
        return false;
    }
    
    uint32_t calculatedCRC = calculateConfigCRC(config.data, config.data_len);
    if (config.crc != calculatedCRC) {
        NRF_LOG_ERROR("Config CRC mismatch: 0x%08X != 0x%08X\n", config.crc, calculatedCRC);
        fds_record_close(&record_desc);
        return false;
    }
    
    memcpy(configData, config.data, config.data_len);
    *len = config.data_len;
    
    fds_record_close(&record_desc);
    
    NRF_LOG_DEBUG("Config loaded: %d bytes\n", config.data_len);
    return true;
}

uint32_t calculateConfigCRC(uint8_t* data, uint32_t len) {
    uint32_t crc = 0xFFFFFFFF;
    
    for (uint32_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >> 1) ^ 0xEDB88320;
            } else {
                crc = crc >> 1;
            }
        }
    }
    
    return ~crc;
}
