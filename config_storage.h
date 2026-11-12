#ifndef __CONFIG_STORAGE_H
#define __CONFIG_STORAGE_H

#include <stdint.h>
#include <stdbool.h>

#define MAX_CONFIG_SIZE 512

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t crc; 
    uint32_t data_len;
    uint8_t data[MAX_CONFIG_SIZE];
} config_storage_t;

bool initConfigStorage(void);

bool saveConfig(uint8_t* configData, uint32_t len);

bool loadConfig(uint8_t* configData, uint32_t* len);

uint32_t calculateConfigCRC(uint8_t* data, uint32_t len);

#endif // __CONFIG_STORAGE_H
