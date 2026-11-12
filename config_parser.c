#include "config_parser.h"
#include "constants.h"
#include "config_storage.h"
#include "encryption.h"
#include "hal/hal.h"
#include <string.h>

#define TRANSMISSION_MODE_CLEAR_ON_BOOT (1 << 7)

static uint16_t crc16_ccitt_feed(uint16_t crc, uint8_t b)
{
    crc ^= (uint16_t)((uint16_t)b << 8);
    for (int j = 0; j < 8; j++) {
        if ((crc & 0x8000U) != 0U) {
            crc = (uint16_t)(((uint32_t)crc << 1) ^ 0x1021U);
        } else {
            crc = (uint16_t)((uint32_t)crc << 1);
        }
    }
    return crc;
}

static uint16_t config_toolbox_outer_crc16(const uint8_t *data, uint32_t body_len)
{
    if (body_len < 2U) {
        uint16_t crc = 0xFFFFU;

        for (uint32_t i = 0; i < body_len; i++) {
            crc = crc16_ccitt_feed(crc, data[i]);
        }
        return crc;
    }
    uint16_t crc = 0xFFFFU;

    crc = crc16_ccitt_feed(crc, 0);
    crc = crc16_ccitt_feed(crc, 0);
    for (uint32_t i = 2U; i < body_len; i++) {
        crc = crc16_ccitt_feed(crc, data[i]);
    }
    return crc;
}

bool parseConfigBytes(uint8_t* configData, uint32_t configLen, struct GlobalConfig* globalConfig) {
    if (globalConfig == NULL || configData == NULL) {
        return false;
    }
    
    memset(globalConfig, 0, sizeof(struct GlobalConfig));
    
    if (configLen < 3) {
        globalConfig->loaded = false;
        return false;
    }
    
    
    uint32_t offset = 0;
    offset += 2;
    
    globalConfig->version = configData[offset++];
    globalConfig->minor_version = 0; // Not stored in current format
    
    while (offset < configLen - 2) { // -2 for CRC
        if (offset > configLen) {
            globalConfig->loaded = false;
            return false;
        }
        
        if (offset + 2 > configLen - 2) {
            break;
        }
        
        uint8_t packetId = configData[offset + 1];
        offset += 2; // Advance past packet header
        
        if (offset > configLen) {
            globalConfig->loaded = false;
            return false;
        }
        
        if (packetId == CONFIG_PKT_SYSTEM || packetId == CONFIG_PKT_MANUFACTURER || 
            packetId == CONFIG_PKT_POWER || packetId == CONFIG_PKT_DISPLAY) {
        }
        
        switch (packetId) {
            case CONFIG_PKT_SYSTEM: // system_config
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + sizeof(struct SystemConfig) <= configLen - 2) {
                    memcpy(&globalConfig->system_config, &configData[offset], sizeof(struct SystemConfig));
                    offset += sizeof(struct SystemConfig);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_MANUFACTURER: // manufacturer_data
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + sizeof(struct ManufacturerData) <= configLen - 2) {
                    memcpy(&globalConfig->manufacturer_data, &configData[offset], sizeof(struct ManufacturerData));
                    offset += sizeof(struct ManufacturerData);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_POWER: // power_option
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + sizeof(struct PowerOption) <= configLen - 2) {
                    memcpy(&globalConfig->power_option, &configData[offset], sizeof(struct PowerOption));
                    offset += sizeof(struct PowerOption);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_DISPLAY: // display
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->display_count < 4 && offset + sizeof(struct DisplayConfig) <= configLen - 2) {
                    memcpy(&globalConfig->displays[globalConfig->display_count], &configData[offset], sizeof(struct DisplayConfig));
                    offset += sizeof(struct DisplayConfig);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->display_count++;
                } else if (globalConfig->display_count >= 4) {
                    offset += sizeof(struct DisplayConfig);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_LED: // led - parse but don't log
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->led_count < 4 && offset + sizeof(struct LedConfig) <= configLen - 2) {
                    memcpy(&globalConfig->leds[globalConfig->led_count], &configData[offset], sizeof(struct LedConfig));
                    offset += sizeof(struct LedConfig);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->led_count++;
                } else if (globalConfig->led_count >= 4) {
                    offset += sizeof(struct LedConfig);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_SENSOR: // sensor_data - parse but don't log
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->sensor_count < 4 && offset + sizeof(struct SensorData) <= configLen - 2) {
                    memcpy(&globalConfig->sensors[globalConfig->sensor_count], &configData[offset], sizeof(struct SensorData));
                    offset += sizeof(struct SensorData);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->sensor_count++;
                } else if (globalConfig->sensor_count >= 4) {
                    offset += sizeof(struct SensorData);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_DATA_BUS: // data_bus - parse but don't log
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->data_bus_count < 4 && offset + sizeof(struct DataBus) <= configLen - 2) {
                    memcpy(&globalConfig->data_buses[globalConfig->data_bus_count], &configData[offset], sizeof(struct DataBus));
                    offset += sizeof(struct DataBus);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->data_bus_count++;
                } else if (globalConfig->data_bus_count >= 4) {
                    offset += sizeof(struct DataBus);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_BINARY_INPUT: // binary_inputs - parse but don't log
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->binary_input_count < 4 && offset + sizeof(struct BinaryInputs) <= configLen - 2) {
                    memcpy(&globalConfig->binary_inputs[globalConfig->binary_input_count], &configData[offset], sizeof(struct BinaryInputs));
                    offset += sizeof(struct BinaryInputs);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->binary_input_count++;
                } else if (globalConfig->binary_input_count >= 4) {
                    offset += sizeof(struct BinaryInputs);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_WIFI: // wifi_config - skip this as requested
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + 162 <= configLen - 2) {
                    offset += 162;
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    offset = configLen - 2; // Skip to CRC
                }
                break;

            case CONFIG_PKT_SECURITY: // security_config (0x27)
                if (offset > configLen) {
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + sizeof(struct SecurityConfig) <= configLen - 2) {
                    if (isEncryptionEnabled() && !isAuthenticated()) {
                        globalConfig->loaded = false;
                        return false;
                    }
                    memcpy(&securityConfig, &configData[offset], sizeof(struct SecurityConfig));
                    offset += sizeof(struct SecurityConfig);
                    if (offset > configLen) {
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    offset = configLen - 2;
                }
                break;
                
            default:
                offset = configLen - 2; // Skip to CRC
                break;
        }
    }
    
    
    if (configLen >= 2) {
        uint16_t crcGiven = configData[configLen - 2] | (configData[configLen - 1] << 8);
        uint16_t crcCalculated = config_toolbox_outer_crc16(configData, configLen - 2);
        if (crcGiven != crcCalculated) {
        }
    }
    
    globalConfig->loaded = true;
    return true;
}

bool loadGlobalConfig(struct GlobalConfig* globalConfig) {
    if (globalConfig == NULL) {
        return false;
    }
    
    memset(globalConfig, 0, sizeof(struct GlobalConfig));
    globalConfig->loaded = false;
    
    static uint8_t configData[MAX_CONFIG_SIZE];
    uint32_t configLen = MAX_CONFIG_SIZE;
    
    if (!initConfigStorage()) {
        return false;
    }
    
    if (!loadConfig(configData, &configLen)) {
        return false;
    }
    
    return parseConfigBytes(configData, configLen, globalConfig);
}
