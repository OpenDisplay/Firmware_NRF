#include "config_parser.h"
#include "constants.h"
#include "config_storage.h"
#include "encryption.h"
#include "nrf_log.h"
#include "nrf_delay.h"
#include <string.h>

#define TRANSMISSION_MODE_CLEAR_ON_BOOT (1 << 7)

bool parseConfigBytes(uint8_t* configData, uint32_t configLen, struct GlobalConfig* globalConfig) {
    if (globalConfig == NULL || configData == NULL) {
        NRF_LOG_ERROR("Invalid parameters for parseConfigBytes\n");
        return false;
    }
    
    memset(globalConfig, 0, sizeof(struct GlobalConfig));
    
    if (configLen < 3) {
        NRF_LOG_ERROR("Config too short: %d bytes\n", configLen);
        globalConfig->loaded = false;
        return false;
    }
    
    NRF_LOG_INFO("Parsing config: %d bytes", configLen);
    
    uint32_t offset = 0;
    offset += 2;
    
    globalConfig->version = configData[offset++];
    globalConfig->minor_version = 0; // Not stored in current format
    
    uint32_t packetIndex = 0;
    while (offset < configLen - 2) { // -2 for CRC
        if (offset > configLen) {
            NRF_LOG_ERROR("Offset overflow: offset=%d > configLen=%d", offset, configLen);
            globalConfig->loaded = false;
            return false;
        }
        
        uint32_t remaining = configLen - 2 - offset;
        if (offset + 2 > configLen - 2) {
            NRF_LOG_DEBUG("Loop exit: not enough for header (need 2, have %d)", remaining);
            break;
        }
        
        uint8_t packetNum = configData[offset];
        uint8_t packetId = configData[offset + 1];
        offset += 2; // Advance past packet header
        
        if (offset > configLen) {
            NRF_LOG_ERROR("Offset overflow after header: offset=%d > configLen=%d", offset, configLen);
            globalConfig->loaded = false;
            return false;
        }
        
        packetIndex++; // Count this packet (before processing, so we count even if we skip it)
        if (packetId == CONFIG_PKT_SYSTEM || packetId == CONFIG_PKT_MANUFACTURER || 
            packetId == CONFIG_PKT_POWER || packetId == CONFIG_PKT_DISPLAY) {
            NRF_LOG_INFO("Pkt #%d ID=0x%02X", packetNum, packetId);
        }
        
        switch (packetId) {
            case CONFIG_PKT_SYSTEM: // system_config
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before system_config");
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + sizeof(struct SystemConfig) <= configLen - 2) {
                    memcpy(&globalConfig->system_config, &configData[offset], sizeof(struct SystemConfig));
                    offset += sizeof(struct SystemConfig);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after system_config");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    NRF_LOG_ERROR("system_config: need %d, have %d", sizeof(struct SystemConfig), configLen - 2 - offset);
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_MANUFACTURER: // manufacturer_data
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before manufacturer_data");
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + sizeof(struct ManufacturerData) <= configLen - 2) {
                    memcpy(&globalConfig->manufacturer_data, &configData[offset], sizeof(struct ManufacturerData));
                    offset += sizeof(struct ManufacturerData);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after manufacturer_data");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    NRF_LOG_ERROR("manufacturer_data: need %d, have %d", sizeof(struct ManufacturerData), configLen - 2 - offset);
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_POWER: // power_option
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before power_option");
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + sizeof(struct PowerOption) <= configLen - 2) {
                    memcpy(&globalConfig->power_option, &configData[offset], sizeof(struct PowerOption));
                    offset += sizeof(struct PowerOption);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after power_option");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    NRF_LOG_ERROR("power_option: need %d, have %d", sizeof(struct PowerOption), configLen - 2 - offset);
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_DISPLAY: // display
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before display");
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->display_count < 4 && offset + sizeof(struct DisplayConfig) <= configLen - 2) {
                    memcpy(&globalConfig->displays[globalConfig->display_count], &configData[offset], sizeof(struct DisplayConfig));
                    NRF_LOG_INFO("Display: ic=0x%04X %dx%d", 
                                 globalConfig->displays[globalConfig->display_count].panel_ic_type,
                                 globalConfig->displays[globalConfig->display_count].pixel_width,
                                 globalConfig->displays[globalConfig->display_count].pixel_height);
                    NRF_LOG_INFO("Display: RST=%d BUSY=%d DC=%d", 
                                 globalConfig->displays[globalConfig->display_count].reset_pin,
                                 globalConfig->displays[globalConfig->display_count].busy_pin,
                                 globalConfig->displays[globalConfig->display_count].dc_pin);
                    NRF_LOG_INFO("Display: CS=%d DATA=%d CLK=%d", 
                                 globalConfig->displays[globalConfig->display_count].cs_pin,
                                 globalConfig->displays[globalConfig->display_count].data_pin,
                                 globalConfig->displays[globalConfig->display_count].clk_pin);
                    NRF_LOG_INFO("Display: color=%d modes=0x%02X", 
                                 globalConfig->displays[globalConfig->display_count].color_scheme,
                                 globalConfig->displays[globalConfig->display_count].transmission_modes);
                    offset += sizeof(struct DisplayConfig);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after display");
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->display_count++;
                } else if (globalConfig->display_count >= 4) {
                    offset += sizeof(struct DisplayConfig);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after display (skipped)");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    NRF_LOG_ERROR("display: need %d, have %d", sizeof(struct DisplayConfig), configLen - 2 - offset);
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_LED: // led - parse but don't log
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before led");
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->led_count < 4 && offset + sizeof(struct LedConfig) <= configLen - 2) {
                    memcpy(&globalConfig->leds[globalConfig->led_count], &configData[offset], sizeof(struct LedConfig));
                    offset += sizeof(struct LedConfig);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after led");
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->led_count++;
                } else if (globalConfig->led_count >= 4) {
                    offset += sizeof(struct LedConfig);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after led (skipped)");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    NRF_LOG_ERROR("led: need %d, have %d", sizeof(struct LedConfig), configLen - 2 - offset);
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_SENSOR: // sensor_data - parse but don't log
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before sensor");
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->sensor_count < 4 && offset + sizeof(struct SensorData) <= configLen - 2) {
                    memcpy(&globalConfig->sensors[globalConfig->sensor_count], &configData[offset], sizeof(struct SensorData));
                    offset += sizeof(struct SensorData);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after sensor");
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->sensor_count++;
                } else if (globalConfig->sensor_count >= 4) {
                    offset += sizeof(struct SensorData);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after sensor (skipped)");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    NRF_LOG_ERROR("sensor: need %d, have %d", sizeof(struct SensorData), configLen - 2 - offset);
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_DATA_BUS: // data_bus - parse but don't log
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before data_bus");
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->data_bus_count < 4 && offset + sizeof(struct DataBus) <= configLen - 2) {
                    memcpy(&globalConfig->data_buses[globalConfig->data_bus_count], &configData[offset], sizeof(struct DataBus));
                    offset += sizeof(struct DataBus);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after data_bus");
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->data_bus_count++;
                } else if (globalConfig->data_bus_count >= 4) {
                    offset += sizeof(struct DataBus);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after data_bus (skipped)");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    NRF_LOG_ERROR("data_bus: need %d, have %d", sizeof(struct DataBus), configLen - 2 - offset);
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_BINARY_INPUT: // binary_inputs - parse but don't log
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before binary_input");
                    globalConfig->loaded = false;
                    return false;
                }
                if (globalConfig->binary_input_count < 4 && offset + sizeof(struct BinaryInputs) <= configLen - 2) {
                    memcpy(&globalConfig->binary_inputs[globalConfig->binary_input_count], &configData[offset], sizeof(struct BinaryInputs));
                    offset += sizeof(struct BinaryInputs);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after binary_input");
                        globalConfig->loaded = false;
                        return false;
                    }
                    globalConfig->binary_input_count++;
                } else if (globalConfig->binary_input_count >= 4) {
                    offset += sizeof(struct BinaryInputs);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after binary_input (skipped)");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    NRF_LOG_ERROR("binary_input: need %d, have %d", sizeof(struct BinaryInputs), configLen - 2 - offset);
                    globalConfig->loaded = false;
                    return false;
                }
                break;
                
            case CONFIG_PKT_WIFI: // wifi_config - skip this as requested
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before wifi");
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + 162 <= configLen - 2) {
                    offset += 162;
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after wifi");
                        globalConfig->loaded = false;
                        return false;
                    }
                } else {
                    offset = configLen - 2; // Skip to CRC
                }
                break;

            case CONFIG_PKT_SECURITY: // security_config (0x27)
                if (offset > configLen) {
                    NRF_LOG_ERROR("Offset overflow before security_config");
                    globalConfig->loaded = false;
                    return false;
                }
                if (offset + sizeof(struct SecurityConfig) <= configLen - 2) {
                    if (isEncryptionEnabled() && !isAuthenticated()) {
                        NRF_LOG_ERROR("Security config write rejected: encryption enabled but not authenticated (security config always requires authentication)");
                        globalConfig->loaded = false;
                        return false;
                    }
                    memcpy(&securityConfig, &configData[offset], sizeof(struct SecurityConfig));
                    offset += sizeof(struct SecurityConfig);
                    if (offset > configLen) {
                        NRF_LOG_ERROR("Offset overflow after security_config");
                        globalConfig->loaded = false;
                        return false;
                    }
                    NRF_LOG_INFO("Security: enabled=%d, flags=0x%02X, reset_pin=%d",
                                 securityConfig.encryption_enabled,
                                 securityConfig.flags,
                                 securityConfig.reset_pin);
                } else {
                    NRF_LOG_ERROR("security_config: need %d, have %d",
                                  sizeof(struct SecurityConfig), configLen - 2 - offset);
                    offset = configLen - 2;
                }
                break;
                
            default:
                NRF_LOG_WARNING("Unknown pkt 0x%02X @%d", packetId, offset - 2);
                offset = configLen - 2; // Skip to CRC
                break;
        }
    }
    
    NRF_LOG_INFO("Parsed %d pkts, offset=%d/%d", packetIndex, offset, configLen - 2);
    
    if (configLen >= 2) {
        uint16_t crcGiven = configData[configLen - 2] | (configData[configLen - 1] << 8);
        uint32_t crcCalculated32 = calculateConfigCRC(configData, configLen - 2);
        uint16_t crcCalculated = (uint16_t)(crcCalculated32 & 0xFFFF);
        if (crcGiven != crcCalculated) {
            NRF_LOG_WARNING("CRC mismatch: 0x%04X vs 0x%04X", crcGiven, crcCalculated);
        }
    }
    
    globalConfig->loaded = true;
    NRF_LOG_INFO("Config parsed successfully: version=%d, displays=%d, leds=%d, sensors=%d, data_buses=%d, binary_inputs=%d",
                 globalConfig->version, globalConfig->display_count, globalConfig->led_count,
                 globalConfig->sensor_count, globalConfig->data_bus_count, globalConfig->binary_input_count);
    return true;
}

bool loadGlobalConfig(struct GlobalConfig* globalConfig) {
    if (globalConfig == NULL) {
        NRF_LOG_ERROR("Invalid parameter for loadGlobalConfig\n");
        return false;
    }
    
    memset(globalConfig, 0, sizeof(struct GlobalConfig));
    globalConfig->loaded = false;
    
    static uint8_t configData[MAX_CONFIG_SIZE];
    uint32_t configLen = MAX_CONFIG_SIZE;
    
    if (!initConfigStorage()) {
        NRF_LOG_ERROR("Failed to initialize config storage\n");
        return false;
    }
    
    if (!loadConfig(configData, &configLen)) {
        NRF_LOG_DEBUG("No config found\n");
        return false;
    }
    
    return parseConfigBytes(configData, configLen, globalConfig);
}
