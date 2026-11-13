#ifndef __STRUCTS_H
#define __STRUCTS_H

#include <stdint.h>
#include <stdbool.h>


/* The config packet structs are the protocol's own (od/protocol/opendisplay_structs.h), so
 * this firmware and every other 3.0 target agree on the wire layout by construction. */
#include "opendisplay_structs.h"

struct GlobalConfig {
    struct SystemConfig system_config;
    struct ManufacturerData manufacturer_data;
    struct PowerOption power_option;
    struct DisplayConfig displays[4];
    uint8_t display_count;
    struct LedConfig leds[4];
    uint8_t led_count;
    struct SensorData sensors[4];
    uint8_t sensor_count;
    struct DataBus data_buses[4];
    uint8_t data_bus_count;
    struct BinaryInputs binary_inputs[4];
    uint8_t binary_input_count;
    struct NfcConfig nfc_configs[2];
    uint8_t nfc_config_count;
    struct FlashConfig flash_configs[2];
    uint8_t flash_config_count;
    uint8_t version;            // Protocol version
    uint8_t minor_version;      // Protocol minor version
    bool loaded;                // True if config was successfully loaded
};

#endif // __STRUCTS_H
