#ifndef __STRUCTS_H
#define __STRUCTS_H

#include <stdint.h>
#include <stdbool.h>

struct ImageData {
    uint8_t* data;
    uint32_t size;
    uint32_t received;
    uint8_t dataType;
    bool isCompressed;
    uint32_t crc32;
    uint16_t width;
    uint16_t height;
    bool ready;
    uint32_t totalBlocks;
    uint32_t currentBlock;
    bool* blocksReceived;
    uint32_t* blockBytesReceived;  // Track bytes received per block
    uint32_t* blockPacketsReceived; // Track packets received per block
};

struct SystemConfig {
    uint16_t ic_type;           // IC used in this device
    uint8_t communication_modes; // Supported communication modes (bitfield)
    uint8_t device_flags;       // Misc device flags (bitfield)
    uint8_t pwr_pin;            // Power pin number (0xFF if not present)
    uint8_t reserved[17];       // Reserved bytes for future use
} __attribute__((packed));

struct ManufacturerData {
    uint16_t manufacturer_id;   // Defines the manufacturer
    uint8_t board_type;         // Board identifier
    uint8_t board_revision;     // Board revision number
    uint8_t reserved[18];       // Reserved bytes for future use
} __attribute__((packed));

struct PowerOption {
    uint8_t power_mode;         // Power source type enum
    uint8_t battery_capacity_mah[3]; // Battery capacity in mAh (3 bytes)
    uint16_t sleep_timeout_ms;  // Nominal awake time in milliseconds (advertising timeout)
    uint8_t tx_power;           // Transmit power setting
    uint8_t sleep_flags;        // Sleep-related flags (bitfield)
    uint8_t battery_sense_pin;  // Pin used to measure battery voltage (0xFF if none)
    uint8_t battery_sense_enable_pin; // Pin that enables battery sense circuit (0xFF if none)
    uint8_t battery_sense_flags; // Battery sense flags (bitfield)
    uint8_t capacity_estimator; // Battery chemistry estimator enum
    uint16_t voltage_scaling_factor; // Voltage scaling / divider factor
    uint32_t deep_sleep_current_ua; // Deep sleep current in microamperes
    uint16_t deep_sleep_time_seconds; // Deep sleep duration in seconds (0 if not used)
    uint8_t reserved[10];        // Reserved bytes for future use
} __attribute__((packed));

struct DisplayConfig {
    uint8_t instance_number;    // Unique index for multiple display blocks (0-based)
    uint8_t display_technology; // Display technology enum
    uint16_t panel_ic_type;     // Display controller / panel type
    uint16_t pixel_width;       // Pixel width of panel
    uint16_t pixel_height;      // Pixel height of panel
    uint16_t active_width_mm;   // Active width of panel in millimeters
    uint16_t active_height_mm;  // Active height of panel in millimeters
    uint16_t tag_type;          // Legacy tag type (optional)
    uint8_t rotation;           // Physical rotation in degrees (enum)
    uint8_t reset_pin;          // Pin number for panel reset (0xFF if none)
    uint8_t busy_pin;           // Pin number to read panel busy status (0xFF if none)
    uint8_t dc_pin;             // Data/Command select pin (0xFF if none)
    uint8_t cs_pin;             // SPI chip select pin (0xFF if none)
    uint8_t data_pin;           // Data out pin (MOSI / data line)
    uint8_t partial_update_support; // Partial update capability (enum)
    uint8_t color_scheme;       // Color scheme supported by the display
    uint8_t transmission_modes; // Supported image/data transmission modes (bitfield)
    uint8_t clk_pin;            // Clock pin (SCLK)
    uint8_t reserved_pin_2;     // Reserved / spare pin 2
    uint8_t reserved_pin_3;     // Reserved / spare pin 3
    uint8_t reserved_pin_4;     // Reserved / spare pin 4
    uint8_t reserved_pin_5;     // Reserved / spare pin 5
    uint8_t reserved_pin_6;     // Reserved / spare pin 6
    uint8_t reserved_pin_7;     // Reserved / spare pin 7
    uint8_t reserved_pin_8;     // Reserved / spare pin 8
    uint8_t reserved[15];       // Reserved bytes for future use
} __attribute__((packed));

struct LedConfig {
    uint8_t instance_number;    // Unique index for multiple LED blocks (0-based)
    uint8_t led_type;           // LED type enum (RGB, single, RY, etc.)
    uint8_t led_1_r;            // LED channel 1 (red) pin number
    uint8_t led_2_g;            // LED channel 2 (green) pin number
    uint8_t led_3_b;            // LED channel 3 (blue) pin number
    uint8_t led_4;              // LED channel 4 pin number (if present)
    uint8_t led_flags;          // LED flags (bitfield)
    uint8_t reserved[15];       // Reserved bytes for future use
} __attribute__((packed));

struct SensorData {
    uint8_t instance_number;    // Unique index for multiple sensor blocks (0-based)
    uint16_t sensor_type;       // Sensor type enum
    uint8_t bus_id;             // Instance id of the bus to use for this sensor
    uint8_t reserved[26];       // Reserved bytes for future use
} __attribute__((packed));

struct DataBus {
    uint8_t instance_number;    // Unique index for multiple bus blocks (0-based)
    uint8_t bus_type;           // Bus type enum
    uint8_t pin_1;              // Pin 1 (SCL for I2C)
    uint8_t pin_2;              // Pin 2 (SDA for I2C)
    uint8_t pin_3;              // Pin 3 (aux)
    uint8_t pin_4;              // Pin 4 (aux)
    uint8_t pin_5;              // Pin 5 (aux)
    uint8_t pin_6;              // Pin 6 (aux)
    uint8_t pin_7;              // Pin 7 (aux)
    uint32_t bus_speed_hz;      // Bus speed in Hz (32-bit value)
    uint8_t bus_flags;          // Bus flags (bitfield)
    uint8_t pullups;            // Internal pullup resistors (bit per pin)
    uint8_t pulldowns;          // Internal pulldown resistors (bit per pin)
    uint8_t reserved[14];       // Reserved bytes for future use
} __attribute__((packed));

struct BinaryInputs {
    uint8_t instance_number;    // Unique index for multiple input blocks (0-based)
    uint8_t input_type;         // Input type enum
    uint8_t display_as;         // How input should be represented in systems (enum)
    uint8_t reserved_pin_1;     // Reserved / spare pin 1
    uint8_t reserved_pin_2;     // Reserved / spare pin 2
    uint8_t reserved_pin_3;     // Reserved / spare pin 3
    uint8_t reserved_pin_4;     // Reserved / spare pin 4
    uint8_t reserved_pin_5;     // Reserved / spare pin 5
    uint8_t reserved_pin_6;     // Reserved / spare pin 6
    uint8_t reserved_pin_7;     // Reserved / spare pin 7
    uint8_t reserved_pin_8;     // Reserved / spare pin 8
    uint8_t input_flags;        // Input flags (bitfield)
    uint8_t invert;             // Invert flags per pin (bitfield)
    uint8_t pullups;            // Internal pullup resistors per pin (bitfield)
    uint8_t pulldowns;          // Internal pulldown resistors per pin (bitfield)
    uint8_t button_data_byte_index;  // Byte index in dynamicreturndata (0-10) for button data
    uint8_t reserved[14];       // Reserved bytes for future use
} __attribute__((packed));

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
    uint8_t version;            // Protocol version
    uint8_t minor_version;      // Protocol minor version
    bool loaded;                // True if config was successfully loaded
};

struct SecurityConfig {
    uint8_t encryption_enabled;     // 0 = disabled, 1 = enabled
    uint8_t encryption_key[16];    // AES-128 master key (16 bytes)
    uint16_t session_timeout_seconds; // Session timeout (0 = no timeout)
    uint8_t flags;                  // Security flags bitfield
    uint8_t reset_pin;              // Reset pin number (0xFF = disabled)
    uint8_t reserved[43];           // Reserved bytes for future use
} __attribute__((packed));

#define SECURITY_FLAG_REWRITE_ALLOWED     (1 << 0)
#define SECURITY_FLAG_SHOW_KEY_ON_SCREEN  (1 << 1)
#define SECURITY_FLAG_RESET_PIN_ENABLED   (1 << 2)
#define SECURITY_FLAG_RESET_PIN_POLARITY  (1 << 3)
#define SECURITY_FLAG_RESET_PIN_PULLUP    (1 << 4)
#define SECURITY_FLAG_RESET_PIN_PULLDOWN  (1 << 5)

struct EncryptionSession {
    bool authenticated;              // Session is authenticated
    uint8_t session_key[16];         // Derived session key (zeroized on clear)
    uint8_t session_id[8];           // Session identifier (8 bytes, derived via CMAC)
    uint64_t nonce_counter;          // Per-session counter (64-bit, prevents wrap)
    uint64_t last_seen_counter;      // Last accepted counter value
    uint64_t replay_window[64];      // Sliding window for replay protection (64 packets)
    uint8_t replay_idx;              // Current index in replay window (0-63)
    uint32_t last_activity;          // Timestamp of last activity
    uint8_t integrity_failures;      // Consecutive integrity failures (max 3)
    uint32_t session_start_time;     // Session establishment time
    uint8_t auth_attempts;           // Authentication attempts (for rate limiting)
    uint32_t last_auth_time;         // Last authentication attempt time
    uint8_t client_nonce[16];        // Client nonce from auth (16 bytes)
    uint8_t server_nonce[16];        // Server nonce from auth (16 bytes)
    uint8_t pending_server_nonce[16]; // Pending server nonce (expires after 30 seconds)
    uint32_t server_nonce_time;      // Time when server nonce was generated
};

#endif // __STRUCTS_H
