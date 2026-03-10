#ifndef __EPD_SERVICE_H__
#define __EPD_SERVICE_H__
#include <inttypes.h>
#include <stdbool.h>
#include "ble.h"
#include "ble_srv_common.h"
#if defined(S112)
#include "nrf_sdh_ble.h"
#endif
#include "EPD_driver.h"
#include "sdk_config.h"
#include "structs.h"

#if defined(S112)
void ble_epd_evt_handler(ble_evt_t const* p_ble_evt, void* p_context);

#define BLE_EPD_BLE_OBSERVER_PRIO 2
#define BLE_EPD_DEF(_name)  \
    static ble_epd_t _name; \
    NRF_SDH_BLE_OBSERVER(_name##_obs, BLE_EPD_BLE_OBSERVER_PRIO, ble_epd_evt_handler, &_name)
#else
#define BLE_EPD_DEF(_name) static ble_epd_t _name;
#endif

#ifndef APP_VERSION
#define APP_VERSION 0x19
#endif

#ifndef BUILD_VERSION
#ifdef BUILD_VERSION_MAJOR
#ifdef BUILD_VERSION_MINOR
#define BUILD_VERSION_STR_HELPER(x) #x
#define BUILD_VERSION_STR(x) BUILD_VERSION_STR_HELPER(x)
#define BUILD_VERSION BUILD_VERSION_STR(BUILD_VERSION_MAJOR) "." BUILD_VERSION_STR(BUILD_VERSION_MINOR)
#else
#define BUILD_VERSION "1.0"
#endif
#else
#define BUILD_VERSION "1.0"
#endif
#endif

#ifndef SHA_STRING
#ifdef SHA_VALUE
#define SHA_STRING SHA_VALUE
#else
#ifndef SHA
#define SHA "1234567890abcdef1234567890abcdef12345678"
#endif

#ifndef STRINGIFY
#define STRINGIFY(x) #x
#endif
#define XSTRINGIFY(x) STRINGIFY(x)
#define SHA_STRING XSTRINGIFY(SHA)
#endif
#endif

#define BLE_UUID_EPD_SVC_BASE \
    {{0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x46, 0x24, 0x00, 0x00}}
#define BLE_UUID_EPD_SVC 0x2446
#define BLE_UUID_EPD_CHAR 0x2446  // Same as service UUID (as in src)
#define BLE_UUID_APP_VER 0x0003

#define EPD_SVC_UUID_TYPE BLE_UUID_TYPE_VENDOR_BEGIN

#define CMD_CONFIG_READ    0x0040
#define CMD_CONFIG_WRITE   0x0041
#define CMD_CONFIG_CHUNK   0x0042

#define CMD_DIRECT_WRITE_START  0x0070
#define CMD_DIRECT_WRITE_DATA   0x0071
#define CMD_DIRECT_WRITE_END    0x0072

#define CMD_LED_ACTIVATE        0x0073

#define CMD_REBOOT              0x000F
#define CMD_FIRMWARE_VERSION    0x0043
#define CMD_READ_MSD            0x0044

#define CMD_AUTHENTICATE        0x0050
#define CMD_ENTER_DFU           0x0051
#define CMD_DEEP_SLEEP          0x0052

#define AUTH_STATUS_CHALLENGE   0x00  // Challenge sent / success
#define AUTH_STATUS_SUCCESS     AUTH_STATUS_CHALLENGE  // Authentication successful (same value as challenge)
#define AUTH_STATUS_FAILED      0x01  // Authentication failed (wrong key)
#define AUTH_STATUS_ALREADY     0x02  // Already authenticated
#define AUTH_STATUS_NOT_CONFIG  0x03  // Encryption not configured
#define AUTH_STATUS_RATE_LIMIT  0x04  // Rate limit exceeded
#define AUTH_STATUS_ERROR       0xFF  // Generic error

#define RESP_AUTH_REQUIRED      0xFE

#define RESP_CONFIG_READ  0x40
#define RESP_CONFIG_WRITE  0x41
#define RESP_CONFIG_CHUNK  0x42
#define RESP_DIRECT_WRITE_START_ACK  0x70
#define RESP_DIRECT_WRITE_DATA_ACK   0x71
#define RESP_DIRECT_WRITE_END_ACK    0x72
#define RESP_DIRECT_WRITE_REFRESH_SUCCESS 0x73
#define RESP_DIRECT_WRITE_REFRESH_TIMEOUT 0x74
#define RESP_DIRECT_WRITE_ERROR      0xFF
#define RESP_LED_ACTIVATE_ACK        0x73
#define RESP_FIRMWARE_VERSION  0x43
#define RESP_MSD_READ          0x44
#define RESP_AUTHENTICATE      0x50
#define RESP_ENTER_DFU         0x51
#define RESP_DEEP_SLEEP        0x52

#define CONFIG_CHUNK_SIZE 200
#define CONFIG_CHUNK_SIZE_WITH_PREFIX 202
#define MAX_CONFIG_CHUNKS 20
#define MAX_RESPONSE_DATA_SIZE 100

#define MAX_ENCRYPTED_CIPHERTEXT_LEN 512  /**< Maximum ciphertext length in bytes */
#define BLE_CMD_HEADER_SIZE 2              /**< Command header size (2 bytes) */
#define ENCRYPTION_NONCE_SIZE 16           /**< Nonce size for encryption (16 bytes) */
#define ENCRYPTION_TAG_SIZE 12             /**< Authentication tag size (12 bytes) */
#define MAX_ENCRYPTED_PACKET_SIZE (BLE_CMD_HEADER_SIZE + ENCRYPTION_NONCE_SIZE + MAX_ENCRYPTED_CIPHERTEXT_LEN + ENCRYPTION_TAG_SIZE)  /**< Maximum encrypted packet: 2 + 16 + 512 + 12 = 542 bytes */
#define MAX_UNENCRYPTED_PACKET_SIZE 514    /**< Maximum unencrypted packet: 2 (cmd) + 512 (payload) = 514 bytes */
#define MAX_BLE_PACKET_SIZE MAX_ENCRYPTED_PACKET_SIZE  /**< Overall maximum BLE packet size */

#if defined(S112)
#define BLE_EPD_MAX_DATA_LEN (NRF_SDH_BLE_GATT_MAX_MTU_SIZE - 3)
#else
#define BLE_EPD_MAX_DATA_LEN \
    (GATT_MTU_SIZE_DEFAULT - 3) /**< Maximum length of data (in bytes) that can be transmitted to the peer. */
#endif

enum EPD_CMDS {
    EPD_CMD_SET_PINS = 0x00,     /**< set EPD pin mapping. */
    EPD_CMD_INIT = 0x01,         /**< init EPD display driver */
    EPD_CMD_CLEAR = 0x02,        /**< clear EPD screen */
    EPD_CMD_SEND_COMMAND = 0x03, /**< send command to EPD */
    EPD_CMD_SEND_DATA = 0x04,    /**< send data to EPD */
    EPD_CMD_REFRESH = 0x05,      /**< diaplay EPD ram on screen */
    EPD_CMD_SLEEP = 0x06,        /**< EPD enter sleep mode */

    EPD_CMD_SET_TIME = 0x20,       /** < set time with unix timestamp */
    EPD_CMD_SET_WEEK_START = 0x21, /** < set week start day (0: Sunday, 1: Monday, ...) */

    EPD_CMD_SET_CONFIG = 0x90, /**< set full EPD config */
    EPD_CMD_SYS_RESET = 0x91,  /**< MCU reset */
    EPD_CMD_SYS_SLEEP = 0x92,  /**< MCU enter sleep mode */
    EPD_CMD_CFG_ERASE = 0x99,  /**< Erase config and reset */
};

typedef struct {
    uint16_t service_handle; /**< Handle of EPD Service (as provided by the S110 SoftDevice). */
    ble_gatts_char_handles_t
        char_handles; /**< Handles related to the EPD characteristic (as provided by the SoftDevice). */
    ble_gatts_char_handles_t
        app_ver_handles;  /**< Handles related to the APP version characteristic (as provided by the SoftDevice). */
    uint16_t conn_handle; /**< Handle of the current connection (as provided by the SoftDevice). BLE_CONN_HANDLE_INVALID
                             if not in a connection. */
    uint16_t max_data_len;        /**< Maximum length of data (in bytes) that can be transmitted to the peer */
    bool is_notification_enabled; /**< Variable to indicate if the peer has enabled notification of the RX
                                     characteristic.*/
    epd_model_t* epd;             /**< current EPD model */
    struct DisplayConfig* display_config; /**< Display config from GlobalConfig (new system) */
    struct GlobalConfig* global_config; /**< Global config (for EN/LED pins) */
} ble_epd_t;

typedef struct {
    ble_epd_t* p_epd;
    uint32_t timestamp;
} epd_gui_update_event_t;

#define EPD_GUI_SCHD_EVENT_DATA_SIZE sizeof(epd_gui_update_event_t)

void ble_epd_sleep_prepare(ble_epd_t* p_epd);

uint32_t ble_epd_init(ble_epd_t* p_epd);

void ble_epd_on_ble_evt(ble_epd_t* p_epd, ble_evt_t* p_ble_evt);

uint32_t ble_epd_string_send(ble_epd_t* p_epd, uint8_t* p_string, uint16_t length);

void ble_epd_on_timer(ble_epd_t* p_epd, uint32_t timestamp, bool force_update);

#endif  // EPD_BLE_H__

/** @} */
