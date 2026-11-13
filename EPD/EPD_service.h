#ifndef __EPD_SERVICE_H__
#define __EPD_SERVICE_H__
#include <inttypes.h>
#include <stdbool.h>
#include "ble.h"
#include "ble_srv_common.h"
#if defined(S112)
#include "nrf_sdh_ble.h"
#endif
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

#define BLE_UUID_EPD_SVC_BASE \
    {{0xFB, 0x34, 0x9B, 0x5F, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x46, 0x24, 0x00, 0x00}}
#define BLE_UUID_EPD_SVC 0x2446
#define BLE_UUID_EPD_CHAR 0x2446  // Same as service UUID (as in src)
#define BLE_UUID_APP_VER 0x0003

#define EPD_SVC_UUID_TYPE BLE_UUID_TYPE_VENDOR_BEGIN

/* Opcodes, response codes and error bytes are the protocol's own. */
#include "opendisplay_protocol.h"

#if defined(S112)
#define BLE_EPD_MAX_DATA_LEN (NRF_SDH_BLE_GATT_MAX_MTU_SIZE - 3)
#else
#define BLE_EPD_MAX_DATA_LEN \
    (GATT_MTU_SIZE_DEFAULT - 3) /**< Maximum length of data (in bytes) that can be transmitted to the peer. */
#endif


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
    struct DisplayConfig* display_config; /**< Display config from GlobalConfig (new system) */
    struct GlobalConfig* global_config; /**< Global config (for EN/LED pins) */
} ble_epd_t;

/* Work that must not run in the BLE event handler: the refresh after DIRECT_WRITE_END and the
 * config-read chunks that did not fit the SoftDevice's notification queue. Call from main(). */
void ble_epd_service_run(ble_epd_t* p_epd);
bool ble_epd_refresh_busy(void);
#define EPD_GUI_SCHD_EVENT_DATA_SIZE 8

void ble_epd_sleep_prepare(ble_epd_t* p_epd);

uint32_t ble_epd_init(ble_epd_t* p_epd);

void ble_epd_on_ble_evt(ble_epd_t* p_epd, ble_evt_t* p_ble_evt);

uint32_t ble_epd_string_send(ble_epd_t* p_epd, uint8_t* p_string, uint16_t length);


#endif  // EPD_BLE_H__

/** @} */
