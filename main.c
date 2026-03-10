#include <stdint.h>
#include <string.h>
#include "ble.h"
#include "ble_advdata.h"
#include "ble_advertising.h"
#include "ble_conn_params.h"
#include "ble_dfu.h"
#include "ble_hci.h"
#include "ble_srv_common.h"
#include "nordic_common.h"
#include "nrf.h"
#if defined(S112)
#include "nrf_ble_gatt.h"
#include "nrf_bootloader_info.h"
#include "nrf_sdh.h"
#include "nrf_sdh_ble.h"
#include "nrf_sdh_soc.h"
#include "nrf_soc.h"  // For sd_temp_get
#else
#include "fstorage.h"
#include "softdevice_handler.h"
#include "nrf_soc.h"  // For sd_temp_get
#endif
#include "EPD_service.h"
#include "EPD_driver.h"
#include "app_error.h"
#include "app_scheduler.h"
#include "app_timer.h"
#include "button_control.h"
#include "config_parser.h"
#include "config_storage.h"
#include "led_control.h"
#include "main.h"
#include "constants.h"
#include "nrf_drv_gpiote.h"
#include "nrf_drv_wdt.h"
#include "nrf_log.h"
#include "nrf_log_ctrl.h"
#include "nrf_power.h"
#include "nrf_pwr_mgmt.h"
#include "encryption.h"
#include "structs.h"
#if defined(S112)
#include "nrf_log_default_backends.h"
#endif

#define CENTRAL_LINK_COUNT              0                                               /**< Number of central links used by the application. When changing this number remember to adjust the RAM settings*/
#define PERIPHERAL_LINK_COUNT           1                                               /**< Number of peripheral links used by the application. When changing this number remember to adjust the RAM settings*/

#define DEVICE_NAME_PREFIX               "OD"                                          /**< Device name prefix (OpenDisplay) */
#define APP_ADV_INTERVAL                 1600                                           /**< The advertising interval (in units of 0.625 ms. This value corresponds to 1 s). */
#define APP_ADV_TIMEOUT_IN_SECONDS       0                                              /**< The advertising timeout (0 = unlimited). */
#define APP_TIMER_PRESCALER              0                                              /**< Value of the RTC1 PRESCALER register. */
#define APP_TIMER_OP_QUEUE_SIZE          4                                              /**< Size of timer operation queues. */

#if defined(S112)
#define APP_BLE_CONN_CFG_TAG            1                                               /**< A tag identifying the SoftDevice BLE configuration. */
#define APP_BLE_OBSERVER_PRIO           3                                               /**< Application's BLE observer priority. You shouldn't need to modify this value. */
#define TIMER_TICKS(MS) APP_TIMER_TICKS(MS)
#else
#define TIMER_TICKS(MS) APP_TIMER_TICKS(MS, APP_TIMER_PRESCALER)
// Low frequency clock source to be used by the SoftDevice
#define NRF_CLOCK_LFCLKSRC      {.source        = NRF_CLOCK_LF_SRC_RC,               \
                                 .rc_ctiv       = 16,                                \
                                 .rc_temp_ctiv  = 2,                                 \
                                 .xtal_accuracy = 0}
#endif

#define MIN_CONN_INTERVAL                MSEC_TO_UNITS(7.5, UNIT_1_25_MS)               /**< Minimum connection interval (7.5 ms) */
#define MAX_CONN_INTERVAL                MSEC_TO_UNITS(30, UNIT_1_25_MS)                /**< Maximum connection interval (30 ms). */
#define SLAVE_LATENCY                    6                                              /**< Slave latency. */
#define CONN_SUP_TIMEOUT                 MSEC_TO_UNITS(430, UNIT_10_MS)                 /**< Connection supervisory timeout (430 ms). */
#define FIRST_CONN_PARAMS_UPDATE_DELAY   TIMER_TICKS(5000)                              /**< Time from initiating event (connect or start of notification) to first time sd_ble_gap_conn_param_update is called (5 seconds). */
#define NEXT_CONN_PARAMS_UPDATE_DELAY    TIMER_TICKS(30000)                             /**< Time between each call to sd_ble_gap_conn_param_update after the first call (30 seconds). */
#define MAX_CONN_PARAMS_UPDATE_COUNT     3                                              /**< Number of attempts before giving up the connection parameter negotiation. */

#define SCHED_MAX_EVENT_DATA_SIZE       EPD_GUI_SCHD_EVENT_DATA_SIZE                    /**< Maximum size of scheduler events. */
#define SCHED_QUEUE_SIZE                10                                              /**< Maximum number of events in the scheduler queue. */

#define CLOCK_TIMER_INTERVAL             TIMER_TICKS(1000)                              /**< Clock timer interval (ticks). */

#define DEAD_BEEF                        0xDEADBEEF                                     /**< Value used as error code on stack dump, can be used to identify stack location on stack unwind. */

#if defined(S112)
NRF_BLE_GATT_DEF(m_gatt);                                                               /**< GATT module instance. */
BLE_ADVERTISING_DEF(m_advertising);                                                     /**< Advertising module instance. */
#else
static ble_dfu_t                         m_dfus;                                        /**< Structure used to identify the DFU service. */
#endif
static uint16_t                          m_conn_handle = BLE_CONN_HANDLE_INVALID;       /**< Handle of the current connection. */
static ble_uuid_t                        m_adv_uuids[] = {{BLE_UUID_EPD_SVC, \
                                                           BLE_UUID_TYPE_VENDOR_BEGIN}};         /**< Universally unique service identifier. */
#define MSD_PAYLOAD_SIZE 16
static uint8_t                           msd_payload[MSD_PAYLOAD_SIZE];
static uint8_t                           mloopcounter = 0;
uint8_t                                  rebootFlag = 1;  // Set to 1 after reboot, cleared after BLE connection (extern in main.h)
static uint8_t                           connectionRequested = 0;  // Reserved for future features
uint8_t dynamicreturndata[11] = {0};  // Dynamic return data blocks (bytes 2-12 in MSD payload) - extern for button_control.c

BLE_EPD_DEF(m_epd);                                                                     /**< Structure to identify the EPD Service. */
struct GlobalConfig globalConfig;                                                       /**< Global configuration (extern for led_control.c) */
static uint32_t                          m_timestamp = 1735689600;                      /**< Current timestamp. */
APP_TIMER_DEF(m_clock_timer_id);                                                        /**< Clock timer. */
static nrf_drv_wdt_channel_id            m_wdt_channel_id;
static uint32_t                          m_wdt_last_feed_time = 0;
static uint32_t                          m_resetreas;
// clang-format on

static float read_chip_temperature(void) {
    int32_t temp_raw = 0;
    uint32_t err_code;
    
#if defined(S112)
    err_code = sd_temp_get(&temp_raw);
#else
    err_code = sd_temp_get(&temp_raw);
#endif
    
    if (err_code == NRF_SUCCESS) {
        float temp_c = temp_raw * 0.25f;
        return temp_c;
    }
    return -999.0f;
}

void updatemsdata(void) {
    uint16_t msd_cid = globalConfig.manufacturer_data.manufacturer_id;
    if (msd_cid == 0) {
        msd_cid = 0x2446;  // Default company ID
    }
    float chip_temperature = read_chip_temperature();
    uint16_t battery_voltage_mv = EPD_ReadVoltage();
    uint16_t battery_voltage_10mv = battery_voltage_mv / 10;
    if (battery_voltage_10mv > 511) {
        battery_voltage_10mv = 511;
    }
    int16_t temp_encoded = (int16_t)((chip_temperature + 40.0f) * 2.0f);
    if (temp_encoded < 0) {
        temp_encoded = 0;  // Clamp to minimum (-40°C)
    } else if (temp_encoded > 255) {
        temp_encoded = 255;  // Clamp to maximum (+87.5°C)
    }
    uint8_t temperature_byte = (uint8_t)temp_encoded;
    uint8_t battery_voltage_low_byte = (uint8_t)(battery_voltage_10mv & 0xFF);
    uint8_t status_byte = ((battery_voltage_10mv >> 8) & 0x01) |
                          ((rebootFlag & 0x01) << 1) |
                          ((connectionRequested & 0x01) << 2) |
                          ((mloopcounter & 0x0F) << 4);
    memset(msd_payload, 0, sizeof(msd_payload));
    msd_payload[0] = (uint8_t)(msd_cid & 0xFF);
    msd_payload[1] = (uint8_t)((msd_cid >> 8) & 0xFF);
    memcpy(&msd_payload[2], dynamicreturndata, sizeof(dynamicreturndata));
    msd_payload[13] = temperature_byte;      // Temperature with 0.5°C accuracy (-40°C to +87.5°C)
    msd_payload[14] = battery_voltage_low_byte; // Battery voltage lower 8 bits (10mV steps)
    msd_payload[15] = status_byte;            // Battery voltage MSB + Reboot flag + Connection requested + RFU + mloopcounter
    mloopcounter = (uint8_t)((mloopcounter + 1) & 0x0F);
}

void get_msd_payload(uint8_t* out, uint8_t max_len, uint8_t* out_len) {
    uint8_t copy_len;
    if (out_len == NULL) {
        return;
    }
    copy_len = (max_len < MSD_PAYLOAD_SIZE) ? max_len : MSD_PAYLOAD_SIZE;
    if (out != NULL && copy_len > 0) {
        memcpy(out, msd_payload, copy_len);
    }
    *out_len = copy_len;
}

void assert_nrf_callback(uint16_t line_num, const uint8_t* p_file_name) {
    app_error_handler(DEAD_BEEF, line_num, p_file_name);
}

uint32_t timestamp(void) { return m_timestamp; }

void set_timestamp(uint32_t timestamp) {
    app_timer_stop(m_clock_timer_id);
    m_timestamp = timestamp;
    app_timer_start(m_clock_timer_id, CLOCK_TIMER_INTERVAL, NULL);
}

static void advertising_start(void);
static void on_adv_evt(ble_adv_evt_t ble_adv_evt);
void advertising_restart_with_updated_msd(void);

void app_feed_wdt(void) {
    if (m_timestamp - m_wdt_last_feed_time >= WDT_FEED_INTERVAL_SEC) {
        nrf_drv_wdt_channel_feed(m_wdt_channel_id);
        m_wdt_last_feed_time = m_timestamp;
    }
}

#if defined(S112)
static void buttonless_dfu_sdh_state_observer(nrf_sdh_state_evt_t state, void* p_context) {
    if (state == NRF_SDH_EVT_STATE_DISABLED) {
        nrf_power_gpregret2_set(BOOTLOADER_DFU_SKIP_CRC);
        nrf_pwr_mgmt_shutdown(NRF_PWR_MGMT_SHUTDOWN_GOTO_SYSOFF);
    }
}

NRF_SDH_STATE_OBSERVER(m_buttonless_dfu_state_obs, 0) = {
    .handler = buttonless_dfu_sdh_state_observer,
};

static void advertising_config_get(ble_adv_modes_config_t* p_config) {
    memset(p_config, 0, sizeof(ble_adv_modes_config_t));

    p_config->ble_adv_fast_enabled = true;
    p_config->ble_adv_fast_interval = APP_ADV_INTERVAL;
    p_config->ble_adv_fast_timeout = APP_ADV_TIMEOUT_IN_SECONDS * 100;
}

static void ble_dfu_evt_handler(ble_dfu_buttonless_evt_type_t event) {
    switch (event) {
        case BLE_DFU_EVT_BOOTLOADER_ENTER_PREPARE: {
            if (isEncryptionEnabled() && !isAuthenticated()) {
                NRF_LOG_WARNING("DFU blocked: encryption enabled but not authenticated");
                NRF_LOG_FINAL_FLUSH();
                nrf_delay_ms(100);
                NVIC_SystemReset();
                return;
            }
            NRF_LOG_INFO("Device is preparing to enter bootloader mode.");
            ble_adv_modes_config_t config;
            advertising_config_get(&config);
            config.ble_adv_on_disconnect_disabled = true;
            ble_advertising_modes_config_set(&m_advertising, &config);
            ret_code_t err_code = sd_ble_gap_disconnect(m_conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
            if (err_code != NRF_SUCCESS &&
                err_code != NRF_ERROR_INVALID_STATE &&
                err_code != BLE_ERROR_INVALID_CONN_HANDLE) {
                APP_ERROR_CHECK(err_code);
            }
            break;
        }

        case BLE_DFU_EVT_BOOTLOADER_ENTER:
            NRF_LOG_INFO("Device will enter bootloader mode.");
            break;

        case BLE_DFU_EVT_BOOTLOADER_ENTER_FAILED:
            NRF_LOG_ERROR("Request to enter bootloader mode failed asynchroneously.");
            APP_ERROR_CHECK(false);
            break;

        case BLE_DFU_EVT_RESPONSE_SEND_ERROR:
            NRF_LOG_ERROR("Request to send a response to client failed.");
            APP_ERROR_CHECK(false);
            break;

        default:
            NRF_LOG_ERROR("Unknown event from ble_dfu_buttonless.");
            break;
    }
}
#else
static void ble_dfu_evt_handler(ble_dfu_t* p_dfu, ble_dfu_evt_t* p_evt) {
    switch (p_evt->type) {
        case BLE_DFU_EVT_INDICATION_DISABLED:
            NRF_LOG_INFO("Indication for BLE_DFU is disabled\r\n");
            break;

        case BLE_DFU_EVT_INDICATION_ENABLED:
            NRF_LOG_INFO("Indication for BLE_DFU is enabled\r\n");
            break;

        case BLE_DFU_EVT_ENTERING_BOOTLOADER:
            NRF_LOG_INFO("Device is entering bootloader mode!\r\n");
            break;
        default:
            NRF_LOG_INFO("Unknown event from ble_dfu\r\n");
            break;
    }
}
#endif

static void clock_timer_timeout_handler(void* p_context) {
    UNUSED_PARAMETER(p_context);

    m_timestamp++;

    ble_epd_on_timer(&m_epd, m_timestamp, false);
}

static void scheduler_init(void) { APP_SCHED_INIT(SCHED_MAX_EVENT_DATA_SIZE, SCHED_QUEUE_SIZE); }

static void timers_init(void) {
#if defined(S112)
    APP_ERROR_CHECK(app_timer_init());
#else
    APP_TIMER_INIT(APP_TIMER_PRESCALER, APP_TIMER_OP_QUEUE_SIZE, false);
#endif
    APP_ERROR_CHECK(app_timer_create(&m_clock_timer_id, APP_TIMER_MODE_REPEATED, clock_timer_timeout_handler));
}

static void application_timers_start(void) {
    APP_ERROR_CHECK(app_timer_start(m_clock_timer_id, CLOCK_TIMER_INTERVAL, NULL));
}

void sleep_mode_enter(void) {
    NRF_LOG_DEBUG("Entering deep sleep mode\n");
    NRF_LOG_FINAL_FLUSH();
    nrf_delay_ms(100);

    ble_epd_sleep_prepare(&m_epd);
    nrf_pwr_mgmt_shutdown(NRF_PWR_MGMT_SHUTDOWN_GOTO_SYSOFF);
}

void enter_deep_sleep(void) {
    NRF_LOG_INFO("=== ENTERING DEEP SLEEP (System OFF) ===");
    NRF_LOG_INFO("Device will enter lowest power state");
    NRF_LOG_INFO("Only power cycle or reset pin can wake the device");
    NRF_LOG_FINAL_FLUSH();
    if (m_conn_handle != BLE_CONN_HANDLE_INVALID) {
        NRF_LOG_INFO("Disconnecting BLE...");
        ret_code_t err_code = sd_ble_gap_disconnect(m_conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
        if (err_code == NRF_SUCCESS) {
            nrf_delay_ms(200); // Allow disconnect to complete
        }
        m_conn_handle = BLE_CONN_HANDLE_INVALID;
    }
    NRF_LOG_INFO("Stopping advertising...");
#if defined(S112)
    uint8_t adv_handle = 0; // Try handle 0 first (most common)
    ret_code_t adv_err = sd_ble_gap_adv_stop(adv_handle);
    if (adv_err == BLE_ERROR_INVALID_ADV_HANDLE) {
        adv_err = sd_ble_gap_adv_stop(0xFF);
    }
    if (adv_err != NRF_SUCCESS && adv_err != NRF_ERROR_INVALID_STATE && adv_err != BLE_ERROR_INVALID_ADV_HANDLE) {
        NRF_LOG_WARNING("Failed to stop advertising: 0x%X", adv_err);
    }
#else
    ret_code_t adv_err = sd_ble_gap_adv_stop();
    if (adv_err != NRF_SUCCESS && adv_err != NRF_ERROR_INVALID_STATE) {
        NRF_LOG_WARNING("Failed to stop advertising: 0x%X", adv_err);
    }
#endif
    nrf_delay_ms(100);
    NRF_LOG_INFO("Preparing EPD for sleep...");
    ble_epd_sleep_prepare(&m_epd);
    nrf_delay_ms(100);
    if (isAuthenticated()) {
        NRF_LOG_INFO("Clearing encryption session...");
        clearEncryptionSession();
    }
    NRF_LOG_INFO("Disabling interrupts...");
    NVIC->ICER[0] = 0xFFFFFFFF;
    NVIC->ICPR[0] = 0xFFFFFFFF;
#if defined(__NRF_NVIC_ISER_COUNT) && __NRF_NVIC_ISER_COUNT == 2
    NVIC->ICER[1] = 0xFFFFFFFF;
    NVIC->ICPR[1] = 0xFFFFFFFF;
#endif
    NRF_LOG_INFO("Entering System OFF mode...");
    NRF_LOG_FINAL_FLUSH();
    nrf_delay_ms(200);
#ifdef SOFTDEVICE_PRESENT
#if defined(S112)
    if (nrf_sdh_is_enabled()) {
        ret_code_t err_code = sd_power_system_off();
        if (err_code != NRF_SUCCESS && err_code != NRF_ERROR_SOFTDEVICE_NOT_ENABLED) {
            NRF_LOG_ERROR("Failed to enter System OFF via SoftDevice: 0x%X", err_code);
        }
    }
#else
    ret_code_t err_code = sd_power_system_off();
    if (err_code == NRF_ERROR_SOFTDEVICE_NOT_ENABLED || err_code == NRF_ERROR_NOT_SUPPORTED) {
        NRF_LOG_INFO("SoftDevice not available, using direct System OFF");
    } else if (err_code != NRF_SUCCESS) {
        NRF_LOG_WARNING("SoftDevice System OFF returned: 0x%X, using direct access", err_code);
    }
#endif
#endif
    nrf_power_system_off();
    while (1) {
        __WFE();
    }
}

static void services_init(void) {
    struct DisplayConfig* saved_display_config = m_epd.display_config;
    struct GlobalConfig* saved_global_config = m_epd.global_config;
    memset(&m_epd, 0, sizeof(ble_epd_t));
    m_epd.display_config = saved_display_config;
    m_epd.global_config = saved_global_config;
    APP_ERROR_CHECK(ble_epd_init(&m_epd));

#if defined(S112)
    ble_dfu_buttonless_init_t dfus_init = {0};
    dfus_init.evt_handler = ble_dfu_evt_handler;
    APP_ERROR_CHECK(ble_dfu_buttonless_init(&dfus_init));
#else
    ble_dfu_init_t dfus_init;
    memset(&dfus_init, 0, sizeof(dfus_init));
    dfus_init.evt_handler = ble_dfu_evt_handler;
    dfus_init.ctrl_point_security_req_write_perm = SEC_SIGNED;
    dfus_init.ctrl_point_security_req_cccd_write_perm = SEC_SIGNED;
    APP_ERROR_CHECK(ble_dfu_init(&m_dfus, &dfus_init));
#endif
}

void getChipIdHex(char* buffer, uint8_t buffer_size) {
    if (buffer == NULL || buffer_size < 7) return;
    uint32_t id2 = NRF_FICR->DEVICEID[1];
    uint32_t last3Bytes = id2 & 0xFFFFFF;
    snprintf(buffer, buffer_size, "%06X", (unsigned int)last3Bytes);
}

static void gap_params_init(void) {
    char device_name[20];
    char chipId[7];
    ble_gap_addr_t addr;
    ble_gap_conn_params_t gap_conn_params;
    ble_gap_conn_sec_mode_t sec_mode;

    BLE_GAP_CONN_SEC_MODE_SET_OPEN(&sec_mode);
#if defined(S112)
    APP_ERROR_CHECK(sd_ble_gap_addr_get(&addr));
#else
    APP_ERROR_CHECK(sd_ble_gap_address_get(&addr));
#endif

    NRF_LOG_INFO("Bluetooth MAC Address: %02X:%02X:%02X:%02X:%02X:%02X\n", addr.addr[5], addr.addr[4], addr.addr[3],
                 addr.addr[2], addr.addr[1], addr.addr[0]);
    getChipIdHex(chipId, sizeof(chipId));
    snprintf(device_name, sizeof(device_name), "%s%s", DEVICE_NAME_PREFIX, chipId);
    NRF_LOG_INFO("Device name: %s\n", device_name);
    APP_ERROR_CHECK(sd_ble_gap_device_name_set(&sec_mode, (const uint8_t*)device_name, strlen(device_name)));

    memset(&gap_conn_params, 0, sizeof(gap_conn_params));

    gap_conn_params.min_conn_interval = MIN_CONN_INTERVAL;
    gap_conn_params.max_conn_interval = MAX_CONN_INTERVAL;
    gap_conn_params.slave_latency = SLAVE_LATENCY;
    gap_conn_params.conn_sup_timeout = CONN_SUP_TIMEOUT;

    APP_ERROR_CHECK(sd_ble_gap_ppcp_set(&gap_conn_params));
}

static void on_conn_params_evt(ble_conn_params_evt_t* p_evt) {
    if (p_evt->evt_type == BLE_CONN_PARAMS_EVT_FAILED) {
        APP_ERROR_CHECK(sd_ble_gap_disconnect(m_conn_handle, BLE_HCI_CONN_INTERVAL_UNACCEPTABLE));
    }
}

static void conn_params_error_handler(uint32_t nrf_error) { APP_ERROR_HANDLER(nrf_error); }

static void conn_params_init(void) {
    ble_conn_params_init_t cp_init;

    memset(&cp_init, 0, sizeof(cp_init));

    cp_init.p_conn_params = NULL;
    cp_init.first_conn_params_update_delay = FIRST_CONN_PARAMS_UPDATE_DELAY;
    cp_init.next_conn_params_update_delay = NEXT_CONN_PARAMS_UPDATE_DELAY;
    cp_init.max_conn_params_update_count = MAX_CONN_PARAMS_UPDATE_COUNT;
    cp_init.start_on_notify_cccd_handle = BLE_GATT_HANDLE_INVALID;
    cp_init.disconnect_on_fail = false;
    cp_init.evt_handler = on_conn_params_evt;
    cp_init.error_handler = conn_params_error_handler;

    APP_ERROR_CHECK(ble_conn_params_init(&cp_init));
}

static void advertising_start(void) {
#if defined(S112)
    APP_ERROR_CHECK(ble_advertising_start(&m_advertising, BLE_ADV_MODE_FAST));
#else
    APP_ERROR_CHECK(ble_advertising_start(BLE_ADV_MODE_FAST));
#endif
}

void advertising_restart_with_updated_msd(void) {
    // Rebuild advertising data structure with updated MSD payload
#if defined(S112)
    ble_advdata_t advdata;
    ble_advdata_t scanrsp;
    ble_advdata_manuf_data_t manuf_data;
    
    memset(&advdata, 0, sizeof(advdata));
    advdata.name_type = BLE_ADVDATA_FULL_NAME;
    advdata.include_appearance = false;
    advdata.flags = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
    manuf_data.company_identifier = (uint16_t)msd_payload[0] | ((uint16_t)msd_payload[1] << 8);
    manuf_data.data.p_data = msd_payload + 2;
    manuf_data.data.size = sizeof(msd_payload) - 2;
    advdata.p_manuf_specific_data = &manuf_data;
    
    memset(&scanrsp, 0, sizeof(scanrsp));
    scanrsp.uuids_complete.uuid_cnt = sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]);
    scanrsp.uuids_complete.p_uuids = m_adv_uuids;
    
    ret_code_t err_code = ble_advertising_advdata_update(&m_advertising, &advdata, &scanrsp);
    if (err_code != NRF_SUCCESS) {
        NRF_LOG_WARNING("Failed to update advertising data: 0x%X\n", err_code);
    }
#else
    ret_code_t err_code = sd_ble_gap_adv_stop();
    if (err_code == NRF_SUCCESS || err_code == NRF_ERROR_INVALID_STATE) {
        ble_advdata_t advdata;
        ble_advdata_t scanrsp;
        ble_adv_modes_config_t options;
        ble_advdata_manuf_data_t manuf_data;
        
        memset(&advdata, 0, sizeof(advdata));
        advdata.name_type = BLE_ADVDATA_FULL_NAME;
        advdata.include_appearance = false;
        advdata.flags = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
        manuf_data.company_identifier = (uint16_t)msd_payload[0] | ((uint16_t)msd_payload[1] << 8);
        manuf_data.data.p_data = msd_payload + 2;
        manuf_data.data.size = sizeof(msd_payload) - 2;
        advdata.p_manuf_specific_data = &manuf_data;
        
        memset(&scanrsp, 0, sizeof(scanrsp));
        scanrsp.uuids_complete.uuid_cnt = sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]);
        scanrsp.uuids_complete.p_uuids = m_adv_uuids;
        
        memset(&options, 0, sizeof(options));
        options.ble_adv_fast_enabled = true;
        options.ble_adv_fast_interval = APP_ADV_INTERVAL;
        options.ble_adv_fast_timeout = APP_ADV_TIMEOUT_IN_SECONDS;
        
        err_code = ble_advertising_init(&advdata, &scanrsp, &options, on_adv_evt, NULL);
        if (err_code == NRF_SUCCESS) {
            advertising_start();
            NRF_LOG_DEBUG("Advertising restarted with new MSD\n");
        } else {
            NRF_LOG_WARNING("Failed to reinit advertising: 0x%X\n", err_code);
        }
    }
#endif
}

void gpiote_evt_handler(nrf_drv_gpiote_pin_t pin, nrf_gpiote_polarity_t action) {
    nrf_drv_gpiote_in_event_disable(pin);
    nrf_drv_gpiote_in_uninit(pin);
    nrf_drv_gpiote_uninit();
    advertising_start();
}

static void on_adv_evt(ble_adv_evt_t ble_adv_evt) {
    switch (ble_adv_evt) {
        case BLE_ADV_EVT_FAST:
            break;
        case BLE_ADV_EVT_IDLE:
            NRF_LOG_INFO("advertising timeout\n");
            break;
        default:
            break;
    }
}

static void on_ble_evt(ble_evt_t* p_ble_evt) {
    switch (p_ble_evt->header.evt_id) {
        case BLE_GAP_EVT_CONNECTED:
            NRF_LOG_INFO("CONNECTED\n");
            m_conn_handle = p_ble_evt->evt.gap_evt.conn_handle;
            break;

        case BLE_GAP_EVT_DISCONNECTED:
            NRF_LOG_INFO("DISCONNECTED\n");
            m_conn_handle = BLE_CONN_HANDLE_INVALID;
#if !defined(S112)
            advertising_start();
#endif
            break;
#if defined(S112)
        case BLE_GAP_EVT_PHY_UPDATE_REQUEST: {
        ble_gap_phys_t const phys = {
                .rx_phys = BLE_GAP_PHY_AUTO,
                .tx_phys = BLE_GAP_PHY_AUTO,
            };
            APP_ERROR_CHECK(sd_ble_gap_phy_update(p_ble_evt->evt.gap_evt.conn_handle, &phys));
        } break;
#endif
        case BLE_GAP_EVT_SEC_PARAMS_REQUEST:
            APP_ERROR_CHECK(
                sd_ble_gap_sec_params_reply(m_conn_handle, BLE_GAP_SEC_STATUS_PAIRING_NOT_SUPP, NULL, NULL));
            break;
        case BLE_GATTS_EVT_SYS_ATTR_MISSING:
            APP_ERROR_CHECK(sd_ble_gatts_sys_attr_set(m_conn_handle, NULL, 0, 0));
            break;
        case BLE_GATTC_EVT_TIMEOUT:
            APP_ERROR_CHECK(
                sd_ble_gap_disconnect(p_ble_evt->evt.gattc_evt.conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION));
            break;
        case BLE_GATTS_EVT_TIMEOUT:
            APP_ERROR_CHECK(
                sd_ble_gap_disconnect(p_ble_evt->evt.gatts_evt.conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION));
            break;
        default:
            // No implementation needed.
            break;
    }
}

#if defined(S112)
static void ble_evt_handler(ble_evt_t const* p_ble_evt, void* p_context) {
    UNUSED_PARAMETER(p_context);

    on_ble_evt((ble_evt_t*)p_ble_evt);
}

#else
static void ble_evt_dispatch(ble_evt_t* p_ble_evt) {
    ble_conn_params_on_ble_evt(p_ble_evt);
    ble_epd_on_ble_evt(&m_epd, p_ble_evt);
    on_ble_evt(p_ble_evt);
    ble_advertising_on_ble_evt(p_ble_evt);
    ble_dfu_on_ble_evt(&m_dfus, p_ble_evt);
}

static void sys_evt_dispatch(uint32_t sys_evt) {
    fs_sys_event_handler(sys_evt);
    ble_advertising_on_sys_evt(sys_evt);
}
#endif

static void ble_stack_init(void) {
#if defined(S112)
    APP_ERROR_CHECK(nrf_sdh_enable_request());
    uint32_t ram_start = 0;
    APP_ERROR_CHECK(nrf_sdh_ble_default_cfg_set(APP_BLE_CONN_CFG_TAG, &ram_start));
    APP_ERROR_CHECK(nrf_sdh_ble_enable(&ram_start));
    NRF_SDH_BLE_OBSERVER(m_ble_observer, APP_BLE_OBSERVER_PRIO, ble_evt_handler, NULL);
#else
    nrf_clock_lf_cfg_t clock_lf_cfg = NRF_CLOCK_LFCLKSRC;
    SOFTDEVICE_HANDLER_INIT(&clock_lf_cfg, NULL);
    ble_enable_params_t ble_enable_params;
    APP_ERROR_CHECK(
        softdevice_enable_get_default_config(CENTRAL_LINK_COUNT, PERIPHERAL_LINK_COUNT, &ble_enable_params));
    ble_enable_params.common_enable_params.vs_uuid_count = 2;
    CHECK_RAM_START_ADDR(CENTRAL_LINK_COUNT, PERIPHERAL_LINK_COUNT);
    APP_ERROR_CHECK(softdevice_enable(&ble_enable_params));
    APP_ERROR_CHECK(softdevice_ble_evt_handler_set(ble_evt_dispatch));
    APP_ERROR_CHECK(softdevice_sys_evt_handler_set(sys_evt_dispatch));
#endif
}

#if defined(S112)
void gatt_evt_handler(nrf_ble_gatt_t* p_gatt, nrf_ble_gatt_evt_t const* p_evt) {
    if ((m_conn_handle == p_evt->conn_handle) && (p_evt->evt_id == NRF_BLE_GATT_EVT_ATT_MTU_UPDATED)) {
        m_epd.max_data_len = p_evt->params.att_mtu_effective - 3;
    }
}

void gatt_init(void) {
    APP_ERROR_CHECK(nrf_ble_gatt_init(&m_gatt, gatt_evt_handler));
    APP_ERROR_CHECK(nrf_ble_gatt_att_mtu_periph_set(&m_gatt, NRF_SDH_BLE_GATT_MAX_MTU_SIZE));
}
#else

static void ble_options_set(void) {
    ble_opt_t ble_opt;
    memset(&ble_opt, 0, sizeof(ble_opt));
    ble_opt.common_opt.conn_bw.role = BLE_GAP_ROLE_PERIPH;
    ble_opt.common_opt.conn_bw.conn_bw.conn_bw_rx = BLE_CONN_BW_HIGH;
    ble_opt.common_opt.conn_bw.conn_bw.conn_bw_tx = BLE_CONN_BW_HIGH;
    APP_ERROR_CHECK(sd_ble_opt_set(BLE_COMMON_OPT_CONN_BW, &ble_opt));
}
#endif

static void advertising_init(void) {
#if defined(S112)
    ble_advertising_init_t init;
    ble_advdata_manuf_data_t manuf_data;
    memset(&init, 0, sizeof(init));
    init.advdata.name_type = BLE_ADVDATA_FULL_NAME;
    init.advdata.include_appearance = false;
    init.advdata.flags = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
    manuf_data.company_identifier = (uint16_t)msd_payload[0] | ((uint16_t)msd_payload[1] << 8);
    manuf_data.data.p_data = msd_payload + 2;
    manuf_data.data.size = sizeof(msd_payload) - 2;  // 14 bytes (skip company ID)
    init.advdata.p_manuf_specific_data = &manuf_data;
    init.srdata.uuids_complete.uuid_cnt = sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]);
    init.srdata.uuids_complete.p_uuids = m_adv_uuids;
    init.config.ble_adv_fast_enabled = true;
    init.config.ble_adv_fast_interval = APP_ADV_INTERVAL;
    init.config.ble_adv_fast_timeout = APP_ADV_TIMEOUT_IN_SECONDS * 100;
    init.evt_handler = on_adv_evt;
    APP_ERROR_CHECK(ble_advertising_init(&m_advertising, &init));
    ble_advertising_conn_cfg_tag_set(&m_advertising, APP_BLE_CONN_CFG_TAG);
#else
    ble_advdata_t advdata;
    ble_advdata_t scanrsp;
    ble_adv_modes_config_t options;
    ble_advdata_manuf_data_t manuf_data;
    memset(&advdata, 0, sizeof(advdata));
    advdata.name_type = BLE_ADVDATA_FULL_NAME;
    advdata.include_appearance = false;
    advdata.flags = BLE_GAP_ADV_FLAGS_LE_ONLY_GENERAL_DISC_MODE;
    manuf_data.company_identifier = (uint16_t)msd_payload[0] | ((uint16_t)msd_payload[1] << 8);
    manuf_data.data.p_data = msd_payload + 2;
    manuf_data.data.size = sizeof(msd_payload) - 2;  // 14 bytes (skip company ID)
    advdata.p_manuf_specific_data = &manuf_data;
    memset(&scanrsp, 0, sizeof(scanrsp));
    scanrsp.uuids_complete.uuid_cnt = sizeof(m_adv_uuids) / sizeof(m_adv_uuids[0]);
    scanrsp.uuids_complete.p_uuids = m_adv_uuids;
    memset(&options, 0, sizeof(options));
    options.ble_adv_fast_enabled = true;
    options.ble_adv_fast_interval = APP_ADV_INTERVAL;
    options.ble_adv_fast_timeout = APP_ADV_TIMEOUT_IN_SECONDS;
    APP_ERROR_CHECK(ble_advertising_init(&advdata, &scanrsp, &options, on_adv_evt, NULL));
#endif
}

static void log_init(void) {
    APP_ERROR_CHECK(NRF_LOG_INIT(timestamp));
#if defined(S112)
    NRF_LOG_DEFAULT_BACKENDS_INIT();
#endif
}

static void power_management_init(void) {
#if defined(S112)
    APP_ERROR_CHECK(nrf_pwr_mgmt_init());
#else
    APP_ERROR_CHECK(nrf_pwr_mgmt_init(APP_TIMER_TICKS(1000, APP_TIMER_PRESCALER)));
#endif
}

#ifndef BOOTLOADER_DFU_START
#define BOOTLOADER_DFU_START 0xB1
#endif

void enter_dfu_mode(void) {
    NRF_LOG_INFO("Entering DFU bootloader mode");
    NRF_LOG_FINAL_FLUSH();
    if (m_conn_handle != BLE_CONN_HANDLE_INVALID) {
        sd_ble_gap_disconnect(m_conn_handle, BLE_HCI_REMOTE_USER_TERMINATED_CONNECTION);
        nrf_delay_ms(200);
    }

#if defined(S112)
    sd_power_gpregret_clr(0, 0xFFFFFFFF);
    sd_power_gpregret_set(0, BOOTLOADER_DFU_START);
#else
    NRF_POWER->GPREGRET = BOOTLOADER_DFU_START;
#endif

    nrf_delay_ms(100);
    NVIC_SystemReset();
}

bool is_ble_active(void) {
    return (m_conn_handle != BLE_CONN_HANDLE_INVALID);
}

static void idle_state_handle(void) {
    app_feed_wdt();
    static uint32_t last_msd_update = 0;
    static bool first_update = true;
    if (m_conn_handle == BLE_CONN_HANDLE_INVALID) {
        if (first_update) {
            last_msd_update = m_timestamp;
            first_update = false;
        }
        if ((m_timestamp - last_msd_update) >= MSD_UPDATE_INTERVAL_SEC) {
            updatemsdata();
            advertising_restart_with_updated_msd();
            last_msd_update = m_timestamp;
        }
    } else {
        first_update = true;
    }
    process_button_events();
    if (NRF_LOG_PROCESS() == false) {
        nrf_pwr_mgmt_run();
    }
}

void wdt_event_handler(void) {
    NRF_LOG_ERROR("WDT Rest!\r\n");
    NRF_LOG_FINAL_FLUSH();
}

int main(void) {
    log_init();
    m_resetreas = NRF_POWER->RESETREAS;
    NRF_POWER->RESETREAS |= NRF_POWER->RESETREAS;
    NRF_LOG_DEBUG("init..\n");
    nrf_drv_wdt_config_t config = NRF_DRV_WDT_DEAFULT_CONFIG;
    APP_ERROR_CHECK(nrf_drv_wdt_init(&config, wdt_event_handler));
    APP_ERROR_CHECK(nrf_drv_wdt_channel_alloc(&m_wdt_channel_id));
    nrf_drv_wdt_enable();
    timers_init();
    power_management_init();
    ble_stack_init();
    scheduler_init();
    gap_params_init();
#if defined(S112)
    gatt_init();
    ble_dfu_buttonless_async_svci_init();
#else
    ble_options_set();
#endif
    bool config_loaded = loadGlobalConfig(&globalConfig);
    if (!config_loaded) {
        NRF_LOG_INFO("No config found - using defaults");
    }
    encryption_init();
    checkResetPin();
    updatemsdata();
    led_init();
    button_init();
    if (globalConfig.display_count > 0) {
        m_epd.display_config = &globalConfig.displays[0];
        NRF_LOG_INFO("Display config set: panel_ic_type=0x%04X", m_epd.display_config->panel_ic_type);
    } else {
        m_epd.display_config = NULL;
        NRF_LOG_INFO("No display config - display features disabled");
    }
    m_epd.global_config = &globalConfig;
    services_init();
    advertising_init();
    conn_params_init();
    application_timers_start();
    advertising_start();
    if (m_epd.display_config != NULL && m_epd.display_config->panel_ic_type != 0) {
        NRF_LOG_INFO("Initializing EPD: panel_ic=0x%04X", m_epd.display_config->panel_ic_type);
        EPD_GPIO_Load_DisplayConfig(m_epd.display_config, m_epd.global_config);
        NRF_LOG_INFO("EPD pins: DATA=%d CLK=%d CS=%d DC=%d", 
                     m_epd.display_config->data_pin, m_epd.display_config->clk_pin, 
                     m_epd.display_config->cs_pin, m_epd.display_config->dc_pin);
        NRF_LOG_INFO("EPD pins: RST=%d BUSY=%d BS=13", 
                     m_epd.display_config->reset_pin, m_epd.display_config->busy_pin);
        epd_model_id_t model_id = map_panel_ic_to_model_id(m_epd.display_config->panel_ic_type, m_epd.display_config->color_scheme);
        NRF_LOG_INFO("EPD model_id=%d", model_id);
        NRF_LOG_INFO("Initializing GPIO...");
        EPD_GPIO_Init();
        NRF_LOG_INFO("Calling epd_init...");
        m_epd.epd = epd_init(model_id);
        if (m_epd.epd) {
            NRF_LOG_INFO("EPD initialized successfully");
            if ((m_epd.display_config->transmission_modes & (1 << 7)) != 0) {
                NRF_LOG_INFO("CLEAR_ON_BOOT enabled - clearing display");
                m_epd.epd->drv->clear(m_epd.epd, true);
            }
            NRF_LOG_INFO("Putting EPD to sleep and uninitializing GPIO for power saving");
            m_epd.epd->drv->sleep(m_epd.epd);
            nrf_delay_ms(EPD_SLEEP_DELAY_MS);
            EPD_GPIO_Uninit();
        } else {
            NRF_LOG_ERROR("EPD init failed - returned NULL");
            EPD_GPIO_Uninit();
        }
    } else {
        NRF_LOG_INFO("Skipping EPD initialization: no display config found");
    }

    for (;;) {
        app_sched_execute();
        idle_state_handle();
    }
}
