#ifndef _MAIN_H_
#define _MAIN_H_

#include <stdint.h>

uint32_t timestamp(void);
void set_timestamp(uint32_t timestamp);
void sleep_mode_enter(void);
void app_feed_wdt(void);
void updatemsdata(void);
void get_msd_payload(uint8_t* out, uint8_t max_len, uint8_t* out_len);
void getChipIdHex(char* buffer, uint8_t buffer_size);
extern uint8_t rebootFlag;
bool is_ble_active(void);
void advertising_restart_with_updated_msd(void);
void enter_dfu_mode(void);
void enter_deep_sleep(void);

#endif
