/* od_nrf_glue.h -- what this firmware's own code calls in the glue between it and the shared
 * OpenDisplay 3.0 chain under od/. Nothing here is part of the shared API. */
#ifndef OD_NRF_GLUE_H
#define OD_NRF_GLUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "od_config_asm.h"
#include "structs.h"

/* SECURITY_V2 13.7: a build without the security module refuses secrets with this code. The value
 * is defined in shared/core/od_sec2_wire.h, which this build does not vendor. */
#ifndef OD_ERR_CONFIG_SECRET_NEEDS_CLAIM
#define OD_ERR_CONFIG_SECRET_NEEDS_CLAIM 0x10u
#endif

/* ---- platform hooks the glue needs from main.c ------------------------------------------- */
void od_nrf_pump_events(void);          /* nrf_sdh_evts_poll() */
void od_nrf_wdt_feed_now(void);         /* unconditional watchdog feed */
void od_nrf_delay_ms(uint32_t ms);      /* busy delay that keeps the watchdog fed */
uint32_t od_nrf_now_ms(void);           /* monotonic milliseconds from RTC1 */
float od_nrf_chip_temp_c(void);         /* die temperature, -999 if unreadable */
uint16_t od_nrf_battery_mv(void);

/* ---- config --------------------------------------------------------------------------------- */
/* The single config workspace: chunk assembly, the record image for od_config_store_save() and
 * the boot-time load all share it. 16 B header + OD_CONFIG_MAX_SIZE. */
extern struct od_config_asm g_od_cfg_ws;

/* Loads the stored config into `g` and binds display 0. false = no usable config. */
bool od_nrf_config_load(struct GlobalConfig *g);
/* true = acceptable. false: *err is the 3.0 error byte for [FF][41|42][err][00] (0x00, the
 * generic CONFIG_WRITE_FAILED, is a valid error, so it cannot double as "accepted"). */
bool od_nrf_config_check(const uint8_t *blob, uint32_t len, uint8_t *err);
/* Parse a blob into `g` (the 3.0 TLV walk; 0x80+ packets are skipped by their length). */
bool od_nrf_config_parse(const uint8_t *blob, uint32_t len, struct GlobalConfig *g);

/* ---- display state, cached at config load so interrupt-context readers never touch the
 *      drive index while a refresh is using it ---------------------------------------------- */
bool od_nrf_display_configured(void);   /* a 0x20 display exists */
bool od_nrf_display_drivable(void);     /* ... and it has drive packets (0xB1 + mode 0) */
void od_nrf_bind_display(const struct GlobalConfig *g);
void od_nrf_boot_screen(void);          /* draw the boot screen if drivable; blocks */

/* ---- 3.0 replies built by the glue ---------------------------------------------------------- */
uint16_t od_nrf_ident(uint8_t *out, uint16_t cap);              /* READ_IDENT frame */
void od_nrf_msd(uint8_t out[16], uint8_t loop_counter, bool reboot_flag);

/* ---- DFU strand guard (od_nrf_bootguard.c) -------------------------------------------------- */
uint8_t od_nrf_bootguard_next(uint8_t prev, bool *enter_dfu);   /* pure */
void od_nrf_bootguard_boot(void);        /* early in main(): count this boot */
void od_nrf_bootguard_served(void);      /* a GATT request was served: the app is healthy */
void od_nrf_bootguard_stack_failed(void);/* BLE stack init failed: go to DFU */

#endif /* OD_NRF_GLUE_H */
