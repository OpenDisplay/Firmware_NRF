/* od_claim_app.h -- what claim mode, the factory reset and the config policy need from the
 * target, as link-time functions (SECURITY_V2 sections 7, 10; FACTORY_RESET.md).
 *
 * CONTEXT: main loop / boot only. None of these may call back into od_claim_mode,
 * od_factory_reset or od_cfg_policy. A host test defines them all itself.
 */
#ifndef OD_CLAIM_APP_H
#define OD_CLAIM_APP_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------------- screens --- */

/* The firmware-drawn setup screen family (SECURITY_V2 section 7.8). NORMAL is the ordinary
 * boot screen and is never requested through this header. */
enum od_setup_screen {
    OD_SETUP_SCREEN_NORMAL = 0,
    OD_SETUP_SCREEN_SETUP  = 1,   /* claim mode, no claim yet: "SETUP MODE", id, QR /l/?f=1&k=1 */
    OD_SETUP_SCREEN_CODE   = 2,   /* a claim is pending: "CLAIM CODE", the 6 digits, id */
    OD_SETUP_SCREEN_RESET  = 3    /* factory reset, before the erase: "FACTORY RESET", QR /l/?f=1&k=2 */
};

/* Draw one screen of the family through the boot-screen path in display mode 0, from the config
 * as it is stored now. `code` is the 0..999999 claim code (CODE only). Fixed firmware text only:
 * nothing from 0x2C or any other config string. Returns false when nothing could be drawn (no
 * display, mode 0 not drawable, panel error). MAY BLOCK for the refresh (BG22); the caller has
 * already flushed any reply that must leave first. */
bool od_claim_app_draw(enum od_setup_screen kind, uint32_t code);

/* --------------------------------------------------------------- LED / buzzer patterns --- */

enum od_claim_signal {
    OD_CLAIM_SIG_NONE = 0,
    OD_CLAIM_SIG_CM_WAITING,      /* claim mode, waiting: double blink every 2 s; two short beeps at entry */
    OD_CLAIM_SIG_CM_CODE,         /* a code is shown: double blink every 1 s */
    OD_CLAIM_SIG_CM_CLAIMED,      /* 3 long flashes; one long beep */
    OD_CLAIM_SIG_PATTERN_COUNT,   /* a quick power-cycle was counted; arg = cycles so far: arg short blinks */
    OD_CLAIM_SIG_FR_HOLDING,      /* reset pin held, < 5 s: blink 1 Hz */
    OD_CLAIM_SIG_FR_RELEASE_NOW,  /* hold threshold reached: solid on; one short beep */
    OD_CLAIM_SIG_FR_ERASING,      /* blink 5 Hz */
    OD_CLAIM_SIG_FR_DONE,         /* 3 long flashes; two beeps */
    OD_CLAIM_SIG_FR_STUCK,        /* 3 slow blinks */
    OD_CLAIM_SIG_FR_LOCKED        /* SOS once; three long beeps */
};

/* Start (or replace) an indicator pattern on the first LED of 0x21 / the buzzer of 0x29, if the
 * config has them. A continuous pattern (CM_WAITING, CM_CODE, FR_HOLDING, FR_ERASING) runs until
 * the next call; OD_CLAIM_SIG_NONE stops it. A no-op is a correct implementation (a target may
 * implement a subset to save flash: the panel is the primary signal). Must not block for long. */
void od_claim_app_signal(enum od_claim_signal sig, uint8_t arg);

/* ---------------------------------------------------------------------- reset pin --- */

/* Configure `pin` (0x27 reset_pin, in this target's binary-input pin encoding, FACTORY_RESET.md
 * section 2) as an input with the given pulls. false = the pin is not valid on this board. */
bool od_claim_app_pin_input(uint8_t pin, bool pull_up, bool pull_down);

/* Raw level of `pin`: 1 high, 0 low, < 0 error. */
int od_claim_app_pin_read(uint8_t pin);

/* Busy-wait `ms` milliseconds and feed the watchdog. Used only at boot, before the radio. */
void od_claim_app_wait_ms(uint32_t ms);

/* ------------------------------------------------------------------ factory reset --- */

/* R5a: erase every image-store slot. true when done, or when no store is configured / mounts. */
bool od_claim_app_erase_images(void);

/* R5b: erase BLE bonds and target extras kept outside the config (BG22 FMDN runtime objects).
 * true when done or when there is nothing to erase. */
bool od_claim_app_erase_bonds(void);

/* Scrub step 2/3 (SECURITY_V2 section 10.4): erase secrets the target keeps outside the config
 * record (ESP32 nvs.net80211). true when done or when there is nothing to erase. */
bool od_claim_app_scrub_extras(void);

/* SECURITY_V2 section 10.4a: destroy every SUPERSEDED copy of every record in the target's
 * persistent key/config storage, keeping each live record. NVS (ESP32), NVM3 (BG22) and Zephyr
 * NVS (Nordic) are log-structured: an overwrite or a delete leaves the old bytes readable in
 * flash until their page is reclaimed, so a scrubbed WiFi password or an erased key survives a
 * USB/SWD read-out without this. Called at boot only, before the radio, from od_security_boot()
 * when OS2S carries OD_SEC2_OS2S_PURGE. May take a few seconds of flash work.
 *
 * Power cuts: a target that compacts in place (BG22, Nordic: the medium's own garbage collection,
 * which never drops a live record) leaves everything live; one that erases and rewrites (ESP32)
 * may leave a blank medium, which boots as a virgin device -- acceptable because the callers are
 * UNCLAIM and the factory reset, after which the device is unclaimed and holds no secret.
 * true = done; false = not done (the flag stays and the next boot retries). */
bool od_claim_app_storage_purge(void);

/* ----------------------------------------------------------------- config workspace --- */

/* A workspace of at least OD_CONFIG_STORE_MAX_RECORD bytes that the config policy may use for
 * one load-modify-save, from the loop, while no config write is being assembled into it. BG22
 * returns its config assembler (the policy cancels nothing: a rewrite during an assembly is
 * refused by the caller's state). *cap receives its size. */
uint8_t *od_claim_app_workspace(uint32_t *cap);

/* True while a config write is being assembled into od_claim_app_workspace() (chunked write in
 * progress). The policy then refuses its own rewrites (STORAGE_ERROR to the caller), so it never
 * tramples a half-assembled blob. */
bool od_claim_app_workspace_busy(void);

/* The config is about to be re-read from storage by the target, or was just changed by the
 * policy (scrub, 0x27 rewrite at rest): reload the parsed config the target keeps. May be a
 * no-op where the next boot is soon enough (it is: claim mode ends in a reboot). */
void od_claim_app_config_changed(void);

#ifdef __cplusplus
}
#endif

#endif /* OD_CLAIM_APP_H */
