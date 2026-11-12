/* od_nrf_bootguard.c -- keep a broken application from stranding a unit outside DFU.
 *
 * HOW THE BOOTLOADER DECIDES. The Secure DFU bootloader at 0x29000 stays in DFU when GPREGRET
 * reads 0xB0..0xB7 (BOOTLOADER_DFU_GPREGRET with the START bit, the value CMD_ENTER_DFU writes),
 * when the application image is invalid (bank 0 not valid / CRC mismatch in the settings page), or
 * when the settings page requests buttonless DFU. It times out of DFU after inactivity and starts
 * a valid application again, so entering DFU is a window, not a trap.
 *
 * WHAT CAN STILL STRAND A UNIT. A valid image that cannot reach a served GATT request: the BLE
 * stack failing to come up (APP_ERROR_CHECK resets, forever), or a crash or watchdog reset early
 * in every boot. The bootloader sees a valid image each time and never offers DFU.
 *
 * THE RULE. GPREGRET survives soft, watchdog and lockup resets (not a power cycle). The low byte
 * counts boots as 0x50 | n. A served GATT write, or 30 minutes of uptime, clears it. A boot that
 * finds n == OD_BOOTGUARD_MAX_BOOTS - 1 already counted enters DFU instead of starting the app.
 * 0x50..0x5F never matches the bootloader's 0xB0 mask, and a power cycle starts the count over.
 */
#include "od_nrf_glue.h"

#include "nrf.h"
#include "nrf_soc.h"

#ifndef OD_BOOTGUARD_MAX_BOOTS
#define OD_BOOTGUARD_MAX_BOOTS 5u
#endif
#define OD_BOOTGUARD_TAG   0x50u
#define OD_BOOTGUARD_DFU   0xB1u   /* BOOTLOADER_DFU_START */

/* Pure: the next GPREGRET value for a boot that found `prev`. Host-tested. */
uint8_t od_nrf_bootguard_next(uint8_t prev, bool *enter_dfu)
{
    uint8_t n = ((prev & 0xF0u) == OD_BOOTGUARD_TAG) ? (uint8_t)(prev & 0x0Fu) : 0u;

    n = (uint8_t)(n + 1u);
    if (n >= OD_BOOTGUARD_MAX_BOOTS) {
        *enter_dfu = true;
        return OD_BOOTGUARD_DFU;
    }
    *enter_dfu = false;
    return (uint8_t)(OD_BOOTGUARD_TAG | n);
}

#ifndef OD_BOOTGUARD_HOST_TEST
static bool s_cleared;

/* Before the SoftDevice is enabled, so POWER is still directly writable. */
void od_nrf_bootguard_boot(void)
{
    bool dfu = false;
    const uint8_t next = od_nrf_bootguard_next((uint8_t)NRF_POWER->GPREGRET, &dfu);

    NRF_POWER->GPREGRET = next;
    if (dfu) {
        NVIC_SystemReset();
    }
}

/* With the SoftDevice enabled: through its POWER API. */
void od_nrf_bootguard_served(void)
{
    if (!s_cleared) {
        s_cleared = true;
        (void)sd_power_gpregret_clr(0, 0xFFu);
    }
}

void od_nrf_bootguard_stack_failed(void)
{
    NRF_POWER->GPREGRET = OD_BOOTGUARD_DFU;
    NVIC_SystemReset();
}
#endif
