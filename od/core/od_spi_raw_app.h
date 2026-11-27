/* Target seam for the shared CMD_SPI_RAW handler (shared/core/od_cmd_spi_raw.c).
 *
 * Every function returns 0 or an OD_ERR_SPI_RAW_* code negated. The session persists across
 * commands until CLOSE, a re-OPEN, or the target's transfer abort path (a BLE disconnect)
 * tears it down.
 */
#ifndef OD_SPI_RAW_APP_H
#define OD_SPI_RAW_APP_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int  opendisplay_display_spi_raw_open(bool run_panel_init);
int  opendisplay_display_spi_raw_cmd(const uint8_t *data, uint16_t len);
int  opendisplay_display_spi_raw_data(const uint8_t *data, uint16_t len);
int  opendisplay_display_spi_raw_busy(uint32_t timeout_ms, uint16_t *elapsed_ms_out,
                                      bool *still_busy_out);
int  opendisplay_display_spi_raw_reset(uint8_t hold_ms);
void opendisplay_display_spi_raw_close(void);
bool opendisplay_display_spi_raw_is_open(void);

#ifdef __cplusplus
}
#endif

#endif /* OD_SPI_RAW_APP_H */
