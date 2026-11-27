#ifndef OD_BOOT_APP_H
#define OD_BOOT_APP_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OD_BOOT_PLANE_PRIMARY 0
#define OD_BOOT_PLANE_SECOND 1

int od_boot_app_begin_frame(uint16_t width, uint16_t height, uint8_t segments);
int od_boot_app_begin_plane(int plane);
int od_boot_app_write_row(uint16_t y, uint8_t segment, const uint8_t *row, uint16_t len);
int od_boot_app_end_plane(int plane);
int od_boot_app_end_frame(void);

int od_boot_app_bits_per_pixel(uint8_t color_scheme);
int od_boot_app_default_plane(uint8_t color_scheme);
bool od_boot_app_direct_2bpp(void);
uint8_t od_boot_app_segments(void);
uint32_t od_boot_app_device_id24(void);
void od_boot_app_firmware_version(uint8_t *major, uint8_t *minor, uint8_t *patch);
float od_boot_app_battery_volts(void);
float od_boot_app_chip_temp_c(void);

#ifdef __cplusplus
}
#endif

#endif
