#ifndef OD_COLOR_H
#define OD_COLOR_H

#include <stdbool.h>
#include <stdint.h>

#include "opendisplay_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Firmware-local compatibility placeholder. The canonical protocol repository does not yet
 * carry value 9, and this implementation deliberately does not change that sibling repository.
 * The preprocessor cannot detect C enum members, so a future canonical reservation requires
 * removing this fallback after the vendored header is synced; the numeric identity stays 9. */
#ifndef OD_COLOR_SCHEME_GRAY8
#define OD_COLOR_SCHEME_GRAY8 ((uint8_t)9u)
#endif

typedef enum {
  OD_COLOR_OK = 0,
  OD_COLOR_UNSUPPORTED,
  OD_COLOR_BAD_GEOMETRY,
  OD_COLOR_OVERFLOW,
} od_color_status_t;

typedef enum {
  OD_COLOR_LAYOUT_PACKED_ROWS = 0,
  OD_COLOR_LAYOUT_CONTROLLER_PLANES,
  OD_COLOR_LAYOUT_SPLIT_HALVES,
} od_color_layout_t;

typedef enum {
  OD_COLOR_PLANE_0 = 0,
  OD_COLOR_PLANE_1 = 1,
  OD_COLOR_PLANE_NONE = 0xff,
} od_color_plane_t;

typedef struct {
  od_color_layout_t layout;
  uint8_t bits_per_pixel;
  uint8_t part_count;
  od_color_plane_t initial_plane;
  bool partial_supported;
  uint32_t part_width[2];
  uint32_t row_bytes[2];
  uint32_t part_bytes[2];
  uint32_t total_bytes;
} od_color_geometry_t;

/* Describe an implemented direct-write byte stream. Reserved GRAY8 value 9 is a valid
 * classification identity but intentionally returns OD_COLOR_UNSUPPORTED: it has no wire
 * packing, FastEPD adapter, boot fallback, or target admission in this implementation. */
od_color_status_t od_color_direct_geometry(uint8_t color_scheme, uint32_t width, uint32_t height,
                                           od_color_geometry_t *geometry);

#ifdef __cplusplus
}
#endif

#endif
