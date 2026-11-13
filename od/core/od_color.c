#include "od_color.h"

#include <limits.h>
#include <string.h>

static bool part_geometry(uint32_t width, uint32_t height, uint8_t bits_per_pixel,
                          uint32_t *row_bytes, uint32_t *part_bytes)
{
  uint64_t row_bits = (uint64_t)width * bits_per_pixel;
  uint64_t row = (row_bits + 7u) / 8u;
  uint64_t part = row * height;

  if (row > UINT32_MAX || part > UINT32_MAX) {
    return false;
  }
  *row_bytes = (uint32_t)row;
  *part_bytes = (uint32_t)part;
  return true;
}

od_color_status_t od_color_direct_geometry(uint8_t color_scheme, uint32_t width, uint32_t height,
                                           od_color_geometry_t *geometry)
{
  od_color_geometry_t out;
  uint64_t total;

  if (geometry == NULL) {
    return OD_COLOR_BAD_GEOMETRY;
  }
  memset(geometry, 0, sizeof(*geometry));
  if (width == 0u || height == 0u) {
    return OD_COLOR_BAD_GEOMETRY;
  }
  memset(&out, 0, sizeof(out));

  switch (color_scheme) {
    case OD_COLOR_SCHEME_MONO:
      out.layout = OD_COLOR_LAYOUT_PACKED_ROWS;
      out.bits_per_pixel = 1u;
      out.part_count = 1u;
      out.initial_plane = OD_COLOR_PLANE_0;
      out.partial_supported = true;
      out.part_width[0] = width;
      break;

    case OD_COLOR_SCHEME_BWR:
    case OD_COLOR_SCHEME_BWY:
    case OD_COLOR_SCHEME_GRAY4:
      out.layout = OD_COLOR_LAYOUT_CONTROLLER_PLANES;
      out.bits_per_pixel = 1u;
      out.part_count = 2u;
      out.initial_plane = OD_COLOR_PLANE_0;
      out.part_width[0] = width;
      out.part_width[1] = width;
      break;

    /* BWRY16 packs IDENTICALLY to BWRY: 2bpp, one plane, ONE frame. The 16 colours come from
     * driving that frame several times with different per-pass pixel codes, and the pass count
     * is a property of the display_mode (0xAE), not of the scheme. So this answers the geometry
     * of a SINGLE pass; multiplying by the pass count belongs to the drive path, which is the
     * only place that knows which mode was named.
     *
     * Sharing the arm rather than copying it is deliberate -- a host dithering for BWRY16 and a
     * device packing for BWRY have to agree byte for byte, so the two must not be able to drift.
     * `partial_supported` stays false for both: a partial update of one pass of a multi-pass
     * waveform is not a defined operation. */
    case OD_COLOR_SCHEME_BWRY:
    case OD_COLOR_SCHEME_BWRY16:
      out.layout = OD_COLOR_LAYOUT_PACKED_ROWS;
      out.bits_per_pixel = 2u;
      out.part_count = 1u;
      out.initial_plane = OD_COLOR_PLANE_1;
      out.part_width[0] = width;
      break;

    case OD_COLOR_SCHEME_BWGBRY:
    case OD_COLOR_SCHEME_SEVEN_COLOR:
      out.layout = OD_COLOR_LAYOUT_PACKED_ROWS;
      out.bits_per_pixel = 4u;
      out.part_count = 1u;
      out.initial_plane = OD_COLOR_PLANE_1;
      out.part_width[0] = width;
      break;

    case OD_COLOR_SCHEME_GRAY16:
      out.layout = OD_COLOR_LAYOUT_PACKED_ROWS;
      out.bits_per_pixel = 4u;
      out.part_count = 1u;
      out.initial_plane = OD_COLOR_PLANE_0;
      out.part_width[0] = width;
      break;

    case OD_COLOR_SCHEME_BWGBRY_SPLIT:
      out.layout = OD_COLOR_LAYOUT_SPLIT_HALVES;
      out.bits_per_pixel = 4u;
      out.part_count = 2u;
      out.initial_plane = OD_COLOR_PLANE_NONE;
      out.part_width[0] = width / 2u;
      out.part_width[1] = width - out.part_width[0];
      break;

    case OD_COLOR_SCHEME_GRAY8:
    case OD_COLOR_SCHEME_RGB565:
    case OD_COLOR_SCHEME_RGB888:
    case OD_COLOR_SCHEME_RGB16BPC:
    default:
      return OD_COLOR_UNSUPPORTED;
  }

  if (!part_geometry(out.part_width[0], height, out.bits_per_pixel, &out.row_bytes[0],
                     &out.part_bytes[0])) {
    return OD_COLOR_OVERFLOW;
  }
  if (out.part_count == 2u
      && !part_geometry(out.part_width[1], height, out.bits_per_pixel, &out.row_bytes[1],
                        &out.part_bytes[1])) {
    return OD_COLOR_OVERFLOW;
  }
  total = (uint64_t)out.part_bytes[0] + out.part_bytes[1];
  if (total > UINT32_MAX) {
    return OD_COLOR_OVERFLOW;
  }
  out.total_bytes = (uint32_t)total;
  *geometry = out;
  return OD_COLOR_OK;
}
