#ifndef BOOT_SCREEN_H
#define BOOT_SCREEN_H

#include <stdbool.h>
#include "structs.h"
#include "EPD/EPD_driver.h"

// Render a boot screen with a landing-page QR code plus human-readable name/key.
// Does not allocate a full framebuffer; streams rows directly to the panel.
bool boot_screen_render(epd_model_t* epd, const struct GlobalConfig* cfg);

#endif

