/* host stub: the capture records delays instead of waiting */
#pragma once
#include <stdint.h>
void rec_delay(uint32_t ms);
#define nrf_delay_ms(ms) rec_delay(ms)
