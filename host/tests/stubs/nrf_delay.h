/* Host test: nrf_delay_ms records instead of spinning. */
#ifndef HOST_NRF_DELAY_H
#define HOST_NRF_DELAY_H
#include <stdint.h>
void host_delay_ms(uint32_t ms);
#define nrf_delay_ms(ms) host_delay_ms(ms)
#define nrf_delay_us(us) ((void)(us))
#endif
