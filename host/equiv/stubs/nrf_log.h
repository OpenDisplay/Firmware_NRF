/* host stub: logging was compiled out in the shipped 2.x build (NRF_LOG_ENABLED 0), and its
 * arguments were never evaluated -- so SSD16xx_Refresh's ReadTemp did not run. Same here. */
#pragma once
#define NRF_LOG_DEBUG(...) do { } while (0)
#define NRF_LOG_INFO(...) do { } while (0)
