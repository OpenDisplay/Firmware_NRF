/* od_log.h -- allocation-free, complete-record application logging. */

#ifndef OD_LOG_H
#define OD_LOG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define OD_LOG_ERROR 0
#define OD_LOG_WARN  1
#define OD_LOG_INFO  2
#define OD_LOG_DEBUG 3

#ifndef OD_CAP_LOG
#define OD_CAP_LOG 1
#endif

#ifndef OD_LOG_LEVEL
#define OD_LOG_LEVEL OD_LOG_INFO
#endif

#if OD_CAP_LOG
#define OD_LOG_EFFECTIVE_LEVEL OD_LOG_LEVEL
#else
#define OD_LOG_EFFECTIVE_LEVEL (-1)
#endif

/* Keep the test inside the macro: disabled arguments still compile, but are not evaluated. */
#define od_log_error(fmt, ...) do { if (OD_LOG_EFFECTIVE_LEVEL >= OD_LOG_ERROR) \
    _od_log(OD_LOG_ERROR, fmt, ##__VA_ARGS__); } while (0)
#define od_log_warn(fmt, ...)  do { if (OD_LOG_EFFECTIVE_LEVEL >= OD_LOG_WARN) \
    _od_log(OD_LOG_WARN, fmt, ##__VA_ARGS__); } while (0)
#define od_log_info(fmt, ...)  do { if (OD_LOG_EFFECTIVE_LEVEL >= OD_LOG_INFO) \
    _od_log(OD_LOG_INFO, fmt, ##__VA_ARGS__); } while (0)
#define od_log_debug(fmt, ...) do { if (OD_LOG_EFFECTIVE_LEVEL >= OD_LOG_DEBUG) \
    _od_log(OD_LOG_DEBUG, fmt, ##__VA_ARGS__); } while (0)

void od_log_init(void);
void _od_log(int level, const char *fmt, ...) __attribute__((format(printf, 2, 3)));
void od_log_raw(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
void od_log_flush(void);

/* The target transports do not expose comparable delivery accounting. */
uint32_t od_log_dropped_total(void);

void od_log_hex_line(char *buf, size_t buf_size, const char *label,
                     const uint8_t *data, uint16_t len);

#ifdef __cplusplus
}
#endif

#endif
