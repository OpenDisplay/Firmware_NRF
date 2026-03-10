#ifndef __CONFIG_PARSER_H
#define __CONFIG_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include "structs.h"

bool parseConfigBytes(uint8_t* configData, uint32_t configLen, struct GlobalConfig* globalConfig);

bool loadGlobalConfig(struct GlobalConfig* globalConfig);

#endif // __CONFIG_PARSER_H
