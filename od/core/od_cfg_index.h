/* od_cfg_index -- a MAP of the stored config, not a copy of it.
 *
 * The drive packets are too big to keep resident: a single waveform is 539 bytes and a BG22
 * carries 32 KB of RAM in total. So this keeps one 6-byte entry per indexed packet -- the
 * 0xAE-0xB2 range; legacy (< 0x80) packets are stepped over, never recorded -- what it is,
 * which instance, where its body starts and how long it is -- and anything that needs bytes
 * reads them on demand through od_hal_nvs, which takes a read offset for exactly this reason.
 * 32 entries is 192 bytes.
 *
 * THE MEDIUM IS THE SOURCE OF TRUTH, NOT A BUFFER. Indexing the config assembler's workspace
 * would be cheaper -- the payload is already sitting there after a load -- but that buffer is
 * reused while a client is writing a new config, so a read during an upload would return
 * bytes from a half-assembled record. Wrong bytes, not a failure. Reading through the HAL
 * cannot do that.
 *
 * WHY AN INDEX AND NOT A RE-WALK. Re-walking means re-reading and re-parsing for every field,
 * and the walk has to stop at the first unknown legacy id. An index is built once, so a later
 * lookup is a bounds check and one partial read.
 *
 * THE ENTRIES ARE OFFSETS, SO THEY GO STALE. Rebuild after any config write. Two configs that
 * both carry drive packets will resolve old offsets to plausible-looking wrong bytes rather
 * than to an error.
 */
#ifndef OD_CFG_INDEX_H
#define OD_CFG_INDEX_H

#include <stdbool.h>
#include <stdint.h>

#include "opendisplay_structs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define OD_CFG_INDEX_MAX 32u

/* 0xB3 display_controller (OD_PKT_DISPLAY_CONTROLLER, opendisplay_structs.h; docs/
 * CONFIG_DRIVEN_DISPLAY.md, "Built-in controller drivers"). Indexed only where a target sets
 * OD_CFG_INDEX_CONTROLLER=1; everywhere else it is skipped like any unknown length-prefixed id. */
#ifndef OD_CFG_INDEX_CONTROLLER
#define OD_CFG_INDEX_CONTROLLER 0
#endif

typedef struct {
    uint8_t  type;      /* config packet id: 0xAE..0xB2 */
    uint8_t  instance;  /* instance_number -- body[0], NOT the header byte */
    uint8_t  sub;       /* body[1]: mode_index for 0xAE, lut_slot for 0xAF */
    uint16_t offset;    /* byte offset of the packet BODY within the payload */
    uint16_t len;       /* body length in bytes */
} od_cfg_entry_t;

/* IDENTITY IS IN THE BODY, NOT THE HEADER.
 *
 * A packet is [packet_number][packet_type][body]. It is tempting to read packet_number as the
 * instance, and py-opendisplay's serializer does write the instance index there -- but the web
 * toolbox writes a RUNNING COUNTER, and the shipping parsers read neither: they take
 * instance_number from body[0]. So packet_number is a don't-care byte that two writers already
 * disagree about, and matching on it would make a config built by the toolbox fail to find its
 * own packets. */

/* Build the index by walking the stored record once.
 * Returns the entry count, or -1 if nothing is stored or the record header is not ours. */
int od_cfg_index_build(void);

int od_cfg_index_count(void);
const od_cfg_entry_t *od_cfg_index_entry(int i);

/* Find the Nth packet of a type (nth is 0-based). NULL when there is no such packet. */
const od_cfg_entry_t *od_cfg_find(uint8_t type, uint8_t nth);

/* Read `len` bytes of a packet body starting at `off` within that body. Returns bytes read.
 * This is the ONLY way to get config bytes through this module -- there is no resident copy
 * to hand out a pointer into. */
uint32_t od_cfg_read(const od_cfg_entry_t *e, uint16_t off, uint8_t *dst, uint16_t len);

/* Whether no config write or clear has happened since the last build (od_config_store's
 * generation). False means the offsets describe a previous config: rebuild before reading. */
bool od_cfg_index_current(void);

/* Payload length of the stored config, for diagnostics. */
uint32_t od_cfg_blob_len(void);

/* Rebuilds the index, then: can display `instance` be driven by a client that knows nothing
 * about modes? True when its first 0xB1 has a full head and its first 0xAE with mode_index 0
 * has a sequence, is single-pass and renders `color_scheme` (DisplayConfig 0x20's, or 0xFF).
 * False is the "needs migration" state: a 2.x config, or a 3.x config breaking the mode-0
 * invariant (docs/CONFIG_DRIVEN_DISPLAY.md, "Mode conventions"). */
bool od_cfg_has_drive_data(uint8_t instance, uint8_t color_scheme);

#ifdef __cplusplus
}
#endif
#endif /* OD_CFG_INDEX_H */
