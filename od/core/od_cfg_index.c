/* od_cfg_index.c -- see od_cfg_index.h for why this is a map and not a copy. */
#include "od_cfg_index.h"

#include <string.h>

#include "od_config_store.h"
#include "od_config_tlv.h"
#include "od_hal_nvs.h"
#include "od_log.h"

/* The payload starts [0x00 0x00][version] before the first packet. */
#define OD_CFG_PREAMBLE_SZ 3u

static od_cfg_entry_t s_index[OD_CFG_INDEX_MAX];
static uint8_t        s_count;
static uint32_t       s_blob_len;
static uint32_t       s_gen;

/* Read from the PAYLOAD, hiding the record header. od_hal_nvs_read offsets are into the whole
 * record, and every offset this module stores is payload-relative. */
static bool read_payload(uint32_t off, void *dst, uint32_t len)
{
    return od_hal_nvs_read(OD_CONFIG_STORE_HEADER_SIZE + off, dst, len) == OD_HAL_NVS_OK;
}

static uint32_t le32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int od_cfg_index_build(void)
{
    uint8_t  hdr[OD_CONFIG_STORE_HEADER_SIZE];
    uint32_t record_len = 0;

    s_count = 0;
    s_blob_len = 0;
    s_gen = od_config_store_generation();

    if (od_hal_nvs_size(&record_len) != OD_HAL_NVS_OK ||
        record_len <= OD_CONFIG_STORE_HEADER_SIZE) {
        return -1;
    }
    if (od_hal_nvs_read(0u, hdr, sizeof hdr) != OD_HAL_NVS_OK) {
        return -1;
    }
    if (le32(&hdr[0]) != OD_CONFIG_STORE_MAGIC) {
        return -1;
    }
    const uint32_t data_len = le32(&hdr[12]);
    if (data_len > record_len - OD_CONFIG_STORE_HEADER_SIZE ||
        data_len > OD_CONFIG_MAX_SIZE) {
        return -1;
    }
    s_blob_len = data_len;

    /* THE PACKETS DO NOT START AT OFFSET 0. The payload is
     * [0x00 0x00][version][packets...][crc16]. Walking from 0 reads the two padding bytes as a
     * header, gets type 0x00, finds no size for it and stops -- producing an empty index that
     * looks like "this device has no drive data" rather than like a bug. */
    uint32_t off = OD_CFG_PREAMBLE_SZ;

    /* `data_len - 2` keeps the trailing CRC-16 out of the walk; reading an id out of the CRC is
     * how a walk invents a packet that was never written. */
    while (off + 2u + OD_CFG_TLV_CRC_LEN <= data_len && s_count < OD_CFG_INDEX_MAX) {
        uint8_t  ph[4];
        uint8_t  b2[2] = { 0u, 0u };
        uint16_t bsz;
        uint32_t hdr_sz;
        bool     record = true;

        if (!read_payload(off, ph, 2u)) {
            break;
        }
        if (ph[1] >= OD_CFG_TLV_LEN_PREFIXED_MIN) {
            /* [number][id][length:2 LE][body]. The explicit length is what lets an id this
             * build does not know be stepped over instead of abandoning the tail. */
            if (off + 4u > data_len - OD_CFG_TLV_CRC_LEN || !read_payload(off, ph, 4u)) {
                break;
            }
            hdr_sz = 4u;
            bsz = (uint16_t)((uint16_t)ph[2] | ((uint16_t)ph[3] << 8));
            switch (ph[1]) {
            case OD_PKT_DISPLAY_MODE:
            case OD_PKT_DISPLAY_LUT:
            case OD_PKT_DISPLAY_CAL:
            case OD_PKT_DISPLAY_PANEL:
            case OD_PKT_ACTION_TABLE:
#if OD_CFG_INDEX_CONTROLLER
            case OD_PKT_DISPLAY_CONTROLLER:
#endif
                break;
            default:
                /* Skippable, which is the whole point of the range. It costs no index slot:
                 * the slots exist for packets something will come back and read. */
                od_log_info("cfg index: skipping unknown 0x%02X (%u B) at %u",
                            (unsigned)ph[1], (unsigned)bsz, (unsigned)off);
                record = false;
                break;
            }
        } else {
            /* Sized and stepped over, never recorded: nothing reads a legacy packet through
             * the index (od_config parses those at boot), and the drive packets sort after
             * them, so a slot spent here is one a long legacy config takes from the panel. */
            hdr_sz = 2u;
            bsz = od_config_tlv_body_size(ph[1]);
            record = false;
            if (bsz == 0u) {
                /* The legacy range has no length on the wire, so an id missing from the size
                 * table abandons the tail -- and the drive packets sort AFTER everything
                 * legacy, so one missing entry costs the panel all of its drive data. Saying so
                 * matters: the silent version of this reads as "no drive data on this device". */
                od_log_warn("cfg index: unknown legacy packet 0x%02X at %u, abandoning %u B",
                            (unsigned)ph[1], (unsigned)off, (unsigned)(data_len - off));
                break;
            }
        }

        if (off + hdr_sz + bsz > data_len - OD_CFG_TLV_CRC_LEN) {
            break;      /* body would run into the CRC tail */
        }
        if (record && bsz > 0u) {
            /* Identity comes from the body -- see the note in the header. */
            (void)read_payload(off + hdr_sz, b2, bsz >= 2u ? 2u : 1u);
            s_index[s_count].type     = ph[1];
            s_index[s_count].instance = b2[0];
            s_index[s_count].sub      = b2[1];
            s_index[s_count].offset   = (uint16_t)(off + hdr_sz);
            s_index[s_count].len      = bsz;
            s_count++;
        }
        off += hdr_sz + bsz;
    }

    if (s_count == OD_CFG_INDEX_MAX) {
        /* The walk stops when the index fills, and the drive packets sort last, so a full
         * index is indistinguishable from a device with no drive data unless it says so. */
        od_log_warn("cfg index: full at %u entries, rest of the config not indexed",
                    (unsigned)s_count);
    }
    return (int)s_count;
}

int od_cfg_index_count(void) { return (int)s_count; }

const od_cfg_entry_t *od_cfg_index_entry(int i)
{
    return (i >= 0 && i < (int)s_count) ? &s_index[i] : NULL;
}

const od_cfg_entry_t *od_cfg_find(uint8_t type, uint8_t nth)
{
    uint8_t seen = 0;
    for (uint8_t i = 0; i < s_count; i++) {
        if (s_index[i].type == type) {
            if (seen == nth) {
                return &s_index[i];
            }
            seen++;
        }
    }
    return NULL;
}

uint32_t od_cfg_read(const od_cfg_entry_t *e, uint16_t off, uint8_t *dst, uint16_t len)
{
    if (e == NULL || dst == NULL || off >= e->len) {
        return 0u;
    }
    uint16_t avail = (uint16_t)(e->len - off);
    if (len > avail) {
        len = avail;
    }
    if (!read_payload((uint32_t)e->offset + off, dst, len)) {
        return 0u;
    }
    return len;
}

uint32_t od_cfg_blob_len(void) { return s_blob_len; }

bool od_cfg_index_current(void) { return s_gen == od_config_store_generation(); }

/* 0xAE body: [instance][mode_index][name:12][color_scheme][passes]... */
#define MODE0_OFF_SCHEME 14u

bool od_cfg_has_drive_data(uint8_t instance, uint8_t color_scheme)
{
    const od_cfg_entry_t *panel = NULL;
    const od_cfg_entry_t *mode0 = NULL;
    uint8_t h[2];

    if (od_cfg_index_build() < 0) {
        return false;
    }
    for (int i = 0; i < (int)s_count; i++) {
        const od_cfg_entry_t *e = &s_index[i];

        if (e->instance != instance) {
            continue;
        }
        /* First match wins, as everywhere else: a short first copy is not rescued by a later
         * one. */
        if (e->type == OD_PKT_DISPLAY_PANEL && panel == NULL) {
            panel = e;
        } else if (e->type == OD_PKT_DISPLAY_MODE && e->sub == 0u && mode0 == NULL) {
            mode0 = e;
        }
    }
    if (panel == NULL || panel->len < sizeof(struct DisplayPanelHead) || mode0 == NULL ||
        mode0->len <= sizeof(struct DisplayModeHead) ||
        od_cfg_read(mode0, MODE0_OFF_SCHEME, h, sizeof h) != sizeof h) {
        return false;
    }
    /* Mode 0 is what a client that knows nothing about modes gets: single pass, in the 0x20
     * scheme's 2.x pixel format (0xFF = the panel's own). */
    return h[1] == 1u && (h[0] == 0xFFu || h[0] == color_scheme);
}
