/* od_config_tlv.c -- see od_config_tlv.h for why the walk is shared and the copy is not. */
#include "od_config_tlv.h"

uint16_t od_config_tlv_body_size(uint8_t packet_id)
{
    /* EVERY SIZE IS A sizeof, never a literal. The canonical structs already carry
     * OD_STATIC_ASSERT wire-size checks, so a struct that changes shape fails at compile time
     * in the header rather than silently shifting every offset in this walk. */
    switch (packet_id) {
    case 0x01: return (uint16_t)sizeof(struct SystemConfig);
    case 0x02: return (uint16_t)sizeof(struct ManufacturerData);
    case 0x04: return (uint16_t)sizeof(struct PowerOption);
    case 0x20: return (uint16_t)sizeof(struct DisplayConfig);
    case 0x21: return (uint16_t)sizeof(struct LedConfig);
    case 0x23: return (uint16_t)sizeof(struct SensorData);
    case 0x24: return (uint16_t)sizeof(struct DataBus);
    case 0x25: return (uint16_t)sizeof(struct BinaryInputs);
    case 0x26: return (uint16_t)sizeof(struct WifiConfig);
    case 0x27: return (uint16_t)sizeof(struct SecurityConfig);
    case 0x28: return (uint16_t)sizeof(struct TouchController);
    case 0x29: return (uint16_t)sizeof(struct BuzzerConfig);
    /* 0x2A nfc_config. ADDED 2026-08-13 BY DECISION, not as a table fix -- it changes the wire
     * on the ESP32, which previously treated the id as unknown and abandoned the remainder of
     * the blob. The decision: a target parses and stores every canonical packet whether or not
     * it can act on it. Using a subsystem is a hardware capability; understanding the config
     * that describes it is a protocol obligation, and a target that stops reading at a packet it
     * cannot use makes the REST of the config depend on hardware the host cannot see.
     *
     * What changes on the ESP32: 0x2B and 0x2C packets that follow an nfc_config are now applied
     * instead of discarded -- i.e. flash_config and data_extended start taking effect on devices
     * whose config carries NFC. That is a fix in substance, since the host wrote those packets
     * and had no way to know they were being dropped. What changes on Nordic and Silabs: nothing
     * -- both already parse 0x2A and continue, which is why leaving it out would have regressed
     * them the moment either adopted this walk.
     *
     * This is NOT the deferred size-table skip model (D4). That is about ids unknown to the
     * CANONICAL contract; this id has always been in it. */
    case 0x2A: return (uint16_t)sizeof(struct NfcConfig);
    case 0x2B: return (uint16_t)sizeof(struct FlashConfig);
    case 0x2C: return (uint16_t)sizeof(struct DataExtended);
    /* 0x2D findmy_config, the LAST id in the frozen range. It is here for the same reason
     * 0x2A is: a target sizes every canonical packet whether or not it can act on it. Leaving
     * it out is not neutral -- 0x2D sorts after every other legacy packet and before the
     * length-prefixed range, so a device carrying findmy would abandon its blob exactly where
     * the drive packets begin and come up with no panel data at all. */
    case 0x2D: return (uint16_t)sizeof(struct FindMyConfig);
    /* Burned 0x2E-0x31 (reserved; no struct, hence literals). Sized only so a config carrying
     * them walks past instead of abandoning the 0xAE-0xB1 packets that sort after them. Never
     * delivered -- see od_config_tlv_is_burned(). Matches Firmware_Silabs. */
    case OD_CFG_TLV_BURNED_2E: return OD_CFG_TLV_BURNED_2E_SIZE;
    case OD_CFG_TLV_BURNED_2F: return OD_CFG_TLV_BURNED_2F_SIZE;
    case OD_CFG_TLV_BURNED_30: return OD_CFG_TLV_BURNED_30_SIZE;
    case OD_CFG_TLV_BURNED_31: return OD_CFG_TLV_BURNED_31_SIZE;
    default:   return 0u;
    }
}

enum od_config_tlv_result od_config_tlv_walk(od_span_t blob,
                                             od_config_tlv_packet_fn fn, void *ctx,
                                             uint8_t *version_out, uint8_t *unknown_id_out)
{
    if (unknown_id_out) {
        *unknown_id_out = 0u;
    }
    if (!od_span_valid(blob) || !fn) {
        return OD_CFG_TLV_TOO_SHORT;
    }
    if (blob.n < OD_CFG_TLV_HEADER_LEN + OD_CFG_TLV_CRC_LEN) {
        /* Not enough for a version byte and a CRC, so there is no blob here to disagree
         * about. The old check was `configLen < 3`, which admitted a 3- or 4-byte input whose
         * "body end" (len - 2) sat at or before the header -- the loop then simply did not run
         * and the config was reported LOADED. Refusing it is the honest answer. */
        return OD_CFG_TLV_TOO_SHORT;
    }

    if (version_out) {
        *version_out = blob.p[2];
    }

    /* THE BODY REGION, cut once. Everything below walks inside `rest`, so there is no second
     * bound to keep in step with the pointer -- the old parser recomputed `configLen - 2` at
     * fifteen separate comparison sites, and reading an id out of the trailing CRC was the
     * mistake that invited. Both cuts are safe by the length check above: at least 5 bytes, so
     * dropping 3 leaves at least the 2 CRC bytes to trim. */
    od_span_t rest = od_span_drop(blob, OD_CFG_TLV_HEADER_LEN);
    rest = od_span_take(rest, rest.n - OD_CFG_TLV_CRC_LEN);

    /* Each packet is [reserved:1][id:1][body...]. Splitting `rest` in place is safe: the span
     * is passed by value, so the tail is written from a copy, not from what it overwrites. */
    od_span_t hdr;
    while (od_span_split(rest, 2u, &hdr, &rest)) {
        const uint8_t packet_id = hdr.p[1];    /* hdr.p[0] is the reserved byte */
        uint16_t body_size;

        if (packet_id >= OD_CFG_TLV_LEN_PREFIXED_MIN) {
            /* [number][id][length:2 LE][body]. The declared length is what lets an id this
             * build does not know be STEPPED OVER rather than end the walk -- the whole reason
             * the range exists, and why every packet added after 0x2D lives in it.
             *
             * The length is attacker-controlled: the blob is parsed at boot from storage a
             * client can write. It is never added to an offset here -- the split below compares
             * against what remains, so an oversized declaration truncates the walk instead of
             * reaching past the body region. */
            od_span_t len_field;
            if (!od_span_split(rest, 2u, &len_field, &rest)) {
                return OD_CFG_TLV_TRUNCATED;
            }
            body_size = (uint16_t)((uint16_t)len_field.p[0] |
                                   ((uint16_t)len_field.p[1] << 8));
        } else {
            body_size = od_config_tlv_body_size(packet_id);
        }

        if (packet_id < OD_CFG_TLV_LEN_PREFIXED_MIN && body_size == 0u) {
            /* Unknown id in the FROZEN legacy range: abandon the remainder. There is no length
             * on the wire below 0x80, so a walk that cannot size a packet cannot find the next
             * one. Not an error: a config carrying a packet this build does not know is newer,
             * not corrupt.
             *
             * This is why the legacy range is frozen at 0x2D and every later packet is
             * length-prefixed. A new packet added here would put every packet after it behind a
             * wall on any device that predates it. */
            if (unknown_id_out) {
                *unknown_id_out = packet_id;
            }
            return OD_CFG_TLV_OK;
        }

        /* THE CHECK THIS MODULE EXISTS FOR, now the same one call every span split performs:
         * a comparison, never an addition, so a large declared size cannot overflow a sum and
         * turn a truncated blob into an in-bounds read. It also advances `rest` -- the bound
         * and the cursor move together or not at all, which is the whole point of the type. */
        od_span_t body;
        if (!od_span_split(rest, body_size, &body, &rest)) {
            return OD_CFG_TLV_TRUNCATED;
        }

        /* Burned ids were sized only so the walk can get past them. Delivering one would hand a
         * consumer a body whose layout no longer exists. */
        if (od_config_tlv_is_burned(packet_id)) {
            continue;
        }
        if (!fn(ctx, packet_id, body)) {
            return OD_CFG_TLV_REJECTED;
        }
    }

    return OD_CFG_TLV_OK;
}

bool od_config_tlv_is_burned(uint8_t packet_id)
{
    return packet_id >= OD_CFG_TLV_BURNED_2E && packet_id <= OD_CFG_TLV_BURNED_31;
}

static uint16_t od_crc16_feed(uint16_t crc, uint8_t b)
{
    crc ^= (uint16_t)((uint16_t)b << 8);
    for (unsigned bit = 0; bit < 8u; ++bit) {
        if ((crc & 0x8000u) != 0u) {
            crc = (uint16_t)(((uint32_t)crc << 1) ^ 0x1021u);
        } else {
            crc = (uint16_t)((uint32_t)crc << 1);
        }
    }
    return crc;
}

uint16_t od_config_tlv_crc16(od_span_t data)
{
    /* CRC-16/CCITT-FALSE: init 0xFFFF, poly 0x1021, no reflection, no final xor.
     *
     * THE FIRST TWO BYTES ARE FED AS ZERO, and that is not an accident to be tidied away. Those
     * are the container's length field, and zeroing them makes the checksum independent of the
     * declared length -- which is what the toolbox, the nRF firmware and the Silabs firmware
     * all do. Computing a plain CRC over the whole body here would be a subtly different
     * function that disagreed with every shipped device about which configs are intact, and it
     * would present as a warning that appears from nowhere rather than as an obvious break.
     *
     * Byte-at-a-time on purpose: the targets that run this have no table to spare. */
    uint16_t crc = 0xFFFFu;
    if (!od_span_valid(data)) {
        return crc;
    }
    if (data.n < 2u) {
        for (size_t i = 0; i < data.n; ++i) {
            crc = od_crc16_feed(crc, data.p[i]);
        }
        return crc;
    }
    crc = od_crc16_feed(crc, 0u);
    crc = od_crc16_feed(crc, 0u);
    for (size_t i = 2u; i < data.n; ++i) {
        crc = od_crc16_feed(crc, data.p[i]);
    }
    return crc;
}
