/* od_config_asm.c -- see od_config_asm.h for the defect this exists to fix (F3). */
#include "od_config_asm.h"

#include <string.h>

void od_config_asm_reset(struct od_config_asm *s)
{
    if (!s) {
        return;
    }
    s->active     = false;
    s->total_size = 0;
    s->received   = 0;
    s->chunks     = 0;
    /* buffer deliberately not cleared -- see the header. */
}

enum od_config_asm_result od_config_asm_start(struct od_config_asm *s, od_span_t payload)
{
    if (!s || !od_span_valid(payload)) {
        return OD_CONFIG_ASM_REJECTED;
    }
    /* A start frame ALWAYS abandons whatever came before. A client that restarts mid-transfer
     * is not resuming, and silently keeping the old partial record is how two sequences merge
     * into one blob nobody sent. */
    od_config_asm_reset(s);

    if (od_span_is_empty(payload)) {
        return OD_CONFIG_ASM_REJECTED;
    }

    /* Single-frame configs, including the header's short-first-chunk fallback at 201: too long
     * to be a chunk payload, too short to be a chunked start. The caller stores `payload`
     * directly and no transfer is left in progress. */
    if (payload.n < CONFIG_CHUNK_SIZE_WITH_PREFIX) {
        return OD_CONFIG_ASM_SINGLE;
    }
    /* Neither legal shape. The old code took these as chunked starts and silently discarded
     * everything past the first 200 data bytes. */
    if (payload.n > CONFIG_CHUNK_SIZE_WITH_PREFIX) {
        return OD_CONFIG_ASM_REJECTED;
    }

    /* A chunked start is [total:2 LE][data:CONFIG_CHUNK_SIZE]. Cutting it rather than indexing
     * `payload[0..1]` and copying from `payload + 2` means the 200-byte memcpy below is bounded
     * by a span this function derived, not by the reader trusting that the equality test above
     * and CONFIG_CHUNK_SIZE_WITH_PREFIX's definition still agree. Neither split can fail here;
     * both are checked so that a change to either constant is a REJECTED, not an overread. */
    od_span_t total_field;
    od_span_t data;
    if (!od_span_split(payload, 2u, &total_field, &data) ||
        !od_span_split(data, CONFIG_CHUNK_SIZE, &data, NULL)) {
        return OD_CONFIG_ASM_REJECTED;
    }

    const uint32_t total = (uint32_t)total_field.p[0] | ((uint32_t)total_field.p[1] << 8);

    /* Bound the DECLARATION here, at the start, rather than letting an impossible total fail
     * later for an indirect reason:
     *   - <= CONFIG_CHUNK_SIZE would have been a single frame, so it is nonsense chunked;
     *   - > the transferable ceiling cannot be delivered within MAX_CONFIG_CHUNKS, and a
     *     transfer that cannot succeed should be refused before any bytes are stored. */
    if (total <= CONFIG_CHUNK_SIZE || total > OD_CONFIG_ASM_MAX_TRANSFERABLE ||
        total > OD_CONFIG_MAX_SIZE) {
        return OD_CONFIG_ASM_REJECTED;
    }

    memcpy(s->buffer, data.p, data.n);
    s->active     = true;
    s->total_size = total;
    s->received   = (uint32_t)data.n;
    s->chunks     = 1u;
    return OD_CONFIG_ASM_ACCEPTED;
}

enum od_config_asm_result od_config_asm_chunk(struct od_config_asm *s, od_span_t payload)
{
    if (!s || !od_span_valid(payload)) {
        return OD_CONFIG_ASM_REJECTED;
    }
    if (!s->active) {
        return OD_CONFIG_ASM_REJECTED;
    }
    if (od_span_is_empty(payload) || payload.n > CONFIG_CHUNK_SIZE) {
        od_config_asm_reset(s);
        return OD_CONFIG_ASM_REJECTED;
    }

    /* The bytes still owed. Named once because the next two rules both ask about it, and
     * because s->received <= s->total_size is an invariant every path above maintains. */
    const size_t remaining = (size_t)(s->total_size - s->received);

    /* Bounded against the DECLARED TOTAL, not merely against the buffer. Bounding on
     * OD_CONFIG_MAX_SIZE alone is what let 400 bytes be committed against a declared 201. */
    if (payload.n > remaining) {
        od_config_asm_reset(s);
        return OD_CONFIG_ASM_REJECTED;
    }
    /* A non-final chunk must be full. A short one that does not complete the total means the
     * two sides disagree about framing, and continuing would silently accept a record whose
     * length the client never intended. */
    if (payload.n < CONFIG_CHUNK_SIZE && payload.n != remaining) {
        od_config_asm_reset(s);
        return OD_CONFIG_ASM_REJECTED;
    }
    if (s->chunks >= MAX_CONFIG_CHUNKS) {
        od_config_asm_reset(s);
        return OD_CONFIG_ASM_REJECTED;
    }

    memcpy(s->buffer + s->received, payload.p, payload.n);
    s->received += (uint32_t)payload.n;
    s->chunks++;

    /* COMMIT ON THE BYTE COUNT, never on the chunk count. This one line is the F3 fix; the
     * checks above exist so that reaching it means the record is exactly what was declared. */
    if (s->received == s->total_size) {
        s->active = false;
        return OD_CONFIG_ASM_COMPLETE;
    }
    return OD_CONFIG_ASM_ACCEPTED;
}
