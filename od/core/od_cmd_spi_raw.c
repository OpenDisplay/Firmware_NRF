/* CMD_SPI_RAW (0x0084) -- the wire half of the raw SPI debug session.
 *
 * A bring-up escape hatch: clock arbitrary bytes at the panel so register sequences, init
 * sequences and candidate waveforms can be tried without a firmware rebuild. Every panel
 * characterised on this project was brought up through this opcode.
 *
 * THE SESSION PERSISTS ACROSS COMMANDS and that is the whole point. A handler that
 * re-initialised per call would silently discard whatever the previous call staged, which makes
 * register debugging impossible -- the state you are trying to observe is exactly what the
 * re-init destroys.
 *
 * Shared by every target; the panel half is the target's, behind od_spi_raw_app.h.
 *
 * No authentication check here on purpose: this sits in the ordinary dispatch table, so the
 * session gate has already rejected an unauthenticated caller with RESP_AUTH_REQUIRED when
 * encryption is enabled. A second, bespoke check would be one more thing to drift.
 */
#include "od_cmd_app.h"

#include "od_epd.h"
#include "od_reply.h"
#include "od_spi_raw_app.h"
#include "od_xfer.h"
#include "opendisplay_protocol.h"

#include <stddef.h>

#if OD_CAP_SPI_RAW

static od_txq_status_t reply(const od_cmd_ctx_t *ctx, const uint8_t *frame, uint16_t len)
{
    return od_reply(ctx->r, &ctx->rp, frame, len);
}

/* [0xFF][0x84][err][sub][diag]
 *
 * Byte 4 is a DIAGNOSTIC, APPENDED rather than repurposed -- a host that knows the 4-byte shape
 * reads what it needs and ignores the tail. It earns its place because OD_ERR_SPI_RAW_PANEL
 * covers several distinct descriptor-from-config failures that are otherwise
 * indistinguishable, and the only other diagnostic channel is a log over RTT, which needs a
 * wired programmer the device in question may not have. */
static od_cmd_result_t nack(const od_cmd_ctx_t *ctx, uint8_t err, uint8_t sub)
{
    const uint8_t r[5] = { RESP_NACK, RESP_SPI_RAW, err, sub, od_epd_desc_diag() };

    (void)reply(ctx, r, sizeof r);
    return OD_CMD_NACK;
}

static od_cmd_result_t ack(const od_cmd_ctx_t *ctx, uint8_t sub)
{
    const uint8_t r[3] = { RESP_ACK, RESP_SPI_RAW, sub };

    (void)reply(ctx, r, sizeof r);
    return OD_CMD_OK;
}

od_cmd_result_t od_cmd_app_spi_raw(const od_cmd_ctx_t *ctx, od_span_t body)
{
    const uint8_t *args;
    uint16_t args_len;
    uint8_t sub;
    int rc;

    if (body.p == NULL || body.n < 1u) {
        return nack(ctx, OD_ERR_SPI_RAW_BAD_ARGS, 0xFFu);
    }
    sub = body.p[0];
    args = body.p + 1;
    args_len = (uint16_t)(body.n - 1u);

    switch (sub) {
    case SPI_RAW_SUB_OPEN:
        /* The session takes the panel, so an upload in flight ends here: left active with no
         * panel behind it, it would defer the display service until it timed out. The flags
         * byte is optional and absent means zero: pins and power only, nothing clocked out, so
         * virgin register state is observable. */
        od_xfer_replace_active();
        rc = opendisplay_display_spi_raw_open(
            args_len >= 1u && (args[0] & SPI_RAW_OPEN_FLAG_PANEL_INIT) != 0u);
        break;

    case SPI_RAW_SUB_CMD:
        rc = opendisplay_display_spi_raw_cmd(args, args_len);
        break;

    case SPI_RAW_SUB_DATA:
        rc = opendisplay_display_spi_raw_data(args, args_len);
        break;

    case SPI_RAW_SUB_DATA_NOACK:
        /* Bulk streaming: write and return WITHOUT replying, so the host can use
         * write-without-response instead of paying a round trip per frame. Returning early is
         * the entire feature -- falling through to the ACK would reintroduce the latency this
         * exists to remove (an early 16-colour render spent 54 s on 327 frames, almost all of
         * it waiting). No error can be reported, by construction; a host resynchronises by
         * following the burst with any ACKed sub-opcode. */
        (void)opendisplay_display_spi_raw_data(args, args_len);
        return OD_CMD_OK;

    case SPI_RAW_SUB_BUSY: {
        uint16_t elapsed = 0u;
        bool still_busy = false;

        if (args_len < 2u) {
            return nack(ctx, OD_ERR_SPI_RAW_BAD_ARGS, sub);
        }
        rc = opendisplay_display_spi_raw_busy(
            (uint32_t)args[0] | ((uint32_t)args[1] << 8), &elapsed, &still_busy);
        if (rc == 0) {
            /* BUSY is the one sub-opcode with a payload: elapsed plus whether it was STILL
             * busy when the wait ended. Without that flag a host cannot tell a release at
             * the timeout from a timeout. */
            const uint8_t r[6] = { RESP_ACK, RESP_SPI_RAW, sub,
                                   (uint8_t)(elapsed & 0xFFu),
                                   (uint8_t)((elapsed >> 8) & 0xFFu),
                                   (uint8_t)(still_busy ? 1u : 0u) };
            (void)reply(ctx, r, sizeof r);
            return OD_CMD_OK;
        }
        break;
    }

    case SPI_RAW_SUB_RESET:
        /* hold_ms is optional; 10 ms is a safe default pulse for every panel in this fleet. */
        rc = opendisplay_display_spi_raw_reset(args_len >= 1u ? args[0] : 10u);
        break;

    case SPI_RAW_SUB_CLOSE:
        /* Idempotent, so closing a session that is not open is an ACK rather than NOT_OPEN:
         * a host recovering from a dropped link must be able to get to a known state without
         * having to know what the previous one was. */
        opendisplay_display_spi_raw_close();
        rc = 0;
        break;

    default:
        return nack(ctx, OD_ERR_SPI_RAW_UNKNOWN_SUB, sub);
    }

    if (rc != 0) {
        /* The display layer returns OD_ERR_SPI_RAW_* negated. */
        return nack(ctx, (uint8_t)(-rc), sub);
    }
    return ack(ctx, sub);
}

#endif /* OD_CAP_SPI_RAW */
