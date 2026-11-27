/* od_caps.h -- compile-time facts declared by a target.
 *
 * Defaults preserve the fully capable profile. A target that omits a subsystem must say so on
 * its compile line; shared code derives sizing and reservation consequences from these facts.
 * Capabilities never remove opcode routes or od_cmd_app hooks -- every target still has to state
 * its wire behaviour for every canonical command.
 */

#ifndef OD_CAPS_H
#define OD_CAPS_H

#ifndef OD_CAP_PIPE
#define OD_CAP_PIPE 1
#endif

#ifndef OD_CAP_PARTIAL
#define OD_CAP_PARTIAL 1
#endif

#ifndef OD_CAP_RXQ
#define OD_CAP_RXQ 1
#endif

#ifndef OD_CAP_DUAL_CS
#define OD_CAP_DUAL_CS 1
#endif

#ifndef OD_CAP_NFC
#define OD_CAP_NFC 1
#endif

/* External SPI NOR image store (od_imgstore + od_flash_nor over od_hal_spi).
 *
 * DEFAULT OFF, unlike the capabilities above. Those gate behaviour every target can perform;
 * this one needs a flash chip on known pins and a target implementation of od_hal_spi, and a
 * build that has neither must not route opcodes it cannot answer. Only efr32bg22-slc turns it
 * on today. */
#ifndef OD_CAP_IMGSTORE
#define OD_CAP_IMGSTORE 0
#endif

/* The 0xB2 action table: CMD_ACTION_INFO / CMD_ACTION_FIRE routed, od_action.c and
 * od_cmd_action.c linked (APP_ACTION). Defaults to the image store's setting, so a target with an
 * image store keeps routing both opcodes; ESP32 sets it without one, and there an entry naming
 * OD_EFF_DISPLAY_SLOT loads as inactive. */
#ifndef OD_CAP_ACTION
#define OD_CAP_ACTION OD_CAP_IMGSTORE
#endif

/* CMD_DRIVE_WRITE_START (0x0085): full-frame write naming a config-declared drive mode.
 *
 * DEFAULT OFF for the same reason as OD_CAP_IMGSTORE: it is answerable only by a target whose
 * display path is driven from config drive packets (0xAE-0xB1) and can run a mode's declared
 * pass count. A target without that must leave the opcode unrouted rather than claim one it
 * cannot honour. Unrouted means SILENT, not NACKed: od_dispatch's OD_FRAME_UNKNOWN_OPCODE logs
 * and emits no frame, deliberately, so unknown-command traffic cannot stamp activity and hold
 * an exclusive link open. Confirmed on hardware 2026-11-06 -- every sub-opcode of an unrouted
 * 0x0084 timed out rather than answering.
 *
 * The protocol header calls this Silabs-first; every target sets it (ESP32 and Nordic through
 * od_epd_cfg, BG22 through its own adapter). The spec and the error namespace are already in shared/protocol; this gates the routing. */
#ifndef OD_CAP_DRIVE_WRITE
#define OD_CAP_DRIVE_WRITE 0
#endif

/* CMD_SPI_RAW (0x0084): debug/bring-up escape hatch that clocks the panel SPI bus directly.
 *
 * DEFAULT OFF, and the default matters more here than for the other caps. The opcode BYPASSES
 * EVERY DRIVER-LEVEL SAFETY CHECK: a malformed sequence can leave the panel powered, mid-refresh
 * or driven with a DC-imbalanced waveform, which degrades e-paper permanently. A target that
 * does not need it should not answer it at all; silence is what an unrouted opcode gets.
 *
 * It is not a security hole on its own -- the handler sits in the ordinary dispatch table and so
 * inherits the session gate, meaning an unauthenticated caller gets RESP_AUTH_REQUIRED and never
 * reaches it. The protocol marks it Silabs-only; this firmware routes it on every target, and
 * each needs the display's drive packets in config before OPEN succeeds. */
#ifndef OD_CAP_SPI_RAW
#define OD_CAP_SPI_RAW 0
#endif

/* CMD_READ_IDENT (0x0046): plaintext panel identity, routed pre-gate like FIRMWARE_VERSION.
 *
 * DEFAULT OFF: the protocol lists it as Silabs-only with the other families "pending
 * adoption", and the response carries a fw_target value each family must answer for itself.
 * A target enabling it implements od_cmd_app_read_ident(). */
#ifndef OD_CAP_READ_IDENT
#define OD_CAP_READ_IDENT 0
#endif

#ifndef OD_XFER_DIRECT_AUTO_END
#define OD_XFER_DIRECT_AUTO_END 0
#endif

#if (OD_CAP_PIPE != 0) && (OD_CAP_PIPE != 1)
#error "OD_CAP_PIPE must be 0 or 1"
#endif
#if (OD_CAP_PARTIAL != 0) && (OD_CAP_PARTIAL != 1)
#error "OD_CAP_PARTIAL must be 0 or 1"
#endif
#if (OD_CAP_RXQ != 0) && (OD_CAP_RXQ != 1)
#error "OD_CAP_RXQ must be 0 or 1"
#endif
#if (OD_CAP_DUAL_CS != 0) && (OD_CAP_DUAL_CS != 1)
#error "OD_CAP_DUAL_CS must be 0 or 1"
#endif
#if (OD_CAP_NFC != 0) && (OD_CAP_NFC != 1)
#error "OD_CAP_NFC must be 0 or 1"
#endif
#if (OD_CAP_READ_IDENT != 0) && (OD_CAP_READ_IDENT != 1)
#error "OD_CAP_READ_IDENT must be 0 or 1"
#endif
#if (OD_XFER_DIRECT_AUTO_END != 0) && (OD_XFER_DIRECT_AUTO_END != 1)
#error "OD_XFER_DIRECT_AUTO_END must be 0 or 1"
#endif

#endif /* OD_CAPS_H */
