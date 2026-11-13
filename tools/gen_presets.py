#!/usr/bin/env python3
"""Drive presets for this target, generated from the 2.x C drivers and checked by replay.

    tools/gen_presets.py [--extra presets/m3_oplists.json] [--out presets/drive_presets_nrf52811.json]

1. host/build/capture (host/equiv/capture.c, the 2.x drivers from the import commit compiled
   against a recording SPI mock) prints each model's bus stream: init, the per-plane RAM write,
   refresh, sleep.
2. That stream becomes an od_epd mode-0 sequence and a sleep sequence. Each image run becomes an
   IMAGE marker. The 2.x service inverted some planes in software; od_display writes the wire
   bytes as they arrive, so the inversion moves into the controller's own data-polarity register
   (SSD 0x21 RAM option nibble, UC 0x50 CDI DDX bit). A model whose inversion has no register
   is blocked.
3. The packets are replayed through the real od/core/od_epd.c (host/build/od_epd_replay, built
   with this target's -DOD_EPD_WITH_WINDOW=0), and the replayed bus stream is compared with the
   2.x stream after the documented transforms. "equivalent" means token-identical after them.

4. A few presets deliberately leave their source: DEVIATIONS below. Such a preset is "corrected":
   its packets replay token-identical to the corrected steps, the change is listed under
   "deviations", and the uncorrected packets stay under "alternatives" with their own
   equivalence result. Nothing here is forced to match the 2.x driver. A preset whose packets
   were checked on a real panel (GLASS) is "glass".

--extra takes models described as op lists (cmd / delay_ms / wait_busy / reset / pixel_data /
data). Those were not compiled from source, so they are marked "extracted, not cross-checked":
the replay proves the packets encode the op list, not that the op list is right.

Schema: the Firmware_Unified drive_presets.json v1 (minor 3) layout, keys are panel_ic_type as
"0x%04X". The keys here are PROVISIONAL (0xE0xx / 0xE1xx): the 2.x ids 1000..1030 collide with
registry ids already assigned (1004 is a 4.2in BWRY panel), so real ids must be allocated.
"""
from __future__ import annotations

import argparse
import json
import os
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
BUILD = REPO / "host" / "build"
CAPTURE = BUILD / "capture"
REPLAY = BUILD / "od_epd_replay"

SLEEP_MAX = 20          # OD_EPD_SLEEP_SEQ_MAX
MAX_STEPS = 128         # OD_EPD_MAX_SEQ_STEPS
BUSY_TIMEOUT = 0xFFFF   # 2.x waited UINT16_MAX ms for a refresh
CONFIG_CAP = 2000       # this target's OD_CONFIG_MAX_SIZE

IC = {0x0D: "UC8151", 0x0E: "UCVAR43", 0x10: "UC8159", 0x11: "UC8176", 0x12: "UC8179",
      0x20: "SSD1619", 0x21: "SSD1677", 0x30: "JD79668", 0x31: "JD79665"}
NAMES = {1: "UC8176_420_BW", 2: "SSD1619_420_BWR", 3: "UC8176_420_BWR", 4: "SSD1619_420_BW",
         5: "JD79668_420_BWRY", 6: "UC8179_750_BW", 7: "UC8179_750_BWR", 8: "UC8159_750_LOW_BW",
         9: "UC8159_750_LOW_BWR", 10: "SSD1677_750_HD_BW", 11: "SSD1677_750_HD_BWR",
         12: "JD79665_750_BWRY", 13: "JD79665_583_BWRY", 14: "UC8151_029_BW", 15: "UC8151_029_BWR",
         16: "SSD1619_029_BW", 17: "SSD1619_029_BWR", 18: "SSD1619_016_BW", 19: "SSD1619_016_BWR",
         20: "SSD1619_022_BW", 21: "SSD1619_022_BWR", 22: "SSD1619_026_BW", 23: "SSD1619_026_BWR",
         24: "UC8151_027_BW", 25: "UC8151_027_BWR", 26: "UCVAR43_430_BW", 27: "UCVAR43_430_BWR",
         28: "SSD1619_013_BW", 29: "SSD1619_013_BWR", 30: "SSD1619_022_LITE_BW",
         31: "SSD1619_022_LITE_BWR"}
SCHEME = {1: 0, 2: 1, 3: 3}                        # 2.x colour -> 3.0 colour_scheme
SCHEME_BY_NAME = {"BW": 0, "BWR": 1, "BWY": 2, "BWRY": 3}
PLANES = {0: 1, 1: 2, 2: 2, 3: 1}

# ---------------------------------------------------------------------------- encoders
# Grammar: od/core/od_epd.h. A step is [n][cmd][n-1 data] or an escape [0][code][args].


def encode_steps(steps: list[tuple]) -> bytes:
    out = bytearray()
    for st in steps:
        k = st[0]
        if k == "cmd":
            data = bytes(st[2])
            if len(data) + 1 > 255:
                raise ValueError("step longer than 255 bytes")
            out += bytes([1 + len(data), st[1]]) + data
        elif k == "busy":
            out += b"\x00\x01"
        elif k == "image":
            out += b"\x00\x03"
        elif k == "delay":
            out += bytes([0, 0x05, st[1] & 0xFF, st[1] >> 8])
        else:
            raise ValueError(st)
    return bytes(out + b"\x00\x00")


def frame(number: int, pid: int, body: bytes) -> bytes:
    return bytes([number & 0xFF, pid]) + struct.pack("<H", len(body)) + body


def mode_body(index: int, name: str, seq: bytes, scheme: int) -> bytes:
    return (bytes([0, index]) + name.encode().ljust(12, b"\0") + bytes([scheme, 1])
            + struct.pack("<bbB", 0, 0, 0) + b"\xff" * 8 + b"\0" * 8
            + struct.pack("<H", len(seq)) + seq)


def panel_body(idle: int, sleep: bytes) -> bytes:
    return (struct.pack("<BBBHH", 0, 0x01, idle, BUSY_TIMEOUT, 0) + bytes([0, 1, 2, 3])
            + bytes([1, len(sleep)]) + sleep)

# ---------------------------------------------------------------------------- tokens


def tokens(lines: list[str], *, side: str) -> list[tuple]:
    """Bus events -> (CMD c data) / (BUSY) / (DELAY ms) / (IMAGE) / (DATA d) tokens.

    side "2x": a run of I lines is one IMAGE; N/S lines are markers handled by the caller.
    side "od": each I line is one IMAGE marker; M lines are dropped."""
    out: list[tuple] = []
    prev_img = False
    for ln in lines:
        t = ln.split()
        k = t[0]
        if k == "I":
            if side == "od" or not prev_img:
                out.append(("IMAGE",))
            prev_img = True
            continue
        prev_img = False
        if k == "C":
            out.append(("CMD", int(t[1], 16), b""))
        elif k == "D":
            d = bytes.fromhex(t[1])
            if out and out[-1][0] == "CMD":
                c = out.pop()
                out.append(("CMD", c[1], c[2] + d))
            else:
                out.append(("DATA", d))
        elif k == "B":
            out.append(("BUSY",))
        elif k == "W":
            out.append(("DELAY", int(t[1])))
        elif k == "T":
            out.append(("RESET", int(t[1])))
        elif k in ("M", "N", "S", "P"):
            continue
        else:
            raise ValueError(ln)
    return out


def strip_reset(toks: list[tuple]) -> tuple[list[tuple], int | None]:
    """od_epd_begin_pass resets the panel and waits for idle itself: drop the leading reset and
    a busy wait that directly follows it."""
    hold = None
    if toks and toks[0][0] == "RESET":
        hold = toks[0][1]
        toks = toks[1:]
        if toks and toks[0] == ("BUSY",):
            toks = toks[1:]
    return toks, hold


def to_steps(toks: list[tuple], notes: list[str]) -> list[tuple]:
    steps: list[tuple] = []
    for tk in toks:
        k = tk[0]
        if k == "CMD":
            steps.append(("cmd", tk[1], tk[2]))
        elif k == "BUSY":
            steps.append(("busy",))
        elif k == "DELAY":
            steps.append(("delay", tk[1]))
        elif k == "IMAGE":
            steps.append(("image",))
        elif k == "DATA":
            # A data byte with no command of its own (UC8151: 0x00 after PON's busy wait). The
            # grammar has no bare data, so it joins the last command, ahead of that busy wait.
            j = max(i for i, s in enumerate(steps) if s[0] == "cmd")
            c = steps[j]
            steps[j] = ("cmd", c[1], c[2] + tk[1])
            if j != len(steps) - 1:
                notes.append(f"T2: bare data {tk[1].hex()} after a busy wait is sent with cmd "
                             f"0x{c[1]:02X}, before that wait")
        else:
            raise ValueError(tk)
    return steps


def steps_to_tokens(steps: list[tuple]) -> list[tuple]:
    m = {"busy": ("BUSY",), "image": ("IMAGE",)}
    out = []
    for s in steps:
        if s[0] == "cmd":
            out.append(("CMD", s[1], bytes(s[2])))
        elif s[0] == "delay":
            out.append(("DELAY", s[1]))
        else:
            out.append(m[s[0]])
    return out

# ---------------------------------------------------------------------------- inversion


def invert_plane(steps: list[tuple], family: str, plane: int, notes: list[str]) -> str | None:
    """Move a software plane inversion into the controller. -> blocker name or None."""
    if family == "SSD":
        reg, mask = 0x21, (0x08 if plane == 0 else 0x80)
        nib = (lambda v: v & 0x0F) if plane == 0 else (lambda v: v >> 4)
        hits = [i for i, s in enumerate(steps) if s[0] == "cmd" and s[1] == reg and s[2]]
        if not hits or any(nib(steps[i][2][0]) not in (0x0, 0x8) for i in hits):
            return "PLANE_INVERT"   # no 0x21, or the nibble is 'bypass', not normal/inverse
        what = "0x21 BW RAM option" if plane == 0 else "0x21 RED RAM option"
    elif family in ("UC8176", "UCVAR43", "UC8179"):
        # CDI byte 1: UC8176 VBD[7:6] DDX[5:4] CDI[3:0]; UC8179 BDZ BDV[5:4] N2OCP DDX[1:0]
        # (on UC8179 bits 5:4 are the border, not data polarity)
        reg = 0x50
        if family == "UC8179":
            mask = 0x01 if plane == 0 else 0x02
        else:
            mask = 0x10 if plane == 0 else 0x20
        hits = [i for i, s in enumerate(steps) if s[0] == "cmd" and s[1] == reg and s[2]]
        if not hits:
            return "PLANE_INVERT"
        what = f"0x50 CDI DDX[{0 if plane == 0 else 1}]"
    else:
        return "PLANE_INVERT"
    for i in hits:
        c = steps[i]
        steps[i] = ("cmd", reg, bytes([c[2][0] ^ mask]) + c[2][1:])
    notes.append(f"T1: plane {plane} inversion moved into {what} (XOR 0x{mask:02X}); "
                 f"datasheet-derived, needs a glass check")
    return None

# ---------------------------------------------------------------------------- replay


def replay(packets: bytes, mode: str, w: int, h: int) -> tuple[int, list[str]]:
    with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
        f.write(packets)
        path = f.name
    try:
        r = subprocess.run([str(REPLAY), path, mode, str(w), str(h)], capture_output=True,
                           text=True, check=False)
    finally:
        os.unlink(path)
    return r.returncode, r.stdout.splitlines()


def check(packets: bytes, w: int, h: int, mode_steps, sleep_steps) -> dict:
    res = {}
    for key, steps in (("0", mode_steps), ("sleep", sleep_steps)):
        rc, out = replay(packets, key, w, h)
        got = tokens(out, side="od")
        if key == "0":
            got, hold = strip_reset(got)
        want = steps_to_tokens(steps)
        res[key] = {"rc": rc, "equal": rc == 0 and got == want}
        if not res[key]["equal"]:
            res[key]["first_diff"] = next((i for i, (a, b) in enumerate(zip(got, want)) if a != b),
                                          min(len(got), len(want)))
    res["all_equal"] = all(v["equal"] for v in res.values())
    return res

# ---------------------------------------------------------------------------- deviations

# The wire convention (opendisplay_protocol.h, py-opendisplay bitplanes): plane 0 bit 1 = white,
# colour plane bit 1 = colour. SSD16xx RAM takes exactly that with the 0x21 RAM options at
# "normal" (BW RAM 1 = white, RED RAM 1 = colour); 2.x left them at "inverse" (08 / 48, and 88
# after T1), so its uploads came out inverted. 2.x's own boot screen, and the two SSD models it
# tuned by hand (013, 022_LITE: net 0x21 = 00), already follow the rule.
_SSD_POL = ("SSD RAM polarity: 0x21 RAM options set to normal for the wire's 1 = white / "
            "1 = colour planes; the source value inverted the image")
_UC8179_POL = ("UC8179 data polarity: CDI DDX[0] set so DTM1 bit 1 = white, the wire's "
               "convention; the source value inverted the BW plane")
_UC8151_SHL = ("UC8151 scan direction: PSR SHL cleared (03 instead of 07), the orientation of "
               "0xE019, which is correct on glass; the source value mirrors left-right")

_SSD_YFLIP = ("SSD gate scan reversed (0x11 Y increment, 0x45 window and 0x4F start from row 0): "
              "the source drew the wire image mirrored and rotated 180 degrees, a vertical flip")

# key -> [(cmd, byte index, new value, reason)]; every occurrence of cmd is changed. A bytes value
# replaces the data from that index on.
DEVIATIONS: dict[int, list[tuple[int, int, int | bytes, str]]] = {
    **{k: [(0x21, 0, 0x00, _SSD_POL)]
       for k in (0xE002, 0xE00B, 0xE011, 0xE013, 0xE015, 0xE017, 0xE020)},
    **{k: [(0x21, 0, 0x40, _SSD_POL)]
       for k in (0xE004, 0xE00A, 0xE010, 0xE012, 0xE014, 0xE016)},
    **{k: [(0x00, 0, 0x03, _UC8151_SHL)] for k in (0xE10F, 0xE111)},
}
# The 2.7in UC8151 (E019, and E110 for the same panel) is mounted the other way round: PSR UD and
# SHL both set (0F) rotates the source's 03 by 180 degrees.
_UC8151_ROT = ("UC8151 scan direction: PSR UD and SHL set (0F): the 2.7in panel is mounted rotated; "
               "the source value drew the image upside down")
DEVIATIONS[0xE019] = [(0x00, 0, 0x0F, _UC8151_ROT)]
DEVIATIONS[0xE110] = [(0x00, 0, 0x0F, _UC8151_ROT)]
# E007: CDI 30 07 -> 31 07 (data byte 0 is BDZ/BDV/N2OCP/DDX).
DEVIATIONS[0xE007] = [(0x50, 0, 0x31, _UC8179_POL)]
# Y flip: rows 0..H-1 increasing instead of H..0 decreasing (the source's 0x45 start is H, not H-1).
DEVIATIONS[0xE011] += [(0x11, 0, 0x03, _SSD_YFLIP), (0x45, 0, bytes.fromhex("00007f01"), _SSD_YFLIP),
                       (0x4F, 0, bytes.fromhex("0000"), _SSD_YFLIP)]
DEVIATIONS[0xE101] = [(0x11, 0, 0x03, _SSD_YFLIP), (0x45, 0, bytes.fromhex("00002701"), _SSD_YFLIP),
                      (0x4F, 0, bytes.fromhex("0000"), _SSD_YFLIP)]

# Presets checked on glass with the wire test image (upright, not mirrored, colours right):
# key -> where. Their status is "glass".
GLASS: dict[int, str] = {
    0xE002: "glass 2026-11-13: two 4.2in SSD BWR tags",
    0xE00F: "glass 2026-11-13: two 2.9in UC8151 BWR tags",
    0xE019: "glass 2026-11-13: 2.7in UC8151 BWR tag",
    0xE013: "glass 2026-11-13: 1.6in SSD BWR tag",
    0xE01D: "glass 2026-11-13: 1.3in SSD BWR tag",
    0xE01F: "glass 2026-11-13: 2.2in Lite SSD BWR tag",
    0xE020: "glass 2026-11-13: 4.2in SSD BWY tag",
    0xE011: "glass 2026-11-13: two 2.9in SSD BWR tags (2.x 1016 and a 1001-provisioned one)",
    0xE101: "glass 2026-11-13: 2.2in EL022H3WRA 160x296 tag (provisioned as 2.x 1020)",
}


def deviate(key: int, steps: list[tuple]) -> tuple[list[tuple], list[dict]]:
    """Apply DEVIATIONS[key] to a step list -> (new steps, what changed)."""
    out = list(steps)
    done: list[dict] = []
    for cmd, idx, val, why in DEVIATIONS.get(key, []):
        hits = [i for i, s in enumerate(out) if s[0] == "cmd" and s[1] == cmd and len(s[2]) > idx]
        if not hits:
            raise SystemExit(f"0x{key:04X}: deviation on cmd 0x{cmd:02X} matches no step")
        for i in hits:
            c = out[i]
            v = val if isinstance(val, bytes) else bytes([val])
            if len(c[2]) < idx + len(v):
                raise SystemExit(f"0x{key:04X}: deviation on cmd 0x{cmd:02X} is longer than its data")
            new = bytes(c[2][:idx]) + v + bytes(c[2][idx + len(v):])
            if new != c[2] and not any(d["cmd"] == f"0x{cmd:02X}" and d["from"] == c[2].hex(" ")
                                       and d["to"] == new.hex(" ") for d in done):
                done.append({"cmd": f"0x{cmd:02X}", "from": c[2].hex(" "), "to": new.hex(" "),
                             "reason": why})
            out[i] = ("cmd", c[1], new)
    if DEVIATIONS.get(key) and not done:
        raise SystemExit(f"0x{key:04X}: deviation changes nothing (already applied at source?)")
    return out, done

# ---------------------------------------------------------------------------- entries


def build_entry(key: int, name: str, w: int, h: int, scheme: int, idle: int,
                mode_steps: list[tuple], sleep_steps: list[tuple], notes: list[str],
                blocked: list[str], legacy: dict, source: str, verified: str) -> dict:
    if key not in DEVIATIONS or blocked:
        e = _entry(key, name, w, h, scheme, idle, mode_steps, sleep_steps, notes, blocked,
                   legacy, source, verified)
        if key in GLASS and e["status"] in ("equivalent", "extracted"):
            e["status"] = "glass"
            e["verified"] = GLASS[key]
        return e
    alt = _entry(key, name, w, h, scheme, idle, mode_steps, sleep_steps, list(notes),
                 list(blocked), legacy, source, verified)
    steps, done = deviate(key, mode_steps)
    e = _entry(key, name, w, h, scheme, idle, steps, sleep_steps, list(notes), list(blocked),
               legacy, source, verified)
    if e["status"] != "blocked":
        # The packets replay to the corrected steps (equivalence); they do not reproduce the
        # source, on purpose: that is what "corrected" says.
        e["status"] = "corrected" if e["status"] in ("equivalent", "extracted") else e["status"]
        e["verified"] = "untested"
        if key in GLASS and e["status"] == "corrected":
            e["status"] = "glass"
            e["verified"] = GLASS[key]
    e["deviations"] = done
    glass_note = "Checked on glass" if e["status"] == "glass" else "Needs a glass check"
    e["notes"] = e["notes"] + [f"deliberately differs from its source: {d['cmd']} "
                               f"{d['from']} -> {d['to']} ({d['reason']}). {glass_note}"
                               for d in done]
    e["alternatives"] = [{k: alt[k] for k in ("status", "verified", "notes", "packets",
                                              "framed_hex", "drive_bytes", "equivalence")}
                         | {"name": "as the source (" + source + ")"}]
    return e


def _entry(key: int, name: str, w: int, h: int, scheme: int, idle: int,
           mode_steps: list[tuple], sleep_steps: list[tuple], notes: list[str],
           blocked: list[str], legacy: dict, source: str, verified: str) -> dict:
    seq = encode_steps(mode_steps)
    sleep = encode_steps(sleep_steps)
    if len(sleep) > SLEEP_MAX:
        blocked.append("SLEEP_MAX")
    if len(mode_steps) + 1 > MAX_STEPS:
        blocked.append("MAX_STEPS")
    nimg = sum(1 for s in mode_steps if s[0] == "image")
    if nimg != PLANES[scheme]:
        blocked.append("PLANE_COUNT")
    pkts = [(0xB1, 0, panel_body(idle, sleep)), (0xAE, 0, mode_body(0, "full", seq, scheme))]
    framed = b"".join(frame(n, i, b) for i, n, b in pkts)
    eq = check(framed, w, h, mode_steps, sleep_steps) if not blocked else None
    if blocked:
        status = "blocked"
    elif eq["all_equal"]:
        status = "equivalent"
    else:
        status = "differs"
    if status == "equivalent" and verified == "extracted":
        status = "extracted"    # encodes its op list; the op list itself is not cross-checked
    e = {
        "panel_ic_type": key,
        "name": name,
        "aliases": [],
        "notes": notes,
        "source": source,
        "width": w,
        "height": h,
        "legacy": legacy,
        "color_scheme": scheme,
        "status": status,
        "verified": verified if status in ("equivalent", "extracted") else "untested",
        "blocked_on": sorted(set(blocked)),
        "modes": [{"index": 0, "name": "full", "refresh": "full", "passes": 1,
                   "color_scheme": scheme, "planes": PLANES[scheme], "window": False,
                   "seq_bytes": len(seq), "steps": len(mode_steps) + 1,
                   "fits": {"nrf52811": True}}],
        "modes_blocked": [],
        "requires_escapes": [],
        "packets": [] if blocked else [{"id": i, "number": n, "body_hex": b.hex()}
                                       for i, n, b in pkts],
        "framed_hex": "" if blocked else framed.hex(),
        "drive_bytes": 0 if blocked else len(framed),
        "equivalence": eq,
    }
    e["fits_target"] = {"nrf52811": not blocked and len(framed) + 600 <= CONFIG_CAP}
    return e


# Same glass and drive as a 2.x model, other colour: (key, base 2.x model id, name, 3.0 scheme).
# 2.x had no BWY; a 4.2in 1001 tag with yellow particles is this panel.
VARIANTS = [(0xE020, 2, "SSD1619_420_BWY", 2)]


def from_capture(mid: int, colour: int, ic: int, w: int, h: int, *, key: int | None = None,
                 name: str | None = None, scheme: int | None = None) -> dict:
    lines = subprocess.run([str(CAPTURE), str(mid)], capture_output=True, text=True,
                           check=True).stdout.splitlines()
    cut = lines.index("S")
    inv = [ln.split() for ln in lines[:cut] if ln.startswith("N plane")]
    toks, hold = strip_reset(tokens(lines[:cut], side="2x"))
    notes: list[str] = []
    blocked: list[str] = []
    mode_steps = to_steps(toks, notes)
    sleep_steps = to_steps(tokens(lines[cut + 1:], side="2x"), notes)
    fam = "SSD" if ic >= 0x20 and ic < 0x30 else IC[ic]
    for t in inv:
        if t[4] == "1":
            b = invert_plane(mode_steps, fam, int(t[2]), notes)
            if b:
                blocked.append(b)
                notes.append(f"plane {t[2]} is inverted in software by 2.x and {IC[ic]} has no "
                             "known polarity register")
    if hold and hold != 10:
        notes.append(f"T3: 2.x held reset {hold} ms per phase; od_epd_begin_pass holds 10 ms")
    variant = scheme is not None
    scheme = SCHEME[colour] if scheme is None else scheme
    key = 0xE000 + mid if key is None else key
    if variant:
        notes.append(f"same drive as 0x{0xE000 + mid:04X} ({NAMES[mid]}) with colour scheme "
                     f"{scheme}; the same 2.x panel_ic_type {999 + mid}: pick by the panel's colour")
    if scheme == 3:
        per = (w + 7) // 8 * h
        notes.append(f"T4: 2.x wrote {per} B (1 bit/px) per BWRY frame; 3.0 writes the full "
                     f"2 bpp frame ({per * 2} B). Needs a glass check")
    idle = 0 if fam == "SSD" else 1
    legacy = {"panel_ic_type": 999 + mid, "color_scheme": 0 if colour == 1 else 1 if colour == 2
              else 3, "pixel_width": w, "pixel_height": h, "model_id": mid}
    if variant:
        # Not a migration target: 2.x stored this panel as the base model, so an automatic legacy
        # match must keep landing on the base preset. The variant is chosen by hand.
        legacy = {k: v for k, v in legacy.items() if k not in ("panel_ic_type", "model_id")}
    return build_entry(key, name or NAMES[mid], w, h, scheme, idle, mode_steps, sleep_steps,
                       notes, blocked, legacy, "2.x C driver, compiled and captured",
                       "equivalent")


# ---- op-list models ----------------------------------------------------------------------

class Computed(ValueError):
    pass


def _hx(v) -> int:
    try:
        return int(v, 16) if isinstance(v, str) else int(v)
    except ValueError as exc:
        raise Computed(str(v)) from exc


def _op(n: int, o: dict, steps: list[tuple], blocked: list[str]) -> None:
    op = o.get("op")
    if op == "reset":
        if n != 0:
            blocked.append("RESET_MID_SEQUENCE")
    elif op == "cmd":
        steps.append(("cmd", _hx(o["cmd"]), bytes(_hx(x) for x in o.get("data", []))))
    elif op == "data":
        steps.append(("data", bytes(_hx(x) for x in o["data"])))
    elif op == "wait_busy":
        steps.append(("busy",))
    elif op == "delay_ms":
        steps.append(("delay", int(o["ms"])))
    elif op == "pixel_data":
        plane = str(o.get("plane", ""))
        if plane.startswith("interleaved"):
            blocked.append("PIXEL_XFORM")
        elif _hx(o.get("cmd", "0")) in (0xA4, 0xA6):
            blocked.append("SPLIT_CONTROLLER")
        steps.append(("cmd", _hx(o["cmd"]), b""))
        steps.append(("image",))
        # Wire: plane 0 bit 1 = white, colour plane bit 1 = colour. The op list's own data
        # is bit 1 = black on plane 0 unless it says it inverts.
        want_inv = (plane == "black") != bool(o.get("invert"))
        if want_inv:
            steps.append(("inv", 0 if plane == "black" else 1))
    else:
        blocked.append(f"OP_{str(op).upper()}")


def from_oplist(k: int, m: dict) -> dict:
    notes = ["extracted, not cross-checked: op list transcribed, not compiled"]
    if m.get("nrf_ic_type"):
        notes.append(f"same glass as 2.x panel_ic_type {m['nrf_ic_type']}")
    blocked: list[str] = []
    w, h = m.get("width"), m.get("height")
    scheme = SCHEME_BY_NAME.get(m.get("color"), None)
    ctrl = m.get("controller", "")
    fam = ("SSD" if "SSD" in ctrl else "UC8179" if "UC8179" in ctrl
           else "UC8176" if "UC8151" in ctrl else "UCVAR43" if "var43" in ctrl else "UC")
    if not w or not h or scheme is None:
        blocked.append("GEOMETRY")
        w, h, scheme = w or 0, h or 0, 0 if scheme is None else scheme
    ops = []
    for sec in ("init", "refresh_full"):
        v = m.get(sec)
        if not isinstance(v, list):
            blocked.append("UNPARSED")
            v = []
        ops += v
    steps: list[tuple] = []
    for n, o in enumerate(ops):
        if not isinstance(o, dict):
            blocked.append("UNPARSED")
            continue
        try:
            _op(n, o, steps, blocked)
        except Computed as exc:
            blocked.append("COMPUTED_DATA")
            notes.append(f"a register value is computed at run time: {exc}")
    if steps and steps[0] == ("busy",):
        steps = steps[1:]
    # Bare data joins the previous command (as for the 2.x streams).
    clean: list[tuple] = []
    invs = []
    for s in steps:
        if s[0] == "data":
            j = max(i for i, c in enumerate(clean) if c[0] == "cmd")
            c = clean[j]
            clean[j] = ("cmd", c[1], c[2] + s[1])
            if j != len(clean) - 1:
                notes.append("T2: bare data after a busy wait is sent with the command before it")
        elif s[0] == "inv":
            invs.append(s[1])
        else:
            clean.append(s)
    for p in invs:
        b = invert_plane(clean, fam, p, notes)
        if b:
            blocked.append(b)
    sl = m.get("sleep") if isinstance(m.get("sleep"), list) else []
    sleep_steps = []
    for o in sl:
        if not isinstance(o, dict):
            continue
        if o.get("op") == "cmd":
            sleep_steps.append(("cmd", _hx(o["cmd"]), bytes(_hx(x) for x in o.get("data", []))))
        elif o.get("op") == "wait_busy":
            sleep_steps.append(("busy",))
        elif o.get("op") == "delay_ms":
            sleep_steps.append(("delay", int(o["ms"])))
        elif o.get("op") == "reset":
            notes.append("T5: the hardware reset before the sleep commands is left out "
                         "(the panel is awake after a refresh)")
    while len(encode_steps(sleep_steps)) > SLEEP_MAX and any(s[0] == "delay" for s in sleep_steps):
        i = max(i for i, s in enumerate(sleep_steps) if s[0] == "delay")
        del sleep_steps[i]
        notes.append("T6: a sleep delay was dropped to fit the 20 B sleep sequence")
    idle = 0 if fam == "SSD" else 1
    # The loader reads legacy.panel_ic_type as an int: leave it out when 2.x had no such panel.
    legacy = {"color_scheme": scheme, "pixel_width": w, "pixel_height": h}
    if m.get("nrf_ic_type"):
        legacy["panel_ic_type"] = int(m["nrf_ic_type"])
    return build_entry(0xE100 + k, m["name"], int(w), int(h), scheme, idle, clean, sleep_steps,
                       notes, blocked, legacy, "op list (extracted, not cross-checked)",
                       "extracted")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--extra", type=Path, default=REPO / "presets" / "m3_oplists.json")
    ap.add_argument("--extra-only", default="", help="comma list of op-list indices to include")
    ap.add_argument("--out", type=Path, default=REPO / "presets" / "drive_presets_nrf52811.json")
    a = ap.parse_args()
    if not CAPTURE.exists() or not REPLAY.exists():
        subprocess.run(["sh", str(REPO / "host" / "equiv" / "build_capture.sh")], check=True)
    panels = {}
    for ln in subprocess.run([str(CAPTURE), "list"], capture_output=True, text=True,
                             check=True).stdout.splitlines():
        mid, colour, ic, w, h = (int(x) for x in ln.split())
        e = from_capture(mid, colour, ic, w, h)
        panels[f"0x{e['panel_ic_type']:04X}"] = e
        for vkey, vmid, vname, vscheme in VARIANTS:
            if vmid == mid:
                e = from_capture(mid, colour, ic, w, h, key=vkey, name=vname, scheme=vscheme)
                panels[f"0x{e['panel_ic_type']:04X}"] = e
    if a.extra:
        doc = json.loads(a.extra.read_text())
        pick = {int(x) for x in a.extra_only.split(",") if x}
        for k, m in enumerate(doc["models"]):
            if pick and k not in pick:
                continue
            e = from_oplist(k, m)
            panels[f"0x{e['panel_ic_type']:04X}"] = e
    panels = dict(sorted(panels.items()))
    out = {
        "schema": "opendisplay.drive_presets",
        "schema_version": 1,
        "schema_minor": 3,
        "generator": "fw-nrf52811 tools/gen_presets.py",
        "provisional_ids": True,
        "caps": {"nrf52811": CONFIG_CAP, "max_steps": MAX_STEPS, "sleep_max": SLEEP_MAX},
        "target_classes": {"nrf52811": {"max_steps": MAX_STEPS, "window": False,
                                        "config": CONFIG_CAP, "targets": ["nrf52811"]}},
        "transforms": {
            "T1": "software plane inversion moved into the controller's polarity register",
            "T2": "bare data byte joined to the preceding command",
            "T3": "reset pulse 10 ms per phase instead of 50 ms",
            "T4": "BWRY frame is the full 2 bpp frame",
            "T5": "reset before sleep left out",
            "T6": "sleep delay dropped to fit 20 B",
        },
        "statuses": {
            "equivalent": "replays token-identical to the 2.x driver after the transforms",
            "extracted": "replays token-identical to an op list that was not compiled",
            "corrected": "replays token-identical to its source with the listed deviations; "
                         "the uncorrected packets are under alternatives",
            "glass": "equivalent or corrected, and these packets were checked on a real panel "
                     "(see verified)",
            "blocked": "cannot be expressed on this target",
        },
        "names": {e["name"]: k for k, e in panels.items()},
        "panels": panels,
        "native_controllers": {},
    }
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(json.dumps(out, indent=1) + "\n")
    for k, e in panels.items():
        eq = e["equivalence"] or {}
        alt = ""
        if e.get("alternatives"):
            a0 = e["alternatives"][0]
            alt = f" alt={a0['status']}" + ("" if (a0["equivalence"] or {}).get("all_equal")
                                            else "(DIFF)")
        print(f"{k} {e['name'][:34]:34} {e['width']}x{e['height']} s{e['color_scheme']} "
              f"{e['status']:10} bytes={e['drive_bytes']:4} {','.join(e['blocked_on'])} "
              f"{'' if not eq else ('eq' if eq['all_equal'] else 'DIFF ' + json.dumps(eq))}"
              f"{alt}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
