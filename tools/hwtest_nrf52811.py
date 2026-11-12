#!/usr/bin/env python3
"""Hardware test for the 3.0 nRF52811 firmware over BLE. Needs only `bleak`.

    hwtest_nrf52811.py scan
    hwtest_nrf52811.py ident   ADDR
    hwtest_nrf52811.py backup  ADDR [--out cfg.bin]        CONFIG_READ to a file
    hwtest_nrf52811.py config  ADDR --preset 0xE011 [--presets FILE] [--from cfg.bin]
    hwtest_nrf52811.py upload  ADDR [--pattern bars|checker|white|black|colour] [--fast]
    hwtest_nrf52811.py spiraw  ADDR
    hwtest_nrf52811.py negative ADDR                      the refusals: unknown opcode, oversize, ...
    hwtest_nrf52811.py restore ADDR --from cfg.bin
    hwtest_nrf52811.py dfu     ADDR --zip EPD-nRF52-ota.zip  (Secure DFU, FE59)

`config` keeps every packet of the stored config (pins, LEDs, buttons, ...) and replaces only
the drive packets (0xAE..0xB1) with the preset's, then patches display 0's width, height and
colour scheme to the preset and clears the compression bits. Run `backup` first.

Every reply is printed in hex. Nothing here retries a write on its own.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import struct
import sys
import time
import zipfile
import zlib
from pathlib import Path

from bleak import BleakClient, BleakScanner

CHAR = "00002446-0000-1000-8000-00805f9b34fb"
DFU_SVC = "0000fe59-0000-1000-8000-00805f9b34fb"
DFU_CP = "8ec90001-f315-4f60-9fb8-838830daea50"
DFU_PKT = "8ec90002-f315-4f60-9fb8-838830daea50"
HERE = Path(__file__).resolve().parent
PRESETS = HERE.parent / "presets" / "drive_presets_nrf52811.json"

# Legacy (0x00-0x7F) packet body sizes, from od_config_tlv_body_size() of this build.
LEGACY = {0x01: 22, 0x02: 22, 0x04: 30, 0x20: 46, 0x21: 22, 0x23: 30, 0x24: 30, 0x25: 30,
          0x26: 160, 0x27: 64, 0x28: 32, 0x29: 32, 0x2A: 32, 0x2B: 32, 0x2C: 288, 0x2D: 128,
          0x2E: 157, 0x2F: 541, 0x30: 116, 0x31: 36}
DRIVE = (0xAE, 0xAF, 0xB0, 0xB1)


def crc_ccitt(data: bytes) -> int:
    buf = bytearray(data)
    buf[0:2] = b"\0\0"
    crc = 0xFFFF
    for b in buf:
        crc ^= b << 8
        for _ in range(8):
            crc = ((crc << 1) ^ 0x1021) & 0xFFFF if crc & 0x8000 else (crc << 1) & 0xFFFF
    return crc


def split_config(blob: bytes) -> tuple[int, list[tuple[int, int, bytes]]]:
    """-> (version, [(number, id, body)]). Raises on a blob it cannot walk to the CRC."""
    ver, i, end, out = blob[2], 3, len(blob) - 2, []
    while i < end:
        num, pid = blob[i], blob[i + 1]
        if pid >= 0x80:
            n = blob[i + 2] | blob[i + 3] << 8
            out.append((num, pid, blob[i + 4:i + 4 + n]))
            i += 4 + n
        elif pid in LEGACY:
            out.append((num, pid, blob[i + 2:i + 2 + LEGACY[pid]]))
            i += 2 + LEGACY[pid]
        else:
            raise ValueError(f"unknown legacy packet 0x{pid:02X} at {i}")
    if i != end:
        raise ValueError("config does not end at its CRC")
    return ver, out


def join_config(ver: int, pkts: list[tuple[int, int, bytes]]) -> bytes:
    body = bytearray(b"\0\0" + bytes([ver]))
    for num, pid, b in sorted(pkts, key=lambda p: p[1] >= 0x80):   # 0x80+ after legacy
        body += bytes([num, pid]) + (struct.pack("<H", len(b)) if pid >= 0x80 else b"") + b
    return bytes(body) + struct.pack("<H", crc_ccitt(bytes(body)))


class Dev:
    def __init__(self, client: BleakClient):
        self.c = client
        self.q: asyncio.Queue[bytes] = asyncio.Queue()

    async def start(self):
        await self.c.start_notify(CHAR, lambda _h, d: self.q.put_nowait(bytes(d)))

    def drain(self):
        while not self.q.empty():
            self.q.get_nowait()

    async def cmd(self, op: int, body: bytes = b"", *, wait: float = 5.0, expect: int = 1,
                  quiet: bool = False, response: bool = True) -> list[bytes]:
        self.drain()
        await self.c.write_gatt_char(CHAR, struct.pack(">H", op) + body, response=response)
        out = []
        try:
            while len(out) < expect:
                out.append(await asyncio.wait_for(self.q.get(), wait))
        except asyncio.TimeoutError:
            pass
        if not quiet:
            print(f"  0x{op:04X} {body[:16].hex()}{'..' if len(body) > 16 else ''} -> "
                  + (" | ".join(r.hex() for r in out) if out else "(no reply)"))
        return out


async def connect(addr: str) -> tuple[BleakClient, Dev]:
    c = BleakClient(addr, timeout=20.0)
    await c.connect()
    d = Dev(c)
    await d.start()
    print(f"connected {addr}, MTU {c.mtu_size}")
    return c, d


def decode_ident(r: bytes) -> dict:
    if len(r) < 5 or r[:2] != b"\x00\x46":
        return {"raw": r.hex()}
    n = r[4]
    disp = [struct.unpack_from("<HHHB", r, 5 + 7 * i) for i in range(n)]
    t = r[5 + 7 * n:]
    return {"protocol_minor": r[2], "fw_target": r[3], "displays": disp,
            "flags": t[0], "config_driven": bool(t[0] & 1), "needs_migration": bool(t[0] & 2),
            "max_config": t[1] | t[2] << 8, "max_steps": t[3] | t[4] << 8, "escapes": t[5]}


async def do_ident(d: Dev):
    fw = await d.cmd(0x0043)
    if fw and len(fw[0]) >= 5:
        f = fw[0]
        print(f"  firmware {f[2]}.{f[3]} sha {f[5:5 + f[4]].decode(errors='replace')}")
    r = await d.cmd(0x0046)
    print("  READ_IDENT", json.dumps(decode_ident(r[0])) if r else "none")
    m = await d.cmd(0x0044)
    if m:
        print(f"  MSD {m[0][2:].hex()}  dynamic bytes {'all FF (not drivable)' if m[0][4:15] == b'\xff' * 11 else 'live'}")


async def read_config(d: Dev) -> bytes:
    d.drain()
    await d.c.write_gatt_char(CHAR, b"\x00\x40", response=True)
    data, total, chunk = bytearray(), None, 0
    t0 = time.time()
    while total is None or len(data) < total:
        r = await asyncio.wait_for(d.q.get(), 5.0)
        if r[:2] != b"\x00\x40":
            raise RuntimeError(f"CONFIG_READ refused: {r.hex()}")
        c = r[2] | r[3] << 8
        if c != chunk:
            raise RuntimeError(f"chunk {c}, expected {chunk}")
        if c == 0:
            total = r[4] | r[5] << 8
            data += r[6:]
        else:
            data += r[4:]
        chunk += 1
    print(f"  CONFIG_READ {len(data)} B in {chunk} chunks, {time.time() - t0:.2f} s")
    return bytes(data)


async def write_config(d: Dev, blob: bytes) -> bool:
    if len(blob) <= 200:
        r = await d.cmd(0x0041, blob)
        return bool(r) and r[0][0] == 0
    r = await d.cmd(0x0041, struct.pack("<H", len(blob)) + blob[:200])
    if not r or r[0][0] != 0:
        return False
    for o in range(200, len(blob), 200):
        r = await d.cmd(0x0042, blob[o:o + 200], quiet=o + 200 < len(blob))
        if not r or r[0][0] != 0:
            print(f"  chunk at {o} refused: {r[0].hex() if r else 'no reply'}")
            return False
    return True


def preset_entry(path: Path, key: str) -> dict:
    e = json.loads(path.read_text())["panels"][key]
    if not e["packets"]:
        raise SystemExit(f"{key} {e['name']}: {e['status']} {e['blocked_on']}, no packets")
    return e


async def do_config(d: Dev, key: str, presets: Path, base: Path | None):
    e = preset_entry(presets, key)
    blob = base.read_bytes() if base else await read_config(d)
    ver, pkts = split_config(blob)
    pkts = [p for p in pkts if p[1] not in DRIVE]
    for i, (num, pid, b) in enumerate(pkts):
        if pid == 0x20 and b[0] == 0:   # display instance 0
            b = bytearray(b)
            struct.pack_into("<HHH", b, 2, e["panel_ic_type"], e["width"], e["height"])
            b[21] = e["color_scheme"]
            b[22] &= ~0x03 & 0xFF   # no streaming/zip decompression on this target
            pkts[i] = (num, pid, bytes(b))
            break
    else:
        raise SystemExit("the stored config has no display 0 (0x20): write one with pins first")
    for p in e["packets"]:
        pkts.append((p["number"], p["id"], bytes.fromhex(p["body_hex"])))
    new = join_config(ver, pkts)
    print(f"  preset {key} {e['name']} ({e['status']}), config {len(blob)} -> {len(new)} B")
    t0 = time.time()
    ok = await write_config(d, new)
    print(f"  write {'OK' if ok else 'REFUSED'} in {time.time() - t0:.2f} s")
    back = await read_config(d)
    print(f"  read-back {'identical' if back == new else 'DIFFERENT'}")
    await do_ident(d)


def pattern(kind: str, w: int, h: int, scheme: int) -> bytes:
    if scheme == 3:   # BWRY 2 bpp: 00 black 01 white 10 yellow 11 red
        row = bytearray()
        for x in range(0, w, 4):
            px = [((x + k) * 4 // w) & 3 for k in range(4)] if kind in ("bars", "colour") else \
                 [1] * 4 if kind == "white" else [0] * 4
            row.append(px[0] << 6 | px[1] << 4 | px[2] << 2 | px[3])
        return bytes(row) * h
    bw = (w + 7) // 8
    if kind == "white":
        p0 = b"\xff" * bw * h
    elif kind == "black":
        p0 = b"\x00" * bw * h
    elif kind == "checker":
        p0 = b"".join((b"\xf0" if (y // 16) & 1 else b"\x0f") * bw for y in range(h))
    else:   # bars: left half white, right half black
        p0 = (b"\xff" * (bw // 2) + b"\x00" * (bw - bw // 2)) * h
    if scheme == 0:
        return p0
    p1 = b"".join((b"\xff" if y < h // 4 else b"\x00") * bw for y in range(h))   # top quarter colour
    return p0 + p1


async def do_upload(d: Dev, kind: str, fast: bool):
    r = await d.cmd(0x0046, quiet=True)
    info = decode_ident(r[0]) if r else {}
    if not info.get("displays"):
        raise SystemExit("no display in READ_IDENT")
    _ic, w, h, scheme = info["displays"][0]
    data = pattern(kind, w, h, scheme)
    print(f"  {w}x{h} scheme {scheme}: {len(data)} B, pattern {kind}")
    t0 = time.time()
    r = await d.cmd(0x0070)
    if not r or r[0][:2] != b"\x00\x70":
        return
    step = min(d.c.mtu_size - 3 - 2, 240)
    for o in range(0, len(data), step):
        r = await d.cmd(0x0071, data[o:o + step], quiet=True)
        if not r or r[0][:2] != b"\x00\x71":
            print(f"  DATA at {o}: {r[0].hex() if r else 'no reply'}")
            return
    t1 = time.time()
    r = await d.cmd(0x0072, b"\x01" if fast else b"", expect=2, wait=120.0)
    t2 = time.time()
    done = "SUCCESS" if any(x[:2] == b"\x00\x73" for x in r) else "NO 0x73"
    print(f"  transfer {t1 - t0:.1f} s, refresh {t2 - t1:.1f} s, {done}")


async def do_spiraw(d: Dev):
    await d.cmd(0x0084, b"\x00\x00")             # OPEN, pins and power only
    await d.cmd(0x0084, b"\x04\x0a")             # RESET 10 ms
    await d.cmd(0x0084, b"\x03\xe8\x03")         # BUSY wait up to 1000 ms -> elapsed, still_busy
    await d.cmd(0x0084, b"\x09")                 # unknown sub -> NACK
    await d.cmd(0x0084, b"\x05")                 # CLOSE


async def do_negative(d: Dev):
    print("  expect silence:")
    await d.cmd(0x0099, wait=2.0)
    print("  expect [00 50 03] (no security module):")
    await d.cmd(0x0050)
    print("  expect [ff 52 00 00] (no power latch):")
    await d.cmd(0x0052)
    print("  expect [ff 71 fe] only if the MTU allows a 245 B write; else the stack refuses it:")
    if d.c.mtu_size >= 248:
        await d.cmd(0x0071, bytes(243))
    print("  expect [ff 41 00 00] (declared 2001 B > 2000):")
    await d.cmd(0x0041, b"\xd1\x07" + bytes(200))
    print("  expect [ff 70 ...] for a compressed START:")
    await d.cmd(0x0070, b"\x00\x40\x00\x00")
    print("  expect silence for END with no transfer:")
    await d.cmd(0x0072, wait=2.0)


async def do_dfu(addr: str, zpath: Path):
    c, d = await connect(addr)
    r = await d.cmd(0x0051)
    try:
        await c.disconnect()
    except Exception:   # noqa: BLE001 - the device resets
        pass
    if not r or r[0][:2] != b"\x00\x51":
        print("  no ENTER_DFU ack; trying anyway")
    print("  scanning for the DFU bootloader (FE59)...")
    dev = None
    for _ in range(20):
        found = await BleakScanner.discover(timeout=2.0, return_adv=True)
        for dv, adv in found.values():
            if DFU_SVC in [u.lower() for u in adv.service_uuids] or (dv.name or "") == "DfuTarg":
                dev = dv
        if dev:
            break
    if not dev:
        raise SystemExit("no DFU target found; use nRF Connect with the zip instead")
    print(f"  DFU target {dev.address} {dev.name}")
    with zipfile.ZipFile(zpath) as z:
        man = json.loads(z.read("manifest.json"))["manifest"]["application"]
        dat, binf = z.read(man["dat_file"]), z.read(man["bin_file"])
    async with BleakClient(dev, timeout=20.0) as dc:
        q: asyncio.Queue[bytes] = asyncio.Queue()
        await dc.start_notify(DFU_CP, lambda _h, x: q.put_nowait(bytes(x)))

        async def cp(b: bytes) -> bytes:
            await dc.write_gatt_char(DFU_CP, b, response=True)
            r = await asyncio.wait_for(q.get(), 10.0)
            if r[0] != 0x60 or r[1] != b[0] or r[2] != 0x01:
                raise RuntimeError(f"DFU op {b.hex()} -> {r.hex()}")
            return r

        await cp(b"\x02\x00\x00")                       # PRN off
        mtu = max(20, min(dc.mtu_size - 3, 244))

        async def send(obj: int, payload: bytes, maxsz: int):
            for o in range(0, len(payload), maxsz):
                part = payload[o:o + maxsz]
                await cp(bytes([0x01, obj]) + struct.pack("<I", len(part)))   # create
                for k in range(0, len(part), mtu):
                    await dc.write_gatt_char(DFU_PKT, part[k:k + mtu], response=False)
                r = await cp(b"\x03")                    # CRC over everything of this type so far
                off, c32 = struct.unpack_from("<II", r, 3)
                if off != o + len(part) or c32 != zlib.crc32(payload[:o + len(part)]):
                    raise RuntimeError(f"CRC mismatch at {off}")
                await cp(b"\x04")                        # execute
                print(f"  obj {obj}: {o + len(part)}/{len(payload)}", end="\r")
            print()

        r = await cp(b"\x06\x01")                         # select command
        await send(1, dat, struct.unpack_from("<I", r, 3)[0])
        r = await cp(b"\x06\x02")                         # select data
        t0 = time.time()
        await send(2, binf, struct.unpack_from("<I", r, 3)[0])
        print(f"  image sent in {time.time() - t0:.1f} s; the bootloader validates and starts it")


async def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("what")
    ap.add_argument("addr", nargs="?")
    ap.add_argument("--preset", default="0xE011")
    ap.add_argument("--presets", type=Path, default=PRESETS)
    ap.add_argument("--from", dest="src", type=Path)
    ap.add_argument("--out", type=Path, default=Path("cfg_backup.bin"))
    ap.add_argument("--pattern", default="bars")
    ap.add_argument("--fast", action="store_true")
    ap.add_argument("--zip", type=Path)
    a = ap.parse_args()
    if a.what == "scan":
        for dv, adv in (await BleakScanner.discover(timeout=8.0, return_adv=True)).values():
            if adv.manufacturer_data:
                print(dv.address, dv.name, adv.rssi, {k: v.hex() for k, v in adv.manufacturer_data.items()})
        return 0
    if a.what == "dfu":
        await do_dfu(a.addr, a.zip)
        return 0
    c, d = await connect(a.addr)
    try:
        if a.what == "ident":
            await do_ident(d)
        elif a.what == "backup":
            a.out.write_bytes(await read_config(d))
            print(f"  saved {a.out}")
        elif a.what == "config":
            await do_config(d, a.preset, a.presets, a.src)
        elif a.what == "upload":
            await do_upload(d, a.pattern, a.fast)
        elif a.what == "spiraw":
            await do_spiraw(d)
        elif a.what == "negative":
            await do_negative(d)
        elif a.what == "restore":
            ok = await write_config(d, a.src.read_bytes())
            print(f"  restore {'OK' if ok else 'REFUSED'}")
        else:
            raise SystemExit(f"unknown step {a.what}")
    finally:
        await c.disconnect()
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
