#!/usr/bin/env python3
"""Convert a QEMU screendump (binary PPM) to PNG. Standard library only.

QEMU's `screendump` writes PPM, which most image viewers will not open. This
exists so that looking at what the kiosk actually rendered needs no image
tooling installed on the build machine - which matters, because the Buildroot
host QEMU is built without GTK or SDL and cannot open a window at all.

    python3 scripts/ppm2png.py screen.ppm [screen.png] [--scale 2]
"""

from __future__ import annotations

import argparse
import struct
import sys
import zlib


def read_ppm(path: str) -> tuple[int, int, bytes]:
    with open(path, "rb") as f:
        data = f.read()

    # P6 <width> <height> <maxval>, whitespace-separated, # comments allowed.
    tokens: list[bytes] = []
    i = 0
    while len(tokens) < 4:
        while i < len(data) and data[i:i + 1].isspace():
            i += 1
        if data[i:i + 1] == b"#":
            while i < len(data) and data[i] != 0x0A:
                i += 1
            continue
        j = i
        while j < len(data) and not data[j:j + 1].isspace():
            j += 1
        tokens.append(data[i:j])
        i = j
    i += 1

    if tokens[0] != b"P6":
        raise SystemExit("%s is not a binary PPM (magic %r)" % (path, tokens[0]))
    width, height, maxval = int(tokens[1]), int(tokens[2]), int(tokens[3])
    if maxval != 255:
        raise SystemExit("only 8-bit PPMs are supported (maxval %d)" % maxval)

    pixels = data[i:i + width * height * 3]
    if len(pixels) < width * height * 3:
        raise SystemExit("%s is truncated" % path)
    return width, height, pixels


def write_png(path: str, width: int, height: int, pixels: bytes, scale: int) -> tuple[int, int]:
    out_w, out_h = width // scale, height // scale

    raw = bytearray()
    for y in range(out_h):
        raw.append(0)                      # filter type 0 (None) per scanline
        row = (y * scale) * width * 3
        if scale == 1:
            raw += pixels[row:row + width * 3]
        else:
            for x in range(out_w):
                off = row + (x * scale) * 3
                raw += pixels[off:off + 3]

    def chunk(kind: bytes, payload: bytes) -> bytes:
        return (struct.pack(">I", len(payload)) + kind + payload +
                struct.pack(">I", zlib.crc32(kind + payload) & 0xFFFFFFFF))

    png = b"\x89PNG\r\n\x1a\n"
    png += chunk(b"IHDR", struct.pack(">IIBBBBB", out_w, out_h, 8, 2, 0, 0, 0))
    png += chunk(b"IDAT", zlib.compress(bytes(raw), 6))
    png += chunk(b"IEND", b"")

    with open(path, "wb") as f:
        f.write(png)
    return out_w, out_h


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input")
    ap.add_argument("output", nargs="?")
    ap.add_argument("--scale", type=int, default=1,
                    help="downscale by this integer factor (default 1)")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    output = args.output or (args.input.rsplit(".", 1)[0] + ".png")
    if args.scale < 1:
        raise SystemExit("--scale must be at least 1")

    w, h, px = read_ppm(args.input)
    ow, oh = write_png(output, w, h, px, args.scale)
    if not args.quiet:
        print("%s: %dx%d -> %s (%dx%d)" % (args.input, w, h, output, ow, oh))
    return 0


if __name__ == "__main__":
    sys.exit(main())
