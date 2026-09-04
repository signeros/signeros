#!/usr/bin/env python3
"""Regenerate the site's link-preview images (signeros-web/og-*.png).

Every other image in this repository is markup or comes out of a build. These
two cannot be: a link pasted into a forum, a chat or a social post is unfurled
by somebody else's server, which reads `<meta property="og:image">` and wants a
raster. So they are generated here, offline, from the kiosk's own palette
(src/btc_signer_gui/src/ui/theme.h) and committed - the pages themselves fetch
nothing at runtime, because nothing in any layout references them.

Needs Pillow, which nothing else in this tree does:

    apt install python3-pil        # or: pip install pillow
    python3 scripts/make_og_images.py [--out-dir signeros-web]

Both images are 1200x630, the size every platform crops from. Keep the file
names stable: they are referenced by absolute URL and cached by everything that
has ever unfurled them.
"""

from __future__ import annotations

import argparse
import os
import sys

try:
    from PIL import Image, ImageDraw, ImageFont
except ImportError:  # pragma: no cover - the whole point of the message
    sys.exit("this script needs Pillow: apt install python3-pil")

FONT_DIR = "/usr/share/fonts/truetype/dejavu/"

# The kiosk's palette, which is also the site's.
BG = (13, 17, 23)
INK = (230, 237, 243)
DIM = (154, 164, 178)
MUT = (107, 118, 131)
AMBER = (247, 147, 26)
GREEN = (63, 185, 80)

SIZE = (1200, 630)


def font(name: str, size: int) -> "ImageFont.FreeTypeFont":
    path = os.path.join(FONT_DIR, name)
    if not os.path.exists(path):
        sys.exit("missing font %s - apt install fonts-dejavu-core" % path)
    return ImageFont.truetype(path, size)


def bold(size: int):
    return font("DejaVuSans-Bold.ttf", size)


def book(size: int):
    return font("DejaVuSans.ttf", size)


def mono(size: int):
    return font("DejaVuSansMono.ttf", size)


def glow(im, cx: int, cy: int, r: int, col, strength: int):
    """A radial wash, as concentric translucent circles. Pillow has no gradient
    and importing one would be a dependency for four pixels of atmosphere."""
    overlay = Image.new("RGBA", im.size, (0, 0, 0, 0))
    d = ImageDraw.Draw(overlay)
    steps = 48
    for i in range(steps, 0, -1):
        rr = r * i / steps
        alpha = int(strength * (1 - i / steps) ** 2)
        d.ellipse([cx - rr, cy - rr, cx + rr, cy + rr], fill=col + (alpha,))
    return Image.alpha_composite(im.convert("RGBA"), overlay).convert("RGB")


def chips(d, x: int, y: int, items, col, f) -> None:
    for text in items:
        w = d.textlength(text, font=f)
        d.rounded_rectangle([x, y, x + w + 26, y + 38], radius=2, outline=col, width=1)
        d.text((x + 13, y + 11), text, font=f, fill=col)
        x += w + 26 + 12


def base():
    """Shared furniture: the top rule, the wordmark, the domain."""
    im = Image.new("RGB", SIZE, BG)
    im = glow(im, 1080, -40, 620, AMBER, 26)
    im = glow(im, 40, 700, 520, GREEN, 12)
    d = ImageDraw.Draw(im)
    d.rectangle([0, 0, SIZE[0] - 1, 4], fill=AMBER)
    d.text((64, 52), "SIGNER://OS", font=mono(26), fill=AMBER)
    f = mono(24)
    d.text((1136 - d.textlength("signeros.org", font=f), 56), "signeros.org",
           font=f, fill=MUT)
    return im, d


def project_card(path: str) -> None:
    """For index.html and paper_wallet.html: somebody who wants a signer."""
    im, d = base()
    d.text((64, 150), "AIR-GAPPED", font=bold(86), fill=INK)
    d.text((64, 240), "BITCOIN WALLET", font=bold(86), fill=AMBER)
    d.text((64, 330), "ON A USB STICK", font=bold(86), fill=INK)
    d.text((66, 452), "Boot a computer you already own. It runs in memory, cannot go",
           font=book(25), fill=DIM)
    d.text((66, 486), "online, cannot see your disks, and forgets everything at power-off.",
           font=book(25), fill=DIM)
    chips(d, 64, 540,
          ["NEVER ONLINE", "RAM ONLY", "SIGNS PSBT FILES", "FREE & OPEN SOURCE"],
          MUT, mono(17))
    im.save(path, optimize=True)


def gift_card(path: str) -> None:
    """For gift_wallet.html and redeem_gift.html: somebody giving or given one."""
    im, d = base()
    d.text((64, 150), "GIVE BITCOIN", font=bold(86), fill=INK)
    d.text((64, 240), "ON PAPER", font=bold(86), fill=AMBER)
    d.text((66, 360), "A printable gift card with the recovery words written in by hand,",
           font=book(25), fill=DIM)
    d.text((66, 394), "a wallet made on a machine that cannot go online, and a page the",
           font=book(25), fill=DIM)
    d.text((66, 428), "person you give it to can follow on their own.",
           font=book(25), fill=DIM)
    chips(d, 64, 500,
          ["A4 TEMPLATE", "PRINT IT BLANK", "NO SEED EVER TYPED", "FREE"],
          MUT, mono(17))
    d.text((66, 570), "signeros.org/gift_wallet.html", font=mono(22), fill=AMBER)
    im.save(path, optimize=True)


def main() -> None:
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out-dir", default=os.path.join(here, "signeros-web"),
                    help="where the PNGs go (default: signeros-web/)")
    args = ap.parse_args()

    for name, fn in (("og-signeros.png", project_card), ("og-gift.png", gift_card)):
        path = os.path.join(args.out_dir, name)
        fn(path)
        print("  wrote %s (%d bytes)" % (path, os.path.getsize(path)))


if __name__ == "__main__":
    main()
