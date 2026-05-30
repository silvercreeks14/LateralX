"""
Run once before building the installer: python make_ico.py
Builds a proper multi-size ICO by embedding PNG data for each size.
Pillow 12.x has a broken ICO saver so we construct the binary manually.
"""
import io
import struct
from PIL import Image, ImageDraw, ImageFont

_CYAN = (0, 240, 255, 255)   # #00F0FF
_NAVY = (15, 23, 42,  255)   # #0f172a

_FONTS = [
    r"C:\Windows\Fonts\ariblk.ttf",    # Arial Black  (weight 900)
    r"C:\Windows\Fonts\arialbd.ttf",   # Arial Bold
    r"C:\Windows\Fonts\segoeuib.ttf",  # Segoe UI Bold
    r"C:\Windows\Fonts\calibrib.ttf",  # Calibri Bold
    r"C:\Windows\Fonts\verdanab.ttf",  # Verdana Bold
]


def _load_font(size: int) -> ImageFont.FreeTypeFont:
    for path in _FONTS:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    return ImageFont.load_default()


def _make_frame(target: int) -> Image.Image:
    """Render at 4x then downsample — smooth anti-aliased edges."""
    S      = target * 4
    radius = max(4, int(S * 0.22))

    img  = Image.new("RGBA", (S, S), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([0, 0, S - 1, S - 1], radius=radius, fill=_CYAN)

    font = _load_font(int(S * 0.42))
    bb   = draw.textbbox((0, 0), "LX", font=font)
    tw, th = bb[2] - bb[0], bb[3] - bb[1]
    draw.text(
        ((S - tw) // 2 - bb[0], (S - th) // 2 - bb[1]),
        "LX", fill=_NAVY, font=font,
    )
    return img.resize((target, target), Image.LANCZOS)


def _build_ico(frames: list[tuple[int, Image.Image]], output: str) -> None:
    """
    Construct an ICO file that embeds PNG data for each frame.
    Supported on Windows Vista+ (i.e. all relevant Windows versions).
    """
    # Encode every frame as PNG bytes
    entries: list[tuple[int, bytes]] = []
    for size, img in frames:
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        entries.append((size, buf.getvalue()))

    n = len(entries)
    # Offset where image data starts: 6-byte header + n * 16-byte dir entries
    data_start = 6 + n * 16

    header = struct.pack("<HHH", 0, 1, n)   # reserved=0, type=1 (ICO), count

    directory = b""
    blob      = b""
    offset    = data_start

    for size, png in entries:
        w = size if size < 256 else 0  # 0 encodes 256 in ICO spec
        directory += struct.pack(
            "<BBBBHHII",
            w, w,           # width, height
            0, 0,           # colorCount, reserved
            1, 32,          # planes, bitCount (32 = RGBA)
            len(png),       # size of image data
            offset,         # offset from file start
        )
        blob   += png
        offset += len(png)

    with open(output, "wb") as f:
        f.write(header + directory + blob)


# ── Main ──────────────────────────────────────────────────────────────────────

SIZES  = [16, 32, 48, 64, 128, 256]
frames = [(s, _make_frame(s)) for s in SIZES]
_build_ico(frames, "lateralx.ico")

import os
size_kb = os.path.getsize("lateralx.ico") / 1024
print(f"lateralx.ico — {len(SIZES)} sizes {SIZES} — {size_kb:.1f} KB")
