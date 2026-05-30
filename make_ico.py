"""Run once before building the installer: python make_ico.py"""
from PIL import Image, ImageDraw, ImageFont

_CYAN = (0, 240, 255, 255)   # #00F0FF — matches favicon.svg fill
_NAVY = (15, 23, 42,  255)   # #0f172a — matches favicon.svg text

# Font candidates in order of preference (weight-900 / black first)
_FONTS = [
    r"C:\Windows\Fonts\ariblk.ttf",    # Arial Black  (weight 900 — exact favicon match)
    r"C:\Windows\Fonts\arialbd.ttf",   # Arial Bold
    r"C:\Windows\Fonts\segoeuib.ttf",  # Segoe UI Bold (Windows 11 system font)
    r"C:\Windows\Fonts\calibrib.ttf",  # Calibri Bold
    r"C:\Windows\Fonts\verdanab.ttf",  # Verdana Bold  (crisp at small sizes)
]


def _load_font(size: int) -> ImageFont.FreeTypeFont:
    for path in _FONTS:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    return ImageFont.load_default()


def make(target: int) -> Image.Image:
    """Render at 4× then downsample — gives smooth anti-aliased edges."""
    S = target * 4
    radius = max(4, int(S * 0.22))   # rx≈22% matches favicon rx="7" on 32px base

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


sizes  = [16, 32, 48, 64, 128, 256]
images = [make(s) for s in sizes]
images[0].save("lateralx.ico", format="ICO", append_images=images[1:])
print(f"lateralx.ico — {len(sizes)} sizes: {sizes}")
