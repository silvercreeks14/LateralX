"""Run once before building the installer: python make_ico.py"""
from PIL import Image, ImageDraw, ImageFont

_CYAN = (0, 240, 255, 255)
_NAVY = (15, 23, 42, 255)

def make(size):
    r = max(4, int(size * 0.22))
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)
    d.rounded_rectangle([0, 0, size - 1, size - 1], radius=r, fill=_CYAN)
    fs = int(size * 0.44)
    font = None
    for candidate in [r"C:\Windows\Fonts\arialbd.ttf", r"C:\Windows\Fonts\arial.ttf"]:
        try:
            font = ImageFont.truetype(candidate, fs)
            break
        except Exception:
            pass
    if not font:
        font = ImageFont.load_default()
    bb = d.textbbox((0, 0), "LX", font=font)
    d.text(
        ((size - (bb[2] - bb[0])) // 2 - bb[0],
         (size - (bb[3] - bb[1])) // 2 - bb[1]),
        "LX", fill=_NAVY, font=font,
    )
    return img

images = [make(s) for s in [16, 32, 48, 256]]
images[0].save("lateralx.ico", format="ICO", append_images=images[1:])
print("lateralx.ico created successfully.")
