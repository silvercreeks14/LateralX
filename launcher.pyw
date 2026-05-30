"""
LateralX — System Tray Launcher
Double-click this file to start LateralX with no terminal window.
The app runs silently in the background; control it from the tray icon.
"""
import os
import sys
import time
import subprocess
import threading
import webbrowser
from pathlib import Path

APP_URL      = "http://localhost:8000"
PROJECT_ROOT = Path(__file__).parent
LOG_FILE     = PROJECT_ROOT / "lateralx.log"

# ── Icon colours — match the favicon.svg exactly ─────────────────────────────
_CYAN  = (0,   240, 255, 255)   # #00F0FF  fill
_NAVY  = (15,  23,  42,  255)   # #0f172a  text
_GREY  = (80,  100, 120, 255)   # muted fill used when server is not yet ready

# ── Windows: hide any subprocess console windows ─────────────────────────────
_NO_WIN = subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0

# ── Global server process handle ─────────────────────────────────────────────
_server: subprocess.Popen | None = None


# ─────────────────────────────────────────────────────────────────────────────
# Icon drawing
# ─────────────────────────────────────────────────────────────────────────────

def _make_icon(size: int = 64, muted: bool = False) -> "Image.Image":
    from PIL import Image, ImageDraw, ImageFont

    fill   = _GREY if muted else _CYAN
    radius = max(4, int(size * 0.22))          # matches rx="7" on 32 px base

    img  = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    draw.rounded_rectangle([0, 0, size - 1, size - 1], radius=radius, fill=fill)

    # "LX" centred, dark navy — try to load a bold system font
    text       = "LX"
    font_size  = int(size * 0.44)
    font       = None
    for candidate in ["arialbd.ttf", "arial.ttf",
                      r"C:\Windows\Fonts\arialbd.ttf",
                      r"C:\Windows\Fonts\arial.ttf"]:
        try:
            from PIL import ImageFont
            font = ImageFont.truetype(candidate, font_size)
            break
        except Exception:
            continue
    if font is None:
        from PIL import ImageFont
        font = ImageFont.load_default()

    bbox   = draw.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(((size - tw) // 2 - bbox[0],
               (size - th) // 2 - bbox[1]),
              text, fill=_NAVY, font=font)

    return img


# ─────────────────────────────────────────────────────────────────────────────
# Frontend build
# ─────────────────────────────────────────────────────────────────────────────

def _build_frontend_if_needed() -> None:
    dist = PROJECT_ROOT / "frontend" / "dist" / "index.html"
    if dist.exists():
        return
    log = open(LOG_FILE, "a")
    subprocess.run(
        ["npm", "install"],
        cwd=str(PROJECT_ROOT / "frontend"),
        stdout=log, stderr=log,
        creationflags=_NO_WIN,
    )
    subprocess.run(
        ["npm", "run", "build"],
        cwd=str(PROJECT_ROOT / "frontend"),
        stdout=log, stderr=log,
        creationflags=_NO_WIN,
    )
    log.close()


# ─────────────────────────────────────────────────────────────────────────────
# Server lifecycle
# ─────────────────────────────────────────────────────────────────────────────

def _start_server() -> None:
    global _server
    log = open(LOG_FILE, "a")
    _server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app",
         "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(PROJECT_ROOT),
        stdout=log, stderr=log,
        creationflags=_NO_WIN,
    )


def _stop_server() -> None:
    global _server
    if _server and _server.poll() is None:
        _server.terminate()
        try:
            _server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            _server.kill()
    _server = None


def _wait_for_server(timeout: int = 30) -> bool:
    import urllib.request, urllib.error
    for _ in range(timeout):
        try:
            urllib.request.urlopen(APP_URL, timeout=1)
            return True
        except Exception:
            time.sleep(1)
    return False


# ─────────────────────────────────────────────────────────────────────────────
# Tray actions
# ─────────────────────────────────────────────────────────────────────────────

def _open(icon=None, item=None) -> None:
    webbrowser.open(APP_URL)


def _restart(icon=None, item=None) -> None:
    if icon:
        icon.icon  = _make_icon(muted=True)
        icon.title = "LateralX — Restarting…"
    _stop_server()
    time.sleep(1)
    _start_server()
    if _wait_for_server():
        if icon:
            icon.icon  = _make_icon()
            icon.title = "LateralX  •  localhost:8000"
        webbrowser.open(APP_URL)
    else:
        if icon:
            icon.title = "LateralX — Failed to restart (check lateralx.log)"


def _view_log(icon=None, item=None) -> None:
    if LOG_FILE.exists():
        os.startfile(str(LOG_FILE))


def _exit(icon, item) -> None:
    _stop_server()
    icon.stop()


# ─────────────────────────────────────────────────────────────────────────────
# Startup sequence  (runs in pystray's setup thread)
# ─────────────────────────────────────────────────────────────────────────────

def _startup(icon: "pystray.Icon") -> None:
    icon.visible = True
    icon.notify(
        "Starting up… browser will open when ready.\n"
        "Find the LX icon near your clock (↑ in taskbar) to stop LateralX.",
        title="LateralX",
    )

    # Step 1 — build frontend if this is the first run
    dist = PROJECT_ROOT / "frontend" / "dist" / "index.html"
    if not dist.exists():
        icon.title = "LateralX — Building frontend (first run, ~1 min)…"
        _build_frontend_if_needed()

    # Step 2 — start uvicorn
    icon.title = "LateralX — Starting server…"
    _start_server()

    # Step 3 — wait until responsive, then open browser
    icon.title = "LateralX — Waiting for server…"
    if _wait_for_server():
        icon.icon  = _make_icon()                       # full-colour icon
        icon.title = "LateralX  •  localhost:8000"
        icon.notify(
            "Server is ready — opening browser now.\n"
            "Right-click the LX icon near the clock to stop.",
            title="LateralX — Ready",
        )
        webbrowser.open(APP_URL)
    else:
        icon.notify(
            "Server failed to start. Check lateralx.log for details.",
            title="LateralX — Error",
        )
        icon.title = "LateralX — Server failed to start (check lateralx.log)"


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    try:
        import pystray
    except ImportError:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pystray", "--quiet"],
            creationflags=_NO_WIN,
        )
        import pystray

    menu = pystray.Menu(
        pystray.MenuItem("Open LateralX",  _open,     default=True),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Restart Server", _restart),
        pystray.MenuItem("View Log",       _view_log),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Exit",           _exit),
    )

    icon = pystray.Icon(
        name="LateralX",
        icon=_make_icon(muted=True),          # muted until server is ready
        title="LateralX — Initialising…",
        menu=menu,
    )

    icon.run(setup=_startup)                  # _startup runs in background thread


if __name__ == "__main__":
    main()
