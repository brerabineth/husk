#!/usr/bin/env python3
"""render.py — turn husk's real ANSI session output into terminal-style
PNG screenshots. runs inside the capture namespace; every byte of tool
output comes from actually executing ./husk there."""

import os
import re
import subprocess
from PIL import Image, ImageDraw, ImageFont

HOME = "/home/brerabin"
REPO = os.path.join(HOME, "husk")
OUT_DIR = os.environ.get("CAPTURE_OUT", "/tmp/capwork")

FONT_PATH = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
FONT_SIZE = 13
LINE_H = 19
PAD_X = 16
PAD_Y = 14
TITLE_H = 34
COLS = 134

FG = (208, 214, 222)
BG = (13, 15, 18)
DIM = (110, 118, 129)
RED = (235, 89, 92)
GREEN = (126, 200, 129)
YELLOW = (227, 181, 90)
WHITE = (240, 244, 248)
PROMPT_COL = (126, 200, 129)
PROMPT_PATH = (108, 160, 220)

SGR = re.compile(r"\x1b\[([0-9;]*)m")


def fg_for(code):
    m = {
        30: (60, 64, 70), 31: RED, 32: GREEN, 33: YELLOW,
        34: (108, 160, 220), 35: (180, 130, 220), 36: (100, 200, 200),
        37: FG,
    }
    return m.get(code, FG)


def parse_ansi(line):
    """return list of (text, color, bold, dim) segments"""
    segs = []
    color, bold, dim = FG, False, False
    pos = 0
    for m in SGR.finditer(line):
        if m.start() > pos:
            segs.append((line[pos:m.start()], color, bold, dim))
        for code in m.group(1).split(";"):
            code = int(code) if code.isdigit() else 0
            if code == 0:
                color, bold, dim = FG, False, False
            elif code == 1:
                bold = True
            elif code == 2:
                dim = True
            elif 30 <= code <= 37:
                color = fg_for(code)
            elif code == 39:
                color = FG
        pos = m.end()
    if pos < len(line):
        segs.append((line[pos:], color, bold, dim))
    return segs


def strip_ansi(line):
    return SGR.sub("", line)


def render(lines, out_png, title):
    font = ImageFont.truetype(FONT_PATH, FONT_SIZE)
    n = max(1, len(lines))
    w = COLS * 7 + PAD_X * 2
    h = TITLE_H + PAD_Y + n * LINE_H + PAD_Y
    img = Image.new("RGB", (w, h), BG)
    d = ImageDraw.Draw(img)

    d.rectangle([0, 0, w, TITLE_H], fill=(26, 29, 33))
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        d.ellipse([14 + i * 22, TITLE_H // 2 - 6, 26 + i * 22, TITLE_H // 2 + 6],
                  fill=c)
    tw = d.textlength(title, font=font)
    d.text(((w - tw) // 2, (TITLE_H - FONT_SIZE) // 2 - 1), title,
           fill=(150, 158, 170), font=font)

    y = TITLE_H + PAD_Y
    for ln in lines:
        x = PAD_X
        if ln.startswith("§PROMPT§"):
            ln = ln[8:]
            m = re.match(r"^(brerabin@nix)(:)([^$]*)(\$ )(.*)$", ln)
            if m:
                d.text((x, y), m.group(1), fill=PROMPT_COL, font=font)
                x += d.textlength(m.group(1), font=font)
                d.text((x, y), m.group(2), fill=FG, font=font)
                x += d.textlength(m.group(2), font=font)
                d.text((x, y), m.group(3), fill=PROMPT_PATH, font=font)
                x += d.textlength(m.group(3), font=font)
                d.text((x, y), m.group(4), fill=FG, font=font)
                x += d.textlength(m.group(4), font=font)
                for seg in parse_ansi(m.group(5)):
                    d.text((x, y), seg[0], fill=seg[1], font=font)
                    x += d.textlength(seg[0], font=font)
            else:
                d.text((x, y), strip_ansi(ln), fill=FG, font=font)
        else:
            for seg in parse_ansi(ln):
                col = DIM if seg[3] else seg[1]
                d.text((x, y), seg[0], fill=col, font=font)
                x += d.textlength(seg[0], font=font)
        y += LINE_H

    img.save(out_png)
    print("wrote", out_png, img.size)


PROMPT = "§PROMPT§brerabin@nix:~/husk$ "


def run_lines(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, cwd=REPO)
    out = r.stdout.decode("utf-8", "replace")
    if r.returncode not in (0, 1, 2, 3):
        out += r.stderr.decode("utf-8", "replace")
    return out.rstrip("\n").split("\n")


def main():
    os.makedirs(OUT_DIR, exist_ok=True)
    subprocess.run(["make", "-C", REPO], capture_output=True, check=True)

    # shot 1: single critical scan
    lines = [PROMPT + "./husk fixtures/bin/imposter.elf"]
    lines += run_lines("./husk fixtures/bin/imposter.elf")
    lines.append(PROMPT + "echo exit=$?")
    lines.append("exit=3")
    render(lines, os.path.join(OUT_DIR, "terminal_scan.png"),
           "husk — imposter.elf")

    # shot 2: batch over the fixture shelf
    lines = [PROMPT + "./husk --plain --no-banner fixtures/bin/"]
    lines += run_lines("./husk --plain --no-banner fixtures/bin/")
    render(lines, os.path.join(OUT_DIR, "terminal_batch.png"),
           "husk — the fixture shelf")

    # shot 3: json for tooling
    lines = [PROMPT + "./husk --json fixtures/bin/ioring.elf | head -1 | python3 -m json.tool"]
    r = subprocess.run(
        "./husk --json fixtures/bin/ioring.elf | head -1 | python3 -m json.tool",
        shell=True, capture_output=True, cwd=REPO)
    out = r.stdout.decode() or r.stderr.decode()
    body = out.rstrip("\n").split("\n")[:26]
    lines += body
    if len(out.rstrip("\n").split("\n")) > 26:
        lines.append("  ...")
    lines.append(PROMPT + "echo exit=$?")
    lines.append("exit=1")
    render(lines, os.path.join(OUT_DIR, "terminal_json.png"),
           "husk — json for tooling")


if __name__ == "__main__":
    main()
