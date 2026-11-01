import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(__dirname, "..");
const repoRoot = path.resolve(pkgRoot, "../..");
const iconDir = path.join(repoRoot, "icon");
const outputDir = path.join(pkgRoot, "icons");

if (!fs.existsSync(outputDir)) {
  fs.mkdirSync(outputDir, { recursive: true });
}
if (!fs.existsSync(iconDir)) {
  fs.mkdirSync(iconDir, { recursive: true });
}

const pyScript = `
import os
from PIL import Image, ImageDraw, ImageFont

FONTS = [
    ("/usr/share/fonts/truetype/adwaita/AdwaitaSans-Regular.ttf", "Black"),
    ("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", None),
    ("/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf", None),
    ("/usr/share/fonts/truetype/noto/NotoSans-Bold.ttf", None),
]

font_path = None
font_var = None
for p, v in FONTS:
    if os.path.exists(p):
        font_path = p
        font_var = v
        break

if not font_path:
    raise RuntimeError("No suitable bold sans-serif font found on system")

def generate_icon(size, out_path):
    scale = 8 if size <= 32 else 4
    canvas_size = size * scale
    img = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))

    margin_pct = 0.0 if size <= 24 else 0.025
    m = int(canvas_size * margin_pct)
    r = int(canvas_size * 0.22)
    x0, y0 = m, m
    x1, y1 = canvas_size - m - 1, canvas_size - m - 1

    mask = Image.new("L", (canvas_size, canvas_size), 0)
    ImageDraw.Draw(mask).rounded_rectangle([x0, y0, x1, y1], radius=r, fill=255)

    grad = Image.new("RGBA", (canvas_size, canvas_size), (0, 0, 0, 0))
    for y in range(canvas_size):
        ratio = y / canvas_size
        r_c = int(37 + (29 - 37) * ratio)
        g_c = int(99 + (78 - 99) * ratio)
        b_c = int(235 + (216 - 235) * ratio)
        ImageDraw.Draw(grad).line([(0, y), (canvas_size, y)], fill=(r_c, g_c, b_c, 255))
    img.paste(grad, (0, 0), mask)

    draw = ImageDraw.Draw(img)
    if size >= 32:
        draw.rounded_rectangle([x0, y0, x1, y1], radius=r, outline=(255, 255, 255, 50), width=max(1, int(scale * 0.75)))

    font = ImageFont.truetype(font_path, int(canvas_size * 0.78))
    if font_var:
        font.set_variation_by_name(font_var)

    bbox = draw.textbbox((0, 0), "A", font=font)
    tw = bbox[2] - bbox[0]
    th = bbox[3] - bbox[1]
    tx = (canvas_size - tw) / 2 - bbox[0]
    ty = (canvas_size - th) / 2 - bbox[1] - int(canvas_size * 0.025)
    draw.text((tx, ty), "A", fill=(255, 255, 255, 255), font=font)

    res = img.resize((size, size), Image.Resampling.LANCZOS)
    res.save(out_path)
    print(f"Generated {size}x{size} icon: {out_path}")

import sys
output_dir = sys.argv[1]
icon_dir = sys.argv[2]

for s in [16, 24, 32, 48, 128]:
    dest = os.path.join(output_dir, f"icon-{s}.png")
    generate_icon(s, dest)

master_dest = os.path.join(icon_dir, "AutoOTP-icon.png")
generate_icon(512, master_dest)
`;

execFileSync("python3", ["-c", pyScript, outputDir, iconDir], { stdio: "inherit" });
