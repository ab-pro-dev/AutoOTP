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

// Find source icon in icon/ folder
let sourceIcon = null;
if (fs.existsSync(iconDir)) {
  const files = fs.readdirSync(iconDir);
  for (const f of files) {
    if (f.endsWith(".png")) {
      sourceIcon = path.join(iconDir, f);
      break;
    }
  }
}

if (!sourceIcon) {
  console.error("No source PNG icon found in icon/ directory.");
  process.exit(1);
}

const pyScript = `
from PIL import Image, ImageDraw
import sys

source = sys.argv[1]
output_dir = sys.argv[2]

im = Image.open(source).convert('RGBA')
cx, cy = 627, 617
half_size = 320
cropped = im.crop((cx - half_size, cy - half_size, cx + half_size, cy + half_size))
ImageDraw.floodfill(cropped, (0, 0), (0, 0, 0, 0), thresh=20)
ImageDraw.floodfill(cropped, (639, 0), (0, 0, 0, 0), thresh=20)
ImageDraw.floodfill(cropped, (0, 639), (0, 0, 0, 0), thresh=20)
ImageDraw.floodfill(cropped, (639, 639), (0, 0, 0, 0), thresh=20)

for s in [16, 32, 48, 128]:
    resized = cropped.resize((s, s), Image.Resampling.LANCZOS)
    dest = f"{output_dir}/icon-{s}.png"
    resized.save(dest)
    print(f"Generated {s}x{s} icon: {dest}")
`;

try {
  execFileSync("python3", ["-c", pyScript, sourceIcon, outputDir], { stdio: "inherit" });
} catch {
  // Fallback to ImageMagick if python3/PIL is not available
  const sizes = [16, 32, 48, 128];
  for (const size of sizes) {
    const dest = path.join(outputDir, `icon-${size}.png`);
    execFileSync("convert", [sourceIcon, "-resize", `${size}x${size}`, `PNG32:${dest}`]);
    console.log(`Generated ${size}x${size} icon: ${dest}`);
  }
}
