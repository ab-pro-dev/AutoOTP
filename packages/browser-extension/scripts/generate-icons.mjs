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

const sizes = [16, 32, 48, 128];

for (const size of sizes) {
  const dest = path.join(outputDir, `icon-${size}.png`);
  try {
    execFileSync("convert", [sourceIcon, "-resize", `${size}x${size}`, dest]);
    console.log(`Generated ${size}x${size} icon: ${dest}`);
  } catch (err) {
    console.error(`Failed to resize icon with convert: ${err.message}`);
    process.exit(1);
  }
}
