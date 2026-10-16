import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(__dirname, "..");
const distExt = path.resolve(pkgRoot, "dist-ext");

if (!fs.existsSync(distExt)) {
  fs.mkdirSync(distExt, { recursive: true });
}

const filesToCopy = ["manifest.json", "popup.html"];

for (const file of filesToCopy) {
  const src = path.join(pkgRoot, file);
  const dest = path.join(distExt, file);
  if (fs.existsSync(src)) {
    fs.copyFileSync(src, dest);
  } else {
    throw new Error(`Static file not found: ${src}`);
  }
}
