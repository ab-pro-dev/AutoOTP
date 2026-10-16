import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const possiblePaths = [
  path.resolve(__dirname, "../manifest.json"),
  path.resolve(__dirname, "../dist-ext/manifest.json"),
  path.resolve(__dirname, "../src/manifest.json")
];

let manifestPath = "";
for (const p of possiblePaths) {
  if (fs.existsSync(p)) {
    manifestPath = p;
    break;
  }
}

if (!manifestPath) {
  throw new Error("Could not find manifest.json");
}

const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8"));
if (!manifest.key) {
  throw new Error("No 'key' found in manifest.json");
}

const der = Buffer.from(manifest.key, "base64");
const hash = crypto.createHash("sha256").update(der).digest("hex");
const id = hash
  .slice(0, 32)
  .split("")
  .map((c) => {
    const val = parseInt(c, 16);
    return String.fromCharCode("a".charCodeAt(0) + val);
  })
  .join("");

console.log(id);
