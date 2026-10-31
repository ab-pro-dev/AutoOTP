import esbuild from "esbuild";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { verifyNoBareSpecifiers } from "./verify-manifest.mjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(__dirname, "..");
const distExt = path.resolve(pkgRoot, "dist-ext");

export async function bundleAll() {
  if (!fs.existsSync(distExt)) {
    fs.mkdirSync(distExt, { recursive: true });
  }

  // 1. Bundle background service worker (ES module, self-contained)
  await esbuild.build({
    entryPoints: [path.join(pkgRoot, "src/background.ts")],
    bundle: true,
    format: "esm",
    outfile: path.join(distExt, "background.js"),
    target: "es2022",
    platform: "browser"
  });

  // 2. Bundle content script (IIFE, self-contained)
  await esbuild.build({
    entryPoints: [path.join(pkgRoot, "src/content.ts")],
    bundle: true,
    format: "iife",
    outfile: path.join(distExt, "content.js"),
    target: "es2022",
    platform: "browser"
  });

  // 3. Bundle popup script (ES module, self-contained)
  await esbuild.build({
    entryPoints: [path.join(pkgRoot, "src/popup.ts")],
    bundle: true,
    format: "esm",
    outfile: path.join(distExt, "popup.js"),
    target: "es2022",
    platform: "browser"
  });

  // 4. Remove unbundled helper files emitted by tsc from dist-ext
  const unbundledFiles = ["logic.js", "logic.d.ts"];
  for (const f of unbundledFiles) {
    const full = path.join(distExt, f);
    if (fs.existsSync(full)) {
      fs.unlinkSync(full);
    }
  }

  // 5. Verify all bundled *.js files contain no bare or non-relative module specifiers
  verifyNoBareSpecifiers(distExt);
}

if (process.argv[1] && fileURLToPath(import.meta.url) === path.resolve(process.argv[1])) {
  await bundleAll();
  console.log("All extension scripts bundled and verified successfully.");
}
