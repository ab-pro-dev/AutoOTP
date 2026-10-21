import esbuild from "esbuild";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pkgRoot = path.resolve(__dirname, "..");

await esbuild.build({
  entryPoints: [path.join(pkgRoot, "src/content.ts")],
  bundle: true,
  format: "iife",
  outfile: path.join(pkgRoot, "dist-ext/content.js"),
  target: "es2022"
});
