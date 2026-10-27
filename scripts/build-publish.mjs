import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { execFileSync } from "node:child_process";
import esbuild from "esbuild";
import { runScan } from "./scan-publish.mjs";

export function generatePublishPackageJson(rootPkg) {
  return {
    name: "autootp",
    version: rootPkg.version || "0.1.0",
    description: "Automated OTP handling for Gmail",
    type: "module",
    bin: {
      autootp: "autootp.mjs"
    },
    files: [
      "autootp.mjs",
      "extension",
      "README.md"
    ],
    engines: {
      node: ">=22.13"
    }
  };
}

export async function buildPublish(options = {}) {
  const rootDir = options.rootDir || path.resolve(fileURLToPath(new URL("..", import.meta.url)));
  const publishDir = options.publishDir || path.join(rootDir, "publish");

  // Read root package.json
  const rootPkgPath = path.join(rootDir, "package.json");
  const rootPkg = JSON.parse(fs.readFileSync(rootPkgPath, "utf8"));

  // Ensure extension is built
  const extDistDir = path.join(rootDir, "packages/browser-extension/dist-ext");
  if (!fs.existsSync(extDistDir) || !fs.existsSync(path.join(extDistDir, "manifest.json"))) {
    execFileSync("npm", ["run", "build:ext"], { cwd: rootDir, stdio: "inherit" });
  }

  // Ensure workspace packages are built
  const cliDistDir = path.join(rootDir, "packages/cli/dist");
  if (!fs.existsSync(cliDistDir) || !fs.existsSync(path.join(cliDistDir, "index.js"))) {
    execFileSync("npm", ["run", "build"], { cwd: rootDir, stdio: "inherit" });
  }

  // Clean and prepare publish/ directory
  fs.rmSync(publishDir, { recursive: true, force: true });
  fs.mkdirSync(publishDir, { recursive: true });

  // 1. Write publish/package.json
  const publishPkg = generatePublishPackageJson(rootPkg);
  fs.writeFileSync(
    path.join(publishDir, "package.json"),
    JSON.stringify(publishPkg, null, 2) + "\n",
    "utf8"
  );

  // 2. Copy extension files (manifest.json, popup.html, *.js only; no .d.ts)
  const publishExtDir = path.join(publishDir, "extension");
  fs.mkdirSync(publishExtDir, { recursive: true });
  const extFiles = fs.readdirSync(extDistDir);
  for (const file of extFiles) {
    if (file === "manifest.json" || file === "popup.html" || (file.endsWith(".js") && !file.endsWith(".d.ts"))) {
      fs.copyFileSync(path.join(extDistDir, file), path.join(publishExtDir, file));
    }
  }

  // 3. Copy README.md
  fs.copyFileSync(path.join(rootDir, "README.md"), path.join(publishDir, "README.md"));

  // 4. Bundle packages/cli with esbuild
  const stripShebangPlugin = {
    name: "strip-shebang",
    setup(build) {
      build.onLoad({ filter: /index\.(ts|js)$/ }, async (args) => {
        let contents = await fs.promises.readFile(args.path, "utf8");
        if (contents.startsWith("#!")) {
          contents = contents.replace(/^#![^\n]*\n/, "");
        }
        return { contents, loader: args.path.endsWith(".ts") ? "ts" : "js" };
      });
    }
  };

  const entryPoint = fs.existsSync(path.join(rootDir, "packages/cli/src/index.ts"))
    ? path.join(rootDir, "packages/cli/src/index.ts")
    : path.join(rootDir, "packages/cli/dist/index.js");

  const outfilePath = path.join(publishDir, "autootp.mjs");

  await esbuild.build({
    entryPoints: [entryPoint],
    bundle: true,
    platform: "node",
    format: "esm",
    target: "node22",
    minify: false,
    sourcemap: false,
    banner: {
      js: '#!/usr/bin/env node\nimport { createRequire as __createRequire } from "node:module";\nconst require = __createRequire(import.meta.url);'
    },
    external: [
      "node:*",
      "bufferutil",
      "utf-8-validate"
    ],
    plugins: [stripShebangPlugin],
    outfile: outfilePath
  });

  // Make binary executable
  fs.chmodSync(outfilePath, 0o755);

  // 5. Run secret scanner on publish directory
  const scanOk = await runScan(publishDir);
  if (!scanOk) {
    throw new Error("Secret scan failed on publish directory");
  }

  console.log(`Successfully built publishable package in ${path.relative(rootDir, publishDir)}/`);
}

if (process.argv[1] && (import.meta.url === pathToFileURL(process.argv[1]).href || process.argv[1].endsWith("build-publish.mjs"))) {
  buildPublish().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
