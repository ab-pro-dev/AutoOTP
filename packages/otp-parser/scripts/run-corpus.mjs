import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { extractOtp } from "../dist/index.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const corpusPath = resolve(__dirname, "../fixtures/corpus.json");
const corpus = JSON.parse(readFileSync(corpusPath, "utf-8"));

let posPassed = 0;
let posTotal = 0;
let negPassed = 0;
let negTotal = 0;
const failedIds = [];

for (const item of corpus) {
  const result = extractOtp({ subject: item.subject, body: item.body });
  const actual = result ? result.code : null;
  const isPositive = item.expected !== null;

  if (isPositive) {
    posTotal++;
    if (actual === item.expected) {
      posPassed++;
    } else {
      failedIds.push(item.id);
    }
  } else {
    negTotal++;
    if (actual === null) {
      negPassed++;
    } else {
      failedIds.push(item.id);
    }
  }
}

console.log(`positives ${posPassed}/${posTotal}, negatives ${negPassed}/${negTotal}`);
if (failedIds.length > 0) {
  console.log(`failed: ${failedIds.join(", ")}`);
  process.exit(1);
}
