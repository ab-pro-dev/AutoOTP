import { describe, it, expect } from "vitest";
import { VERSION } from "./index.js";

describe("VERSION", () => {
  it("matches semver pattern", () => {
    expect(VERSION).toMatch(/^\d+\.\d+\.\d+$/);
  });
});
