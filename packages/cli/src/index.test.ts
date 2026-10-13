import fs from "node:fs";
import path from "node:path";
import { describe, it, expect, beforeEach, afterEach } from "vitest";
import { TokenStore } from "@autootp/shared";
import {
  validateAlias,
  formatAccountsTable,
  checkCredentialsPermissions,
  revokeToken
} from "./utils.js";
import { removeAction, loginAction } from "./commands.js";

describe("CLI utilities and commands", () => {
  let tempDir: string;
  const originalHome = process.env.AUTOOTP_HOME;

  beforeEach(() => {
    const tmpBase = process.env.TMPDIR || process.env.TEMP || "/tmp";
    tempDir = fs.mkdtempSync(path.join(tmpBase, "autootp-cli-test-"));
    process.env.AUTOOTP_HOME = tempDir;
  });

  afterEach(() => {
    if (originalHome !== undefined) {
      process.env.AUTOOTP_HOME = originalHome;
    } else {
      delete process.env.AUTOOTP_HOME;
    }
    if (fs.existsSync(tempDir)) {
      fs.rmSync(tempDir, { recursive: true, force: true });
    }
  });

  describe("Alias Validation", () => {
    it("accepts valid aliases (lowercase, digits, hyphens, 1-32 chars)", () => {
      const validCases = [
        "personal",
        "work",
        "work-email",
        "account-1",
        "123",
        "a",
        "a-b-c-d",
        "a".repeat(32)
      ];
      for (const alias of validCases) {
        expect(() => validateAlias(alias)).not.toThrow();
      }
    });

    it("rejects invalid aliases with descriptive errors", () => {
      const invalidCases = [
        "", // empty
        "Personal", // uppercase
        "MY-ACCOUNT", // uppercase
        "my account", // space
        "account_1", // underscore
        "account.1", // dot
        "acc@gmail", // special character
        "a".repeat(33) // too long
      ];
      for (const alias of invalidCases) {
        expect(() => validateAlias(alias)).toThrow(/Invalid alias/);
      }
    });
  });

  describe("Accounts Output Formatting", () => {
    it("returns empty-state message when no accounts connected", () => {
      const output = formatAccountsTable([]);
      expect(output).toBe("No accounts connected. Run: autootp login");
    });

    it("formats table with headers, divider and rows for connected accounts", () => {
      const accounts = [
        { alias: "personal", email: "personal@example.com", addedAt: 1700000000000 },
        { alias: "work", email: "work@company.com", addedAt: 1700050000000 }
      ];
      const output = formatAccountsTable(accounts);
      expect(output).toContain("ALIAS");
      expect(output).toContain("EMAIL");
      expect(output).toContain("ADDED");
      expect(output).toContain("personal");
      expect(output).toContain("personal@example.com");
      expect(output).toContain("work");
      expect(output).toContain("work@company.com");
    });
  });

  describe("Account Removal & Revocation", () => {
    it("removes account locally and attempts revoke", async () => {
      const store = new TokenStore(tempDir);
      await store.set("work", {
        refreshToken: "refresh-token-123",
        email: "work@example.com",
        addedAt: Date.now()
      });

      let revokeUrl = "";
      let revokeBody = "";
      const mockFetch = async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
        revokeUrl = input.toString();
        revokeBody = init?.body?.toString() ?? "";
        return new Response("", { status: 200 });
      };

      await removeAction("work", { homeDir: tempDir, fetchImpl: mockFetch as typeof fetch });

      expect(revokeUrl).toBe("https://oauth2.googleapis.com/revoke");
      expect(revokeBody).toContain("token=refresh-token-123");
      expect(await store.get("work")).toBeNull();
    });

    it("throws when removing a non-existent account", async () => {
      await expect(removeAction("nonexistent", { homeDir: tempDir })).rejects.toThrow(
        /Account "nonexistent" not found/
      );
    });

    it("revoke failure does not prevent local removal", async () => {
      const store = new TokenStore(tempDir);
      await store.set("backup", {
        refreshToken: "token-bad",
        email: "backup@example.com",
        addedAt: Date.now()
      });

      const failingFetch = async (): Promise<Response> => {
        return new Response("Bad Request", { status: 400 });
      };

      await removeAction("backup", { homeDir: tempDir, fetchImpl: failingFetch as typeof fetch });
      expect(await store.get("backup")).toBeNull();
    });
  });

  describe("Login Action Guards", () => {
    it("refuses login if the alias already exists", async () => {
      const store = new TokenStore(tempDir);
      await store.set("personal", {
        refreshToken: "r",
        email: "p@example.com",
        addedAt: Date.now()
      });

      await expect(loginAction("personal", { homeDir: tempDir })).rejects.toThrow(
        /Account "personal" already exists\. Run: autootp remove personal/
      );
    });
  });
});
