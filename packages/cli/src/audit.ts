import { TokenStore, getHomeDir } from "@autootp/shared";
import {
  auditAccount,
  ReauthRequiredError,
  AuditMessageItem
} from "@autootp/gmail";
import { sanitizeNotificationText } from "@autootp/service";
import { CommandContext } from "./commands.js";

export interface AuditCommandOptions {
  days?: string | number;
  account?: string;
  subjects?: boolean;
}

export interface AuditContext extends CommandContext {
  initialBackoffMs?: number;
  sleepFn?: (ms: number) => Promise<void>;
}

interface DomainGroup {
  count: number;
  subjects: string[];
}

function sanitizeSubject(rawSubject: string, code?: string, rawCode?: string): string {
  let clean = rawSubject || "(no subject)";
  if (rawCode && clean.includes(rawCode)) {
    clean = clean.replaceAll(rawCode, "******");
  }
  if (code && clean.includes(code)) {
    clean = clean.replaceAll(code, "******");
  }
  clean = clean.replace(/\b\d{4,8}\b/g, (m) => "*".repeat(m.length));
  return sanitizeNotificationText(clean, 40);
}

function addEntry(map: Map<string, DomainGroup>, domain: string, subject: string) {
  const existing = map.get(domain) ?? { count: 0, subjects: [] };
  existing.count++;
  if (subject && !existing.subjects.includes(subject)) {
    existing.subjects.push(subject);
  }
  map.set(domain, existing);
}

/**
 * Runs the read-only inbox audit calibration tool.
 */
export async function auditAction(
  options: AuditCommandOptions = {},
  context: AuditContext = {}
): Promise<void> {
  const exit = context.exitImpl ?? process.exit;
  const homeDir = context.homeDir ?? getHomeDir();

  const rawDays = options.days !== undefined ? String(options.days) : "14";
  const numDays = Number(rawDays);
  if (!Number.isInteger(numDays) || numDays < 1 || numDays > 60) {
    console.error(
      `Invalid value for --days: ${rawDays}. Must be an integer between 1 and 60.`
    );
    exit(1);
    return;
  }

  const store = new TokenStore(homeDir);
  let aliases: string[] = [];

  if (options.account) {
    const data = await store.get(options.account);
    if (!data) {
      console.error(`Account "${options.account}" not found.`);
      exit(1);
      return;
    }
    aliases = [options.account];
  } else {
    aliases = await store.list();
    if (aliases.length === 0) {
      console.error("No accounts connected. Run: autootp login");
      exit(1);
      return;
    }
  }

  const allMessages: AuditMessageItem[] = [];

  for (const alias of aliases) {
    try {
      const res = await auditAccount({
        accountId: alias,
        days: numDays,
        homeDir,
        fetchImpl: context.fetchImpl,
        initialBackoffMs: context.initialBackoffMs,
        sleepFn: context.sleepFn,
        signal: context.signal
      });
      allMessages.push(...res.messages);
    } catch (err: unknown) {
      const error = err instanceof Error ? err : new Error(String(err));
      if (
        error instanceof ReauthRequiredError ||
        error.name === "ReauthRequiredError" ||
        error.message.includes("invalid_grant") ||
        error.message.includes("Google access expired")
      ) {
        console.log(`${alias}: Google access expired. Run: autootp login ${alias}`);
        continue;
      }
      console.error(`Error auditing account "${alias}": ${error.message}`);
    }
  }

  let totalScanned = allMessages.length;
  let totalDetected = 0;
  let totalDetectedVerified = 0;
  let totalDetectedUnverified = 0;
  let totalPossibleMisses = 0;
  let totalPossibleFalsePositives = 0;

  const detectedGroups = new Map<string, DomainGroup>();
  const unverifiedGroups = new Map<string, DomainGroup>();
  const missGroups = new Map<string, DomainGroup>();
  const falsePositiveGroups = new Map<string, DomainGroup>();

  for (const msg of allMessages) {
    const domain = msg.senderDomain ?? "unknown";
    const cleanSubj = sanitizeSubject(msg.subject, msg.detectedCode, msg.detectedRaw);

    if (msg.isDetected) {
      totalDetected++;
      addEntry(detectedGroups, domain, cleanSubj);

      if (msg.senderVerified) {
        totalDetectedVerified++;
      } else {
        totalDetectedUnverified++;
        addEntry(unverifiedGroups, domain, cleanSubj);
      }
    }

    if (msg.isPossibleMiss) {
      totalPossibleMisses++;
      addEntry(missGroups, domain, cleanSubj);
    }

    if (msg.isPossibleFalsePositive) {
      totalPossibleFalsePositives++;
      addEntry(falsePositiveGroups, domain, cleanSubj);
    }
  }

  console.log("Summary:");
  console.log(`  Scanned: ${totalScanned}`);
  console.log(`  Detected: ${totalDetected}`);
  console.log(`  Detected and verified: ${totalDetectedVerified}`);
  console.log(`  Detected and unverified: ${totalDetectedUnverified}`);
  console.log(`  Possible misses: ${totalPossibleMisses}`);
  console.log(`  Possible false positives: ${totalPossibleFalsePositives}`);

  function printGroup(title: string, groupMap: Map<string, DomainGroup>) {
    console.log(`\n${title}:`);
    if (groupMap.size === 0) {
      console.log("  (none)");
      return;
    }
    const sortedDomains = Array.from(groupMap.keys()).sort((a, b) => a.localeCompare(b));
    for (const domain of sortedDomains) {
      const entry = groupMap.get(domain)!;
      console.log(`  ${domain}: ${entry.count}`);
      if (options.subjects && entry.subjects.length > 0) {
        for (const subj of entry.subjects) {
          console.log(`    - ${subj}`);
        }
      }
    }
  }

  printGroup("Detected senders", detectedGroups);
  printGroup("Unverified senders", unverifiedGroups);
  printGroup("Possible misses", missGroups);
  printGroup("Possible false positives", falsePositiveGroups);
}
