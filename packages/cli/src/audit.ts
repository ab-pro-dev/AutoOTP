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
  explain?: boolean;
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
  let totalListed = 0;
  let totalFetched = 0;
  let totalFailed = 0;

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
      totalListed += res.listedCount;
      totalFetched += res.fetchedCount;
      totalFailed += res.failedCount;
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

  console.log(`Listed: ${totalListed}, fetched: ${totalFetched}, failed: ${totalFailed}`);
  if (totalFailed > 0) {
    console.log(
      `WARNING: ${totalFailed} messages could not be fetched; results are incomplete`
    );
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

  if (options.explain) {
    console.log("\nExplain:");

    const unverifiedMsgs = allMessages.filter((m) => m.isDetected && !m.senderVerified);
    const falsePositiveMsgs = allMessages.filter((m) => m.isPossibleFalsePositive);
    const missMsgs = allMessages.filter((m) => m.isPossibleMiss);

    const printExplainGroup = (
      title: string,
      messages: AuditMessageItem[],
      forceAuth: boolean = false
    ) => {
      console.log(`  ${title}:`);
      if (messages.length === 0) {
        console.log("    (none)");
        return;
      }
      const sample = messages.slice(0, 5);
      for (const msg of sample) {
        const domain = msg.senderDomain ?? "unknown";
        const conf = msg.confidence ?? "none";
        const shape = msg.candidateShape ?? "none";
        console.log(`    - domain: ${domain}`);
        console.log(`      confidence: ${conf}`);
        console.log(`      shape: ${shape}`);

        if (
          msg.nearestKeyword &&
          msg.nearestKeywordDistance !== null &&
          msg.nearestKeywordDistance !== undefined
        ) {
          console.log(
            `      nearest keyword: "${msg.nearestKeyword}" (${msg.nearestKeywordDistance} chars)`
          );
        } else {
          console.log("      nearest keyword: none within 80");
        }

        if (forceAuth || !msg.senderVerified) {
          if (msg.authInfo) {
            const { authservId, verdicts, headerFrom, headerD, smtpMailfrom } = msg.authInfo;
            const authParts: string[] = [];
            if (authservId) authParts.push(`authserv-id=${authservId}`);
            if (verdicts.length > 0) authParts.push(verdicts.join(" "));
            if (headerFrom) authParts.push(`header.from=${headerFrom}`);
            if (headerD) authParts.push(`header.d=${headerD}`);
            if (smtpMailfrom) authParts.push(`smtp.mailfrom=${smtpMailfrom}`);

            const authLine = authParts.length > 0 ? authParts.join(" ") : "none";
            console.log(`      auth: ${authLine}`);
          } else {
            console.log("      auth: none");
          }
        }

        console.log(`      context: ${msg.contextWindow ?? "(no content)"}`);
      }
    };

    printExplainGroup("Unverified senders", unverifiedMsgs, true);
    printExplainGroup("Possible false positives", falsePositiveMsgs, false);
    printExplainGroup("Possible misses", missMsgs, false);
  }

  if (totalFailed > 0) {
    exit(3);
  }
}
