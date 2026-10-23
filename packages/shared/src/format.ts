/**
 * Formats an OTP notification into a single line: [HH:MM:SS] <sender> (<alias>) -> <code>
 * In non-TTY environments (or when maskCode is true), the code is masked with asterisks of the same length.
 */
export function formatOtpNotification(otp: {
  accountId?: string;
  account?: string;
  sender: string;
  code: string;
  receivedAt?: number;
  maskCode?: boolean;
  senderVerified?: boolean;
}): string {
  const d = new Date(otp.receivedAt || Date.now());
  const pad = (n: number) => String(n).padStart(2, "0");
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const acct = otp.accountId ?? otp.account ?? "unknown";
  const shouldMask = otp.maskCode ?? (!process.stdout?.isTTY);
  const displayCode = shouldMask ? "*".repeat(otp.code.length) : otp.code;
  const verifiedMarker = otp.senderVerified ? " [verified]" : " [unverified]";
  return `[${time}] ${otp.sender} (${acct}) -> ${displayCode}${verifiedMarker}`;
}
