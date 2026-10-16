/**
 * Formats an OTP notification into a single line: [HH:MM:SS] <sender> (<alias>) -> <code>
 */
export function formatOtpNotification(otp: {
  accountId?: string;
  account?: string;
  sender: string;
  code: string;
  receivedAt?: number;
}): string {
  const d = new Date(otp.receivedAt || Date.now());
  const pad = (n: number) => String(n).padStart(2, "0");
  const time = `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  const acct = otp.accountId ?? otp.account ?? "unknown";
  return `[${time}] ${otp.sender} (${acct}) -> ${otp.code}`;
}
