import {
  formatStatusLabel,
  formatOtpDisplay,
  isOtpUnderTenMinutes,
  ConnectionStatus
} from "./logic.js";

const statusText = document.getElementById("status-text");
const tokenInput = document.getElementById("token-input") as HTMLInputElement | null;
const saveBtn = document.getElementById("save-btn");
const forgetBtn = document.getElementById("forget-btn");
const otpContainer = document.getElementById("otp-container");
const otpText = document.getElementById("otp-text");
const copyBtn = document.getElementById("copy-btn");

function updateStatusClass(el: HTMLElement, status: ConnectionStatus): void {
  el.className = "status-val";
  switch (status) {
    case "connected":
      el.classList.add("status-connected");
      break;
    case "connecting":
      el.classList.add("status-connecting");
      break;
    case "token_rejected":
    case "service_not_running":
      el.classList.add("status-error");
      break;
    default:
      el.classList.add("status-neutral");
      break;
  }
}

async function render(): Promise<void> {
  try {
    const local = await chrome.storage.local.get(["token", "pairToken"]);
    const hasToken = Boolean(local.token || local.pairToken);

    const session = await chrome.storage.session.get(["status", "latestOtp", "otp"]);
    let currentStatus: ConnectionStatus = (session.status as ConnectionStatus) || (hasToken ? "connecting" : "not_paired");

    if (!hasToken) {
      currentStatus = "not_paired";
    }

    if (statusText) {
      statusText.textContent = formatStatusLabel(currentStatus);
      updateStatusClass(statusText, currentStatus);
    }

    const otp = (session.latestOtp || session.otp) as
      | { sender: string; senderDomain?: string | null; code: string; receivedAt: number }
      | undefined;

    if (otp && isOtpUnderTenMinutes(otp.receivedAt)) {
      if (otpContainer) otpContainer.style.display = "flex";
      if (otpText) otpText.textContent = formatOtpDisplay(otp);
    } else {
      if (otpContainer) otpContainer.style.display = "none";
    }
  } catch {}
}

saveBtn?.addEventListener("click", async () => {
  if (!tokenInput) return;
  const val = tokenInput.value.trim();
  if (!val) return;

  try {
    await chrome.storage.local.set({ token: val });
    tokenInput.value = "";
    chrome.runtime.sendMessage({ type: "connect" }).catch(() => {});
    await render();
  } catch {}
});

forgetBtn?.addEventListener("click", async () => {
  try {
    await chrome.storage.local.remove(["token", "pairToken"]);
    await chrome.storage.session.remove(["status", "latestOtp", "otp"]);
    if (tokenInput) tokenInput.value = "";
    chrome.runtime.sendMessage({ type: "forget" }).catch(() => {});
    await render();
  } catch {}
});

copyBtn?.addEventListener("click", async () => {
  try {
    const session = await chrome.storage.session.get(["latestOtp", "otp"]);
    const otp = (session.latestOtp || session.otp) as
      | { sender?: string; code?: string; receivedAt?: number }
      | undefined;
    if (otp?.code) {
      await navigator.clipboard.writeText(otp.code);
      if (copyBtn) {
        const originalText = copyBtn.textContent;
        copyBtn.textContent = "Copied!";
        setTimeout(() => {
          if (copyBtn) copyBtn.textContent = originalText;
        }, 1500);
      }
    }
  } catch {}
});

// Refresh view on storage changes
chrome.storage.onChanged.addListener(() => {
  render();
});

// Periodic tick to update timestamp age ("30s ago") and hide expired codes
setInterval(() => {
  render();
}, 1000);

// Initial render
render();
