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
const fillBtn = document.getElementById("fill-btn") as HTMLButtonElement | null;
const askFirstCheckbox = document.getElementById("ask-first-checkbox") as HTMLInputElement | null;
const senderSiteInfo = document.getElementById("sender-site-info");
const mismatchWarning = document.getElementById("mismatch-warning");
const noFieldNotice = document.getElementById("no-field-notice");

interface PopupState {
  status: ConnectionStatus;
  latest: {
    sender: string;
    senderDomain: string | null;
    code: string;
    account: string;
    receivedAt: number;
    used?: boolean;
  } | null;
  tabHostname: string;
  present: boolean;
  mismatch: boolean;
  askFirst: boolean;
}

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
    const state: PopupState = await chrome.runtime.sendMessage({ type: "get-state" });
    if (!state) return;

    if (statusText) {
      statusText.textContent = formatStatusLabel(state.status);
      updateStatusClass(statusText, state.status);
    }

    if (askFirstCheckbox) {
      askFirstCheckbox.checked = Boolean(state.askFirst);
    }

    const otp = state.latest;
    if (otp && isOtpUnderTenMinutes(otp.receivedAt)) {
      if (otpContainer) otpContainer.style.display = "flex";
      if (otpText) otpText.textContent = formatOtpDisplay(otp);

      const senderDomain = otp.senderDomain || "unknown";
      const site = state.tabHostname || "unknown";
      if (senderSiteInfo) {
        senderSiteInfo.textContent = `Sender: ${senderDomain} / This site: ${site}`;
      }

      if (fillBtn) {
        fillBtn.disabled = !state.present;
        if (state.mismatch) {
          fillBtn.textContent = "Fill anyway";
        } else {
          fillBtn.textContent = "Fill";
        }
      }

      if (mismatchWarning) {
        mismatchWarning.style.display = state.mismatch ? "block" : "none";
      }

      if (noFieldNotice) {
        noFieldNotice.style.display = state.present ? "none" : "block";
      }
    } else {
      if (otpContainer) otpContainer.style.display = "none";
    }
  } catch {}
}

askFirstCheckbox?.addEventListener("change", async () => {
  if (!askFirstCheckbox) return;
  try {
    await chrome.storage.local.set({ askFirst: askFirstCheckbox.checked });
  } catch {}
});

fillBtn?.addEventListener("click", async () => {
  try {
    await chrome.runtime.sendMessage({ type: "fill-now" });
  } catch {}
});

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

chrome.storage.onChanged.addListener(() => {
  render();
});

setInterval(() => {
  render();
}, 1000);

render();
