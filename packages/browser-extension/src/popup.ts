import {
  formatStatusLabel,
  formatOtpDisplay,
  isOtpUnderTenMinutes,
  deriveViewState,
  ConnectionStatus,
  LatestOtpState,
  TabState
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
const unverifiedWarning = document.getElementById("unverified-warning");
const usedFeedback = document.getElementById("used-feedback");
const noFieldNotice = document.getElementById("no-field-notice");

interface PopupState {
  status: ConnectionStatus;
  latest: (LatestOtpState & {
    sender: string;
    code: string;
    account: string;
    receivedAt: number;
  }) | null;
  tab?: TabState;
  tabHostname?: string;
  present?: boolean;
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

    const tab: TabState = state.tab || {
      hostname: state.tabHostname || null,
      present: Boolean(state.present)
    };

    const viewState = deriveViewState({
      status: state.status,
      latest: state.latest,
      tab,
      askFirst: state.askFirst
    });

    const otp = state.latest;
    const hasFreshOtp = Boolean(otp && isOtpUnderTenMinutes(otp.receivedAt));

    if (hasFreshOtp && otp) {
      if (otpContainer) otpContainer.style.display = "flex";
      if (otpText) otpText.textContent = formatOtpDisplay(otp);

      const senderDomain = otp.senderDomain || "unknown";
      const site = tab.hostname || "unknown";
      if (senderSiteInfo) {
        senderSiteInfo.textContent = `Sender: ${senderDomain} / This site: ${site}`;
      }

      if (fillBtn) {
        fillBtn.disabled = !viewState.fillEnabled;
        fillBtn.textContent = viewState.fillLabel;
      }

      if (mismatchWarning) {
        mismatchWarning.style.display = viewState.showMismatchWarning ? "block" : "none";
      }

      if (unverifiedWarning) {
        unverifiedWarning.style.display = viewState.showUnverifiedWarning ? "block" : "none";
      }

      if (usedFeedback) {
        if (viewState.usedFeedback) {
          usedFeedback.textContent = viewState.usedFeedback;
          usedFeedback.style.display = "block";
        } else {
          usedFeedback.style.display = "none";
        }
      }
    } else {
      if (otpContainer) otpContainer.style.display = "none";
    }

    if (noFieldNotice) {
      if (viewState.hint) {
        noFieldNotice.textContent = viewState.hint;
        noFieldNotice.style.display = "block";
      } else {
        noFieldNotice.style.display = "none";
      }
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
    await render();
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
