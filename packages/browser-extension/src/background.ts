import {
  MIN_BACKOFF_MS,
  getNextBackoff,
  parseIncomingMessage,
  decideAutofill,
  domainsMatch,
  ConnectionStatus
} from "./logic.js";

const WS_URL = "ws://127.0.0.1:47821";
const ALARM_NAME = "autootp_reconnect";

let ws: WebSocket | null = null;
let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
let currentBackoffMs = MIN_BACKOFF_MS;
let tokenRejected = false;
let isConnecting = false;

interface TabInfo {
  hostname: string;
  protocol: string;
  present: boolean;
}

type TabRegistry = Record<string, TabInfo>;

interface StoredOtp {
  sender: string;
  senderDomain: string | null;
  code: string;
  account: string;
  receivedAt: number;
  used?: boolean;
}

async function getRegistry(): Promise<TabRegistry> {
  try {
    const res = await chrome.storage.session.get("tabRegistry");
    if (res.tabRegistry && typeof res.tabRegistry === "object") {
      return res.tabRegistry as TabRegistry;
    }
  } catch {}
  return {};
}

async function setTabInfo(tabId: number, info: TabInfo): Promise<void> {
  try {
    const reg = await getRegistry();
    reg[String(tabId)] = info;
    await chrome.storage.session.set({ tabRegistry: reg });
  } catch {}
}

async function removeTabInfo(tabId: number): Promise<void> {
  try {
    const reg = await getRegistry();
    if (String(tabId) in reg) {
      delete reg[String(tabId)];
      await chrome.storage.session.set({ tabRegistry: reg });
    }
  } catch {}
}

if (chrome.tabs?.onRemoved) {
  chrome.tabs.onRemoved.addListener((tabId) => {
    removeTabInfo(tabId).catch(() => {});
  });
}

async function getActiveTab(): Promise<chrome.tabs.Tab | null> {
  try {
    const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tabs && tabs.length > 0 && tabs[0].id !== undefined) {
      return tabs[0];
    }
  } catch {}
  return null;
}

async function attemptAutofill(tabId: number, tabInfo: TabInfo): Promise<void> {
  if (!tabInfo.present) {
    return;
  }

  const activeTab = await getActiveTab();
  if (!activeTab || activeTab.id !== tabId) {
    return;
  }

  const session = await chrome.storage.session.get(["latestOtp", "otp"]);
  const latestOtp = (session.latestOtp || session.otp) as StoredOtp | undefined;
  if (!latestOtp || !latestOtp.code) {
    return;
  }

  const local = await chrome.storage.local.get("askFirst");
  const askFirst = Boolean(local.askFirst);

  const ageMs = Date.now() - latestOtp.receivedAt;
  const decision = decideAutofill({
    askFirst,
    protocol: tabInfo.protocol,
    hostname: tabInfo.hostname,
    senderDomain: latestOtp.senderDomain,
    ageMs,
    used: Boolean(latestOtp.used)
  });

  if (decision === "auto") {
    try {
      await chrome.tabs.sendMessage(
        tabId,
        { type: "fill", code: latestOtp.code },
        { frameId: 0 }
      );
      latestOtp.used = true;
      await chrome.storage.session.set({
        latestOtp,
        otp: latestOtp
      });
    } catch {}
  }
}

async function getToken(): Promise<string | null> {
  try {
    const res = await chrome.storage.local.get(["token", "pairToken"]);
    const val = (res.token || res.pairToken) as unknown;
    if (typeof val === "string" && val.trim().length > 0) {
      return val.trim();
    }
  } catch {}
  return null;
}

async function updateStatus(status: ConnectionStatus): Promise<void> {
  try {
    await chrome.storage.session.set({ status });
  } catch {}
}

function clearReconnectTimer(): void {
  if (reconnectTimer !== null) {
    clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
}

function scheduleReconnect(): void {
  if (tokenRejected || reconnectTimer !== null) {
    return;
  }
  reconnectTimer = setTimeout(() => {
    reconnectTimer = null;
    currentBackoffMs = getNextBackoff(currentBackoffMs);
    connect();
  }, currentBackoffMs);
}

async function connect(): Promise<void> {
  clearReconnectTimer();

  if (tokenRejected) {
    await updateStatus("token_rejected");
    return;
  }

  if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
    return;
  }

  const token = await getToken();
  if (!token) {
    tokenRejected = false;
    await updateStatus("not_paired");
    return;
  }

  isConnecting = true;
  await updateStatus("connecting");

  try {
    const socket = new WebSocket(WS_URL);
    ws = socket;

    socket.onopen = () => {
      if (ws !== socket) return;
      socket.send(JSON.stringify({ type: "auth", token }));
    };

    socket.onmessage = async (event: MessageEvent) => {
      if (ws !== socket) return;
      const msg = parseIncomingMessage(event.data);
      if (!msg) {
        return;
      }

      if (msg.type === "hello") {
        isConnecting = false;
        tokenRejected = false;
        currentBackoffMs = MIN_BACKOFF_MS;
        await updateStatus("connected");
        return;
      }

      if (msg.type === "ping") {
        socket.send(JSON.stringify({ type: "pong" }));
        return;
      }

      if (msg.type === "otp") {
        const { sender, senderDomain, code, account, receivedAt } = msg;
        const otpData: StoredOtp = {
          sender,
          senderDomain,
          code,
          account,
          receivedAt,
          used: false
        };
        await chrome.storage.session.set({
          latestOtp: otpData,
          otp: otpData
        });

        const activeTab = await getActiveTab();
        if (activeTab && activeTab.id !== undefined) {
          const reg = await getRegistry();
          const tabInfo = reg[String(activeTab.id)];
          if (tabInfo && tabInfo.present) {
            await attemptAutofill(activeTab.id, tabInfo);
          }
        }
      }
    };

    socket.onclose = async (event: CloseEvent) => {
      if (ws === socket) {
        ws = null;
      }
      isConnecting = false;

      if (event.code === 4401) {
        tokenRejected = true;
        clearReconnectTimer();
        await updateStatus("token_rejected");
        return;
      }

      const activeToken = await getToken();
      if (!activeToken) {
        await updateStatus("not_paired");
        return;
      }

      await updateStatus("service_not_running");
      scheduleReconnect();
    };

    socket.onerror = () => {};
  } catch {
    ws = null;
    isConnecting = false;
    await updateStatus("service_not_running");
    scheduleReconnect();
  }
}

async function configureAccessLevel(): Promise<void> {
  try {
    if (chrome.storage?.local?.setAccessLevel) {
      await chrome.storage.local.setAccessLevel({
        accessLevel: "TRUSTED_CONTEXTS"
      });
    }
  } catch {}
}

chrome.runtime.onInstalled.addListener(() => {
  configureAccessLevel();
  chrome.alarms.create(ALARM_NAME, { periodInMinutes: 1 });
  connect();
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === ALARM_NAME) {
    if (!tokenRejected && (!ws || ws.readyState === WebSocket.CLOSED)) {
      connect();
    }
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local" && ("token" in changes || "pairToken" in changes)) {
    const change = changes.token || changes.pairToken;
    const newToken = change?.newValue;

    tokenRejected = false;
    currentBackoffMs = MIN_BACKOFF_MS;
    clearReconnectTimer();

    if (ws) {
      ws.close();
      ws = null;
    }

    if (typeof newToken === "string" && newToken.trim().length > 0) {
      connect();
    } else {
      updateStatus("not_paired");
    }
  }
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "fields") {
    const tabId = sender.tab?.id;
    const urlStr = sender.url || sender.tab?.url;
    if (tabId !== undefined && urlStr) {
      let hostname = "";
      let protocol = "";
      try {
        const u = new URL(urlStr);
        hostname = u.hostname.toLowerCase();
        protocol = u.protocol.toLowerCase();
      } catch {}

      const present = Boolean(message.present);
      const tabInfo: TabInfo = { hostname, protocol, present };
      setTabInfo(tabId, tabInfo).then(() => {
        if (present) {
          return attemptAutofill(tabId, tabInfo);
        }
      }).catch(() => {});
    }
    sendResponse?.({ ok: true });
    return true;
  }

  if (message?.type === "get-state") {
    (async () => {
      const local = await chrome.storage.local.get(["token", "pairToken", "askFirst"]);
      const hasToken = Boolean(local.token || local.pairToken);
      const askFirst = Boolean(local.askFirst);

      const session = await chrome.storage.session.get(["status", "latestOtp", "otp"]);
      let status: ConnectionStatus =
        (session.status as ConnectionStatus) || (hasToken ? "connecting" : "not_paired");
      if (!hasToken) {
        status = "not_paired";
      }

      const latest = ((session.latestOtp || session.otp) as StoredOtp | undefined) || null;

      let tabHostname = "";
      let present = false;
      const activeTab = await getActiveTab();
      if (activeTab && activeTab.id !== undefined) {
        const reg = await getRegistry();
        const tabInfo = reg[String(activeTab.id)];
        if (tabInfo) {
          tabHostname = tabInfo.hostname;
          present = Boolean(tabInfo.present);
        }
      }

      let mismatch = false;
      if (latest && tabHostname) {
        if (!latest.senderDomain || !domainsMatch(latest.senderDomain, tabHostname)) {
          mismatch = true;
        }
      } else if (latest && !latest.senderDomain) {
        mismatch = true;
      }

      sendResponse({
        status,
        latest,
        tabHostname,
        present,
        mismatch,
        askFirst
      });
    })();
    return true;
  }

  if (message?.type === "fill-now") {
    (async () => {
      const activeTab = await getActiveTab();
      if (!activeTab || activeTab.id === undefined) {
        sendResponse?.({ ok: false, error: "no_active_tab" });
        return;
      }

      const session = await chrome.storage.session.get(["latestOtp", "otp"]);
      const latest = (session.latestOtp || session.otp) as StoredOtp | undefined;
      if (!latest || !latest.code) {
        sendResponse?.({ ok: false, error: "no_otp" });
        return;
      }

      try {
        await chrome.tabs.sendMessage(
          activeTab.id,
          { type: "fill", code: latest.code },
          { frameId: 0 }
        );
        latest.used = true;
        await chrome.storage.session.set({
          latestOtp: latest,
          otp: latest
        });
        sendResponse?.({ ok: true });
      } catch {
        sendResponse?.({ ok: false, error: "send_failed" });
      }
    })();
    return true;
  }

  if (message?.type === "connect" || message?.type === "reconnect") {
    tokenRejected = false;
    currentBackoffMs = MIN_BACKOFF_MS;
    clearReconnectTimer();
    connect();
    sendResponse?.({ ok: true });
    return true;
  }

  if (message?.type === "forget") {
    tokenRejected = false;
    currentBackoffMs = MIN_BACKOFF_MS;
    clearReconnectTimer();
    if (ws) {
      ws.close();
      ws = null;
    }
    updateStatus("not_paired");
    sendResponse?.({ ok: true });
    return true;
  }

  return false;
});

configureAccessLevel();
connect();
