import {
  scoreField,
  groupSegmented,
  validateFillMessage,
  FieldDescriptor
} from "./logic.js";

interface Candidate {
  kind: "single" | "segmented";
  score: number;
  elements: HTMLInputElement[];
}

function isElementVisible(el: HTMLInputElement): boolean {
  if (el.type === "hidden") {
    return false;
  }
  if (typeof el.checkVisibility === "function") {
    try {
      if (!el.checkVisibility({ checkOpacity: true, checkVisibilityCSS: true })) {
        return false;
      }
    } catch {}
  }
  const rects = el.getClientRects();
  if (rects.length === 0) {
    return false;
  }
  try {
    const style = window.getComputedStyle(el);
    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0"
    ) {
      return false;
    }
  } catch {}
  return true;
}

function getFieldDescriptors(): Array<FieldDescriptor & { element: HTMLInputElement }> {
  const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
  return inputs.map((input) => {
    let maxLength: number | undefined = undefined;
    if (input.hasAttribute("maxlength")) {
      const parsed = parseInt(input.getAttribute("maxlength") || "", 10);
      if (!isNaN(parsed) && parsed > 0) {
        maxLength = parsed;
      }
    }

    const visible = isElementVisible(input);

    return {
      element: input,
      type: input.type || "text",
      name: input.name || "",
      id: input.id || "",
      placeholder: input.placeholder || "",
      ariaLabel: input.getAttribute("aria-label") || "",
      autocomplete: input.autocomplete || input.getAttribute("autocomplete") || "",
      maxLength,
      visible
    };
  });
}

function findCandidates(): Candidate[] {
  const descriptors = getFieldDescriptors();
  const candidates: Candidate[] = [];

  // Single field candidates
  for (const desc of descriptors) {
    const score = scoreField(desc);
    if (score > 0) {
      candidates.push({
        kind: "single",
        score,
        elements: [desc.element]
      });
    }
  }

  // Segmented input candidates
  const segmentedGroups = groupSegmented(descriptors);
  for (const group of segmentedGroups) {
    let score = 90;
    for (const item of group) {
      if ((item.autocomplete || "").toLowerCase().trim() === "one-time-code") {
        score = 150;
        break;
      }
    }
    candidates.push({
      kind: "segmented",
      score,
      elements: group.map((g) => g.element)
    });
  }

  candidates.sort((a, b) => b.score - a.score);
  return candidates;
}

function setNativeValue(element: HTMLInputElement, value: string): void {
  const valueSetter = Object.getOwnPropertyDescriptor(element, "value")?.set;
  const prototype = Object.getPrototypeOf(element);
  const prototypeSetter = Object.getOwnPropertyDescriptor(prototype, "value")?.set;

  if (prototypeSetter && valueSetter !== prototypeSetter) {
    prototypeSetter.call(element, value);
  } else if (valueSetter) {
    valueSetter.call(element, value);
  } else {
    element.value = value;
  }

  element.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
  element.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
}

let lastReportedPresent: boolean | null = null;
let throttleTimer: ReturnType<typeof setTimeout> | null = null;

function scanAndReport(): void {
  const candidates = findCandidates();
  const present = candidates.length > 0;
  if (lastReportedPresent !== present) {
    lastReportedPresent = present;
    chrome.runtime.sendMessage({ type: "fields", present }).catch(() => {});
  }
}

function scheduleScan(): void {
  if (throttleTimer !== null) {
    return;
  }
  throttleTimer = setTimeout(() => {
    throttleTimer = null;
    scanAndReport();
  }, 500);
}

// Listen for fill messages from this extension only
chrome.runtime.onMessage.addListener((message, sender, _sendResponse) => {
  if (sender.id !== chrome.runtime.id) {
    return;
  }

  const valid = validateFillMessage(message);
  if (!valid) {
    return;
  }

  const { code } = valid;
  const candidates = findCandidates();
  if (candidates.length === 0) {
    return;
  }

  const best = candidates[0];
  if (best.kind === "single") {
    const el = best.elements[0];
    if (el) {
      setNativeValue(el, code);
      el.focus();
    }
  } else if (best.kind === "segmented") {
    const inputs = best.elements;
    for (let i = 0; i < Math.min(code.length, inputs.length); i++) {
      setNativeValue(inputs[i], code[i]);
    }
    const lastFilled = inputs[Math.min(code.length, inputs.length) - 1];
    lastFilled?.focus();
  }
});

// Initial scan
scanAndReport();

// Monitor DOM changes for dynamically loaded forms
const observer = new MutationObserver(() => {
  scheduleScan();
});

const targetNode = document.documentElement || document.body;
if (targetNode) {
  observer.observe(targetNode, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: [
      "style",
      "class",
      "hidden",
      "type",
      "name",
      "autocomplete",
      "maxlength"
    ]
  });
}
