const corsByTab = new Map();
const MAX_ENTRIES = 100;

function getCorsHeaders(responseHeaders = []) {
  const interesting = [
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age"
  ];

  const result = {};
  for (const header of responseHeaders) {
    const name = String(header.name || "").toLowerCase();
    if (interesting.includes(name)) {
      result[name] = header.value ?? "";
    }
  }
  return result;
}

function classifyCors(headers) {
  const findings = [];
  const origin = headers["access-control-allow-origin"];
  const credentials = headers["access-control-allow-credentials"];

  if (!origin && !credentials) return findings;

  if (origin === "*") {
    findings.push({
      severity: "LOW",
      rule: "CORS-WIDE-ORIGIN",
      message: "El recurso permite cualquier origen mediante Access-Control-Allow-Origin: *."
    });
  }

  if (credentials === "true" && origin === "*") {
    findings.push({
      severity: "HIGH",
      rule: "CORS-CREDENTIALS-WILDCARD",
      message: "Se detectó Access-Control-Allow-Credentials: true junto con un origen comodín. Revisar la configuración y el contexto del recurso."
    });
  }

  return findings;
}

chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headers = getCorsHeaders(details.responseHeaders);
    if (Object.keys(headers).length === 0) return;

    const list = corsByTab.get(details.tabId) || [];
    list.push({
      url: details.url,
      type: details.type,
      timestamp: Date.now(),
      headers,
      findings: classifyCors(headers)
    });

    if (list.length > MAX_ENTRIES) list.splice(0, list.length - MAX_ENTRIES);
    corsByTab.set(details.tabId, list);
  },
  { urls: ["http://*/*", "https://*/*"] },
  ["responseHeaders"]
);

chrome.tabs.onRemoved.addListener((tabId) => corsByTab.delete(tabId));

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "GET_CORS_RESULTS") {
    sendResponse({ entries: corsByTab.get(message.tabId) || [] });
  }
  return true;
});
