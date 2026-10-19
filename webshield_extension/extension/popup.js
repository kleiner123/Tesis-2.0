let protectionEnabled = false;

const $ = (id) => document.getElementById(id);

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tabs[0]?.id || !tabs[0]?.url) throw new Error("No se pudo obtener la pestaña activa.");
  return tabs[0];
}

function getOriginPattern(url) {
  const u = new URL(url);
  if (!["http:", "https:"].includes(u.protocol)) return null;
  return `${u.protocol}//${u.host}/*`;
}

async function ensureHostAccess(url) {
  const pattern = getOriginPattern(url);
  if (!pattern) throw new Error("Chrome no permite auditar este tipo de URL desde una extensión normal.");

  const already = await chrome.permissions.contains({ origins: [pattern] });
  if (already) return true;

  return await chrome.permissions.request({ origins: [pattern] });
}

async function collectPageData(tabId) {
  const [{ result }] = await chrome.scripting.executeScript({
    target: { tabId },
    func: () => {
      const pageOrigin = location.origin;
      const scripts = [...document.scripts].map((s) => ({
        src: s.src || null,
        inline: !s.src,
        integrity: s.integrity || null,
        crossOrigin: s.crossOrigin || null
      }));

      const thirdParty = scripts.filter((s) => {
        if (!s.src) return false;
        try { return new URL(s.src).origin !== pageOrigin; } catch { return false; }
      });

      const missingSriThirdParty = thirdParty.filter((s) => !s.integrity);

      return {
        pageOrigin,
        scripts,
        thirdPartyCount: thirdParty.length,
        missingSriThirdParty: missingSriThirdParty.length,
        totalScripts: scripts.length
      };
    }
  });
  return result;
}

function renderSummary(data, corsEntries) {
  const corsFindings = corsEntries.flatMap((e) => e.findings || []);
  const high = corsFindings.filter((f) => f.severity === "HIGH").length;
  const low = corsFindings.filter((f) => f.severity === "LOW").length;

  $("summary").innerHTML = `
    <div class="card"><strong>${high}</strong><small>Alto</small></div>
    <div class="card"><strong>${low}</strong><small>CORS</small></div>
    <div class="card"><strong>${data.missingSriThirdParty}</strong><small>3P sin SRI</small></div>`;
}

function renderFindings(data, corsEntries) {
  const items = [];

  for (const entry of corsEntries) {
    for (const finding of entry.findings || []) {
      items.push(`<div class="finding ${finding.severity.toLowerCase()}">
        <b>${finding.severity} · ${finding.rule}</b><br>${finding.message}<br><small>${escapeHtml(entry.url)}</small>
      </div>`);
    }
  }

  if (data.missingSriThirdParty > 0) {
    items.push(`<div class="finding medium">
      <b>MEDIUM · SUPPLY-CHAIN-NO-SRI</b><br>
      Se detectaron ${data.missingSriThirdParty} recursos JavaScript de terceros sin atributo integrity (SRI). Esto es un indicador de riesgo, no una prueba automática de vulnerabilidad.
    </div>`);
  }

  $("findings").innerHTML = items.length ? items.join("") : '<div class="finding"><span class="ok">Sin hallazgos en las reglas actuales.</span></div>';
}

function renderScripts(data) {
  $("scripts").innerHTML = data.scripts.map((s) => {
    if (!s.src) return `<div class="script"><b>Inline JavaScript</b></div>`;
    const label = s.src.startsWith(data.pageOrigin) ? '<span class="ok">Primero</span>' : '<span class="warn">Tercero</span>';
    const sri = s.integrity ? '<span class="ok">SRI ✓</span>' : '<span class="warn">SRI —</span>';
    return `<div class="script">${label} · ${sri}<br>${escapeHtml(s.src)}</div>`;
  }).join("");
}

function escapeHtml(value) {
  return String(value).replace(/[&<>'"]/g, (c) => ({ '&':'&amp;', '<':'&lt;', '>':'&gt;', "'":'&#39;', '"':'&quot;' }[c]));
}

async function audit() {
  $("status").textContent = "Solicitando acceso al sitio y analizando…";
  try {
    const tab = await getActiveTab();
    const allowed = await ensureHostAccess(tab.url);
    if (!allowed) throw new Error("No se concedió acceso al sitio.");

    const data = await collectPageData(tab.id);
    await new Promise((resolve) => setTimeout(resolve, 150));
    const response = await chrome.runtime.sendMessage({ type: "GET_CORS_RESULTS", tabId: tab.id });
    const corsEntries = response?.entries || [];

    renderSummary(data, corsEntries);
    renderFindings(data, corsEntries);
    renderScripts(data);
    $("status").textContent = `Auditoría completada: ${data.pageOrigin}`;
  } catch (error) {
    console.error(error);
    $("status").textContent = `Error: ${error.message}`;
  }
}

$("scanBtn").addEventListener("click", audit);
$("protectBtn").addEventListener("click", () => {
  protectionEnabled = !protectionEnabled;
  $("protectBtn").textContent = `Modo protección: ${protectionEnabled ? "ON" : "OFF"}`;
  $("status").textContent = protectionEnabled
    ? "Modo protección experimental activado. En esta versión solo se registra el estado; el bloqueo se implementará después de validar las reglas de detección."
    : "Modo protección desactivado.";
});
