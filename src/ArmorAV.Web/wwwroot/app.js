const state = {
  jobId: null,
  report: null,
  pollTimer: null,
  token: null,
  locations: {},
  currentBrowsePath: null,
  browseParent: null,
  selectedObject: null
};

const el = (id) => document.getElementById(id);
const text = (id, value) => { el(id).textContent = value; };
const formatBytes = (value) => value < 1024 ? `${value} Б` : value < 1024 * 1024 ? `${(value / 1024).toFixed(1)} КБ` : `${(value / 1024 / 1024).toFixed(1)} МБ`;
const escapeHtml = (value) => String(value ?? "").replace(/[&<>'"]/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", '"': "&quot;" }[char]));

async function api(path, options = {}) {
  if (!state.token) throw new Error("Локальная сессия ещё не готова.");
  const headers = new Headers(options.headers || {});
  headers.set("X-ArmorAV-Token", state.token);
  return fetch(path, { ...options, headers });
}

function showView(name) {
  document.querySelectorAll(".view").forEach((view) => view.classList.toggle("active", view.id === `${name}-view`));
  document.querySelectorAll(".nav-item").forEach((button) => button.classList.toggle("active", button.dataset.view === name));
  if (name === "quarantine") loadQuarantine();
}

function verdictClass(verdict) {
  return verdict === "Confirmed" ? "confirmed" : verdict === "Suspicious" ? "suspicious" : "clean";
}

function renderReport(report) {
  state.report = report;
  const confirmed = report.confirmed || 0;
  text("metric-status", confirmed ? "Внимание" : "Готов");
  text("metric-files", report.filesScanned);
  text("metric-threats", confirmed);
  text("metric-duration", `${report.durationSeconds.toFixed(2)} с`);
  text("hero-title", confirmed ? "Есть подтверждённые угрозы" : "Проверка завершена");
  text("recent-caption", `Проверено ${report.filesScanned} объект(ов) · ${formatBytes(report.bytesScanned)} · ${report.durationSeconds.toFixed(2)} с`);
  text("result-caption", `Подтверждено: ${confirmed} · Подозрительно: ${report.suspicious} · Чисто: ${report.clean} · Пропущено: ${report.skipped.length}`);
  renderResults(report.results, report.skipped);
  renderRecent(report.results);
  document.querySelectorAll("[data-report]").forEach((button) => { button.disabled = false; });
}

function renderResults(results, skipped) {
  const list = el("result-list");
  if (!results.length && !skipped.length) {
    list.innerHTML = '<div class="empty-state compact"><span>◌</span><p>Срабатываний и результатов нет.</p></div>';
    return;
  }
  list.innerHTML = results.map((result, index) => `<button class="result-row" data-result="${index}"><span class="verdict ${verdictClass(result.verdict)}">${escapeHtml(result.verdict)}</span><span class="score">${result.score}</span><span class="type">${escapeHtml(result.fileType)}</span><span class="row-path" title="${escapeHtml(result.path)}">${escapeHtml(result.path)}</span></button>`).join("") + skipped.map((item) => `<div class="result-row skipped"><span class="verdict suspicious">ПРОПУЩЕН</span><span class="score">—</span><span class="type">—</span><span class="row-path" title="${escapeHtml(item.reason)}">${escapeHtml(item.path)} · ${escapeHtml(item.reason)}</span></div>`).join("");
  list.querySelectorAll("[data-result]").forEach((button) => button.addEventListener("click", () => showResult(results[Number(button.dataset.result)])));
}

function renderRecent(results) {
  const target = el("recent-list");
  if (!results.length) {
    target.classList.add("hidden");
    el("recent-empty").classList.remove("hidden");
    return;
  }
  el("recent-empty").classList.add("hidden");
  target.classList.remove("hidden");
  target.innerHTML = results.slice(0, 6).map((result) => `<div class="recent-row"><span class="verdict ${verdictClass(result.verdict)}">${escapeHtml(result.verdict)}</span><span class="recent-path" title="${escapeHtml(result.path)}">${escapeHtml(result.path)}</span><span class="score">${result.score}</span></div>`).join("");
}

function showResult(result) {
  text("details-title", `${result.verdict} · ${result.score} баллов`);
  text("details-body", `Тип: ${result.fileType}\nSHA-256: ${result.sha256 || "—"}\nСемейства: ${result.families.join(", ") || "—"}\nATT&CK: ${result.techniques.join(", ") || "—"}${result.quarantineNote ? `\nКарантин: ${result.quarantineNote}` : ""}`);
  el("details-findings").innerHTML = result.findings.length ? result.findings.map((finding) => `<span class="finding-chip"><b>${escapeHtml(finding.severity)} · ${escapeHtml(finding.name)}</b><br>${escapeHtml(finding.detail)}</span>`).join("") : "";
}

function addOption(parent, label, value, kind) {
  const option = document.createElement("option");
  option.textContent = label;
  option.value = value;
  option.dataset.kind = kind;
  parent.append(option);
}

function populateLocations(locations) {
  const select = el("location-select");
  select.replaceChildren();
  const entries = [
    ["Домашняя папка", locations.home],
    ["Загрузки", locations.downloads],
    ["Документы", locations.documents],
    ["Рабочий стол", locations.desktop]
  ];
  const seen = new Set();
  entries.forEach(([label, path]) => {
    if (!path || seen.has(path)) return;
    seen.add(path);
    addOption(select, label, path, "location");
  });
  select.disabled = !select.options.length;
  if (select.options.length) loadFolder(select.value);
}

function populateObjects(data) {
  const select = el("object-select");
  select.replaceChildren();
  addOption(select, "Выберите файл или папку", "", "");
  if (data.directories.length) {
    const folders = document.createElement("optgroup");
    folders.label = "Папки";
    data.directories.forEach((item) => addOption(folders, `Папка · ${item.name}`, item.path, "directory"));
    select.append(folders);
  }
  if (data.files.length) {
    const files = document.createElement("optgroup");
    files.label = "Файлы";
    data.files.forEach((item) => addOption(files, `Файл · ${item.name} · ${formatBytes(item.size)}`, item.path, "file"));
    select.append(files);
  }
  select.disabled = false;
  state.selectedObject = null;
  el("open-selected").disabled = true;
  el("use-selected-object").disabled = true;
  el("use-current-folder").disabled = false;
  text("folder-caption", data.directories.length || data.files.length ? "Выберите объект из выпадающего списка." : "В этой папке нет доступных объектов.");
}

async function loadFolder(path) {
  if (!path) return;
  const select = el("object-select");
  select.disabled = true;
  select.replaceChildren();
  addOption(select, "Загрузка содержимого…", "", "");
  try {
    const response = await api(`/api/browse?path=${encodeURIComponent(path)}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "Не удалось открыть папку.");
    state.currentBrowsePath = data.path;
    state.browseParent = data.parentPath;
    text("browser-folder", data.path);
    el("parent-folder").disabled = !data.parentPath;
    populateObjects(data);
  } catch (error) {
    text("folder-caption", error.message || "Не удалось открыть папку.");
    select.disabled = true;
    el("parent-folder").disabled = true;
    el("use-current-folder").disabled = true;
    toast(error.message || "Не удалось открыть папку.");
  }
}

function selectedOption() {
  const select = el("object-select");
  return select.options[select.selectedIndex];
}

function updateObjectSelection() {
  const option = selectedOption();
  const path = option?.value;
  const kind = option?.dataset.kind;
  state.selectedObject = path ? { path, kind } : null;
  el("use-selected-object").disabled = !state.selectedObject;
  el("open-selected").disabled = !state.selectedObject || kind !== "directory";
  if (!state.selectedObject) {
    text("folder-caption", "Выберите файл или папку из выпадающего списка.");
    return;
  }
  text("folder-caption", kind === "directory" ? "Можно открыть эту папку или назначить её для проверки." : "Файл готов: нажмите «Использовать объект».");
}

function setTarget(path, kind) {
  if (!path) return;
  el("target-path").value = path;
  text("target-kind", kind === "directory" ? "ПАПКА" : "ФАЙЛ");
  text("scan-status", kind === "directory" ? "Папка выбрана и готова к анализу." : "Файл выбран и готов к анализу.");
}

async function startScan() {
  const path = el("target-path").value.trim();
  if (!path) {
    toast("Выберите файл или папку через выпадающий список.");
    return;
  }
  const command = {
    path,
    quarantineConfirmed: el("quarantine-enabled").checked,
    useCache: el("cache-enabled").checked,
    maxDepth: Number(el("max-depth").value),
    threads: Number(el("thread-count").value)
  };
  try {
    const response = await api("/api/scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(command) });
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "Не удалось начать проверку.");
    state.jobId = data.id;
    text("scan-status", "Проверка поставлена в очередь…");
    text("live-status", "Выполняется анализ");
    el("spinner").classList.remove("hidden");
    el("start-scan").disabled = true;
    el("result-list").innerHTML = '<div class="empty-state compact"><span class="spinner"></span><p>ArmorAV выполняет локальный анализ…</p></div>';
    pollScan();
  } catch (error) {
    toast(error.message || "Не удалось начать проверку.");
  }
}

async function pollScan() {
  if (!state.jobId) return;
  try {
    const response = await api(`/api/scans/${state.jobId}`);
    const data = await response.json();
    if (!response.ok) throw new Error(data.message || "Не удалось получить состояние проверки.");
    text("scan-status", data.message);
    if (data.state === "completed") {
      clearTimeout(state.pollTimer);
      el("spinner").classList.add("hidden");
      el("start-scan").disabled = false;
      text("live-status", "Готов к проверке");
      renderReport(data.report);
      toast("Проверка завершена.");
      return;
    }
    if (data.state === "failed") {
      clearTimeout(state.pollTimer);
      el("spinner").classList.add("hidden");
      el("start-scan").disabled = false;
      text("live-status", "Ошибка проверки");
      toast(data.message || "Проверка завершилась с ошибкой.");
      return;
    }
    state.pollTimer = setTimeout(pollScan, 650);
  } catch (error) {
    state.pollTimer = setTimeout(pollScan, 1000);
  }
}

async function loadQuarantine() {
  const list = el("quarantine-list");
  text("quarantine-caption", "Загрузка списка…");
  list.innerHTML = "";
  try {
    const response = await api("/api/quarantine");
    const records = await response.json();
    if (!response.ok) throw new Error("Не удалось загрузить карантин.");
    text("quarantine-caption", records.length ? `Объектов в карантине: ${records.length}` : "Карантин пуст.");
    list.innerHTML = records.length ? records.map((record) => `<div class="quarantine-row"><div><h4>${escapeHtml(record.originalPath)}</h4><p>${escapeHtml(record.timestampUtc)} · SHA-256: ${escapeHtml(record.sha256)}</p></div><button class="restore-button" data-restore="${record.id}">Восстановить</button></div>`).join("") : '<div class="empty-state compact"><span>▣</span><p>В карантине пока нет объектов.</p></div>';
    list.querySelectorAll("[data-restore]").forEach((button) => button.addEventListener("click", () => restoreItem(button.dataset.restore)));
  } catch (error) {
    text("quarantine-caption", error.message || "Не удалось загрузить карантин.");
  }
}

async function restoreItem(id) {
  try {
    const response = await api(`/api/quarantine/${encodeURIComponent(id)}/restore`, { method: "POST" });
    const data = await response.json();
    toast(data.message || "Не удалось восстановить объект.");
    if (response.ok) loadQuarantine();
  } catch {
    toast("Не удалось восстановить объект.");
  }
}

async function downloadReport(format) {
  if (!state.jobId) {
    toast("Сначала завершите проверку.");
    return;
  }
  try {
    const response = await api(`/api/scans/${state.jobId}/report?format=${encodeURIComponent(format)}`);
    if (!response.ok) {
      const data = await response.json();
      throw new Error(data.message || "Не удалось скачать отчёт.");
    }
    const blob = await response.blob();
    const link = document.createElement("a");
    link.href = URL.createObjectURL(blob);
    link.download = `ArmorAV-report.${format}`;
    link.click();
    URL.revokeObjectURL(link.href);
  } catch (error) {
    toast(error.message || "Не удалось скачать отчёт.");
  }
}

function toast(message) {
  const box = el("toast");
  box.textContent = message;
  box.classList.remove("hidden");
  clearTimeout(box.timer);
  box.timer = setTimeout(() => box.classList.add("hidden"), 4200);
}

document.querySelectorAll("[data-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.view)));
document.querySelectorAll("[data-open-view]").forEach((button) => button.addEventListener("click", () => showView(button.dataset.openView)));
el("hero-scan").addEventListener("click", () => showView("scan"));
el("location-select").addEventListener("change", (event) => loadFolder(event.target.value));
el("object-select").addEventListener("change", updateObjectSelection);
el("parent-folder").addEventListener("click", () => { if (state.browseParent) loadFolder(state.browseParent); });
el("open-selected").addEventListener("click", () => { if (state.selectedObject?.kind === "directory") loadFolder(state.selectedObject.path); });
el("use-current-folder").addEventListener("click", () => setTarget(state.currentBrowsePath, "directory"));
el("use-selected-object").addEventListener("click", () => { if (state.selectedObject) setTarget(state.selectedObject.path, state.selectedObject.kind); });
el("start-scan").addEventListener("click", startScan);
el("refresh-quarantine").addEventListener("click", loadQuarantine);
document.querySelectorAll("[data-report]").forEach((button) => button.addEventListener("click", () => downloadReport(button.dataset.report)));
el("stop-app").addEventListener("click", async () => {
  try {
    const response = await api("/api/shutdown", { method: "POST" });
    if (!response.ok) throw new Error();
    text("live-status", "ArmorAV завершён");
    toast("ArmorAV завершён. Эту вкладку можно закрыть.");
  } catch {
    toast("Не удалось завершить ArmorAV.");
  }
});

fetch("/api/config").then((response) => response.json()).then((data) => {
  state.token = data.token;
  state.locations = data.locations || {};
  text("live-status", `Готов · ${data.version}`);
  populateLocations(state.locations);
}).catch(() => text("live-status", "Не удалось подключиться к локальному сервису"));
