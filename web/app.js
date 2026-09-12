/* SentinelForge console: API data is rendered with textContent only. */
(function () {
  "use strict";

  const state = {
    data: { runs: [], alerts: [], incidents: [], investigations: [] },
    page: "overview",
    user: null,
    accessToken: null,
    selectedIncident: null
  };
  const $ = (id) => document.getElementById(id);
  const esc = (value) => value == null || value === "" ? "—" : String(value);
  const date = (value) => value ? new Date(value).toLocaleString() : "—";
  const jsonText = (value) => JSON.stringify(value, null, 2);

  function node(tag, text, className) {
    const element = document.createElement(tag);
    if (className) element.className = className;
    if (text != null) element.textContent = text;
    return element;
  }
  function button(text, className, handler) {
    const element = node("button", text, className || "link-button");
    element.type = "button";
    element.addEventListener("click", handler);
    return element;
  }
  function badge(value, kind) {
    return node("span", esc(value), `badge ${kind || "status"} ${value || "unknown"}`);
  }
  function appendValue(parent, label, value, className) {
    const item = node("div", null, "detail-item");
    item.append(node("strong", label), node("span", esc(value), className || ""));
    parent.append(item);
  }
  function csrfToken() {
    const item = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith("sf_csrf="));
    return item ? decodeURIComponent(item.slice(8)) : "";
  }
  async function request(path, options) {
    const baseHeaders = Object.assign({ Accept: "application/json" }, state.accessToken ? { Authorization: `Bearer ${state.accessToken}` } : {});
    if (options && options.method && options.method !== "GET") baseHeaders["X-CSRF-Token"] = csrfToken();
    let response;
    try { response = await fetch(path, Object.assign({ credentials: "same-origin", headers: baseHeaders }, options || {})); }
    catch (_) { throw new Error("API unavailable. Start `python -m sentinelforge serve` and refresh."); }
    let body;
    try { body = await response.json(); } catch (_) { throw new Error("The API returned invalid JSON."); }
    if (!response.ok) {
      const error = new Error(body && body.error ? body.error : `API request failed (${response.status}).`);
      error.status = response.status;
      if (response.status === 401) handleSessionExpired();
      if (response.status === 403) showMessage("You do not have permission to perform this action.");
      throw error;
    }
    return body;
  }
  function payloadValue(body, key, fallback) {
    if (body && body[key] !== undefined) return body[key];
    if (body && body.data && body.data[key] !== undefined) return body.data[key];
    return fallback;
  }
  function normalizeUser(body) {
    const user = body && (body.user || body.data && (body.data.user || body.data) || body);
    return user && typeof user === "object" && (user.username || user.name || user.user_id || user.id || user.role) ? user : null;
  }
  function normalizeList(body, key) {
    const value = payloadValue(body, key, body);
    return Array.isArray(value) ? value : [];
  }
  const api = {
    health: () => request("/health"), me: () => request("/auth/me"),
    login: (body) => request("/auth/login", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }),
    logout: () => request("/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }),
    users: () => request("/users"), audit: () => request("/audit"),
    runs: (limit) => request(`/runs${limit ? `?limit=${limit}` : ""}`),
    alerts: (severityValue) => request(`/alerts${severityValue ? `?severity=${encodeURIComponent(severityValue)}` : ""}`),
    incidents: (severityValue) => request(`/incidents${severityValue ? `?severity=${encodeURIComponent(severityValue)}` : ""}`),
    investigations: () => request("/investigations"),
    detail: (resource, id) => request(`/${resource}/${encodeURIComponent(id)}`),
    analyze: (body) => request("/analyze", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) })
  };
  function showMessage(message) { $("global-message").textContent = message; $("global-message").classList.remove("hidden"); }
  function clearMessage() { $("global-message").classList.add("hidden"); }
  function handleSessionExpired() { state.user = null; $("current-user").textContent = "Session expired"; $("logout-btn").classList.add("hidden"); showMessage("Your session has expired. Sign in again to continue."); showLogin(); }
  function showLogin() { $("login-view").classList.remove("hidden"); document.querySelectorAll(".page").forEach((element) => element.classList.add("hidden")); }
  function setUser(user) {
    state.user = user;
    $("current-user").textContent = user ? `${user.username || user.name || "User"} · ${user.role || ""}` : "Local session";
    $("logout-btn").classList.toggle("hidden", !user);
    document.querySelectorAll(".admin-only").forEach((element) => element.classList.toggle("hidden", !user || user.role !== "admin"));
    const panel = $("analyze-form").closest(".analyze-panel");
    if (panel) panel.classList.toggle("hidden", !!user && user.role === "viewer");
    $("login-view").classList.toggle("hidden", !!user);
    if (user) document.querySelectorAll(".page").forEach((element) => element.classList.remove("hidden"));
  }
  async function load() {
    try {
      const [health, runsResponse, alertsResponse, incidentsResponse, investigationsResponse] = await Promise.all([api.health(), api.runs(20), api.alerts(), api.incidents(), api.investigations()]);
      state.data = { runs: normalizeList(runsResponse, "runs"), alerts: normalizeList(alertsResponse, "alerts"), incidents: normalizeList(incidentsResponse, "incidents"), investigations: normalizeList(investigationsResponse, "investigations") };
      $("api-status").textContent = "API reachable";
      $("api-status").className = "status-dot available";
      clearMessage();
      renderAll();
    } catch (error) {
      $("api-status").textContent = "API unavailable";
      $("api-status").className = "status-dot unavailable";
      showMessage(error.message);
      renderAll();
    }
  }
  function renderAll() { renderOverview(); renderAlerts(); renderIncidents(); renderInvestigations(); renderRuns(); }
  function riskFor(incident) { return incident.risk_assessment || {}; }
  function sortedIncidents(incidents) {
    return [...incidents].sort((left, right) => {
      const score = (Number(riskFor(right).score) || 0) - (Number(riskFor(left).score) || 0);
      if (score) return score;
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      const severityDifference = (severityOrder[right.severity] || 0) - (severityOrder[left.severity] || 0);
      if (severityDifference) return severityDifference;
      const time = String(right.updated_at || right.created_at || "").localeCompare(String(left.updated_at || left.created_at || ""));
      return time || String(left.incident_id || "").localeCompare(String(right.incident_id || ""));
    });
  }
  function renderOverview() {
    const { alerts, incidents, investigations, runs } = state.data;
    const risks = incidents.map(riskFor).filter((item) => item.score != null);
    const highest = risks.reduce((best, item) => !best || item.score > best.score ? item : best, null);
    $("summary-cards").replaceChildren(...[["Total alerts", alerts.length, "Persisted detections"], ["Incidents", incidents.length, "Correlated activity"], ["Active investigations", investigations.filter((item) => item.status === "active").length, "Open analyst context"], ["Highest risk", highest ? `${highest.score} · ${highest.level}` : "None", "Deterministic prioritization"]].map((item) => { const card = node("div", null, "metric"); card.append(node("div", item[0], "metric-label"), node("div", item[1], "metric-value"), node("div", item[2], "metric-sub")); return card; }));
    renderTriageQueue($("triage-queue"), sortedIncidents(incidents));
    const counts = ["low", "medium", "high", "critical"].map((level) => [level, alerts.filter((item) => item.severity === level).length]);
    const max = Math.max(1, ...counts.map((item) => item[1]));
    $("severity-chart").replaceChildren(...counts.map(([level, count]) => { const row = node("div", null, "dist-row"); const bar = node("div", null, "bar"); const fill = node("i"); fill.style.width = `${count / max * 100}%`; bar.append(fill); row.append(node("span", level), bar, node("strong", count)); return row; }));
    renderRunRows($("overview-runs"), runs.slice(-5).reverse(), true);
  }
  function renderTriageQueue(container, incidents) {
    if (!incidents.length) { container.replaceChildren(node("div", "No incidents available for triage.", "empty")); return; }
    const table = node("table", null, "data-table triage-table");
    const head = node("thead"); const header = node("tr"); ["Severity", "Risk", "Incident", "Summary", "Status", "Alerts", "Updated"].forEach((label) => header.append(node("th", label))); head.append(header); table.append(head);
    const body = node("tbody");
    incidents.forEach((item) => {
      const risk = riskFor(item); const row = node("tr", null, "clickable-row"); row.tabIndex = 0;
      row.append(node("td", null), node("td", `${esc(risk.score)} · ${esc(risk.level)}`, "risk-cell"), node("td", item.incident_id, "mono id"), node("td", item.title || item.description), node("td", null), node("td", (item.related_alert_ids || []).length), node("td", date(item.updated_at || item.created_at), "muted"));
      row.children[0].append(badge(item.severity, "severity-badge")); row.children[4].append(badge(item.status, "status-badge"));
      row.addEventListener("click", () => openIncidentWorkspace(item.incident_id)); row.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openIncidentWorkspace(item.incident_id); } }); body.append(row);
    });
    table.append(body); container.replaceChildren(table);
  }
  function renderAlertRows(container, rows, compact) {
    if (!rows.length) { container.replaceChildren(node("div", "No alerts available.", "empty")); return; }
    const table = node("table", null, "data-table"); const head = node("thead"); const header = node("tr"); ["Severity", "Rule", "Title", "Timestamp", ...(compact ? [] : ["Evidence"])].forEach((label) => header.append(node("th", label))); head.append(header); table.append(head);
    const body = node("tbody"); rows.forEach((item) => { const row = node("tr", null, "clickable-row"); row.tabIndex = 0; row.append(node("td", null), node("td", item.rule_id, "mono id"), node("td", item.title), node("td", date(item.timestamp), "muted")); if (!compact) row.append(node("td", item.evidence ? item.evidence.length : 0)); row.children[0].append(badge(item.severity, "severity-badge")); const open = () => detail("alerts", item.alert_id); row.addEventListener("click", open); row.addEventListener("keydown", (event) => { if (event.key === "Enter") open(); }); body.append(row); }); table.append(body); container.replaceChildren(table);
  }
  function renderIncidentRows(container, rows, compact) { renderTriageQueue(container, sortedIncidents(rows)); }
  function renderRunRows(container, rows, compact) {
    if (!rows.length) { container.replaceChildren(node("div", "No analysis runs available.", "empty")); return; }
    const table = node("table", null, "data-table"); const head = node("thead"); const header = node("tr"); ["Timestamp", "Source", "Type", "Events", "Diagnostics"].forEach((label) => header.append(node("th", label))); head.append(header); table.append(head); const body = node("tbody");
    rows.forEach((item) => { const row = node("tr", null, "clickable-row"); row.tabIndex = 0; row.append(node("td", date(item.started_at), "muted"), node("td", item.source, "mono"), node("td", item.source_type), node("td", item.event_count), node("td", item.diagnostic_count)); const open = () => detail("runs", item.run_id); row.addEventListener("click", open); row.addEventListener("keydown", (event) => { if (event.key === "Enter") open(); }); body.append(row); }); table.append(body); container.replaceChildren(table);
  }
  function renderRuns() { renderRunRows($("runs-list"), state.data.runs, false); }
  function renderAlerts() { const severityValue = $("alert-severity").value; const rule = $("alert-rule").value.toLowerCase(); renderAlertRows($("alerts-list"), state.data.alerts.filter((item) => (!severityValue || item.severity === severityValue) && (!rule || String(item.rule_id).toLowerCase().includes(rule))), false); }
  function renderIncidents() { const value = $("incident-severity").value; renderIncidentRows($("incidents-list"), state.data.incidents.filter((item) => !value || item.severity === value), false); }
  function renderInvestigations() {
    const rows = state.data.investigations;
    if (!rows.length) { $("investigations-list").replaceChildren(node("div", "No investigations available.", "empty")); return; }
    const table = node("table", null, "data-table"); const head = node("thead"); const header = node("tr"); ["Status", "Investigation", "Incident", "Evidence", "Timeline", "Notes"].forEach((label) => header.append(node("th", label))); head.append(header); table.append(head); const body = node("tbody");
    rows.forEach((item) => { const row = node("tr", null, "clickable-row"); row.tabIndex = 0; row.append(node("td", null), node("td", item.investigation_id, "mono id"), node("td", item.incident_id, "mono id"), node("td", (item.evidence || []).length), node("td", (item.timeline || []).length), node("td", (item.analyst_notes || []).length)); row.children[0].append(badge(item.status, "status-badge")); const open = () => detail("investigations", item.investigation_id); row.addEventListener("click", open); row.addEventListener("keydown", (event) => { if (event.key === "Enter") open(); }); body.append(row); }); table.append(body); $("investigations-list").replaceChildren(table);
  }
  function renderCollection(container, values, title, renderer) {
    if (!values || !values.length) return;
    const section = node("section", null, "detail-section"); section.append(node("h3", title)); values.forEach((value) => section.append(renderer(value))); container.append(section);
  }
  function renderEvidence(value, investigationMode) {
    const event = value.event || value; const block = node("article", null, "evidence-card"); const heading = node("div", null, "evidence-heading"); heading.append(node("strong", value.summary || event.message || value.evidence_id || "Evidence"), node("span", date(value.timestamp || event.timestamp), "muted")); block.append(heading);
    const grid = node("div", null, "evidence-grid"); appendValue(grid, "Evidence ID", value.evidence_id, "mono"); appendValue(grid, "Source", value.source || event.source); appendValue(grid, "Hostname", event.hostname); appendValue(grid, "Username", event.username); appendValue(grid, "Event type", event.event_type); if (investigationMode) { appendValue(grid, "Relevance", value.relevance); appendValue(grid, "Provenance", value.provenance); } block.append(grid);
    const raw = document.createElement("details"); raw.append(node("summary", "View raw evidence"), node("pre", jsonText(value.event || value), "raw-evidence")); block.append(raw); return block;
  }
  function renderTimeline(values) { const list = node("ol", null, "timeline"); values.forEach((entry) => { const item = node("li", null, "timeline-item"); item.append(node("time", date(entry.timestamp)), node("strong", entry.summary || entry.evidence_id), node("span", entry.evidence_id, "mono muted")); list.append(item); }); return list; }
  function renderLinks(container, ids, resource, label) { if (!ids || !ids.length) return; const section = node("section", null, "detail-section"); section.append(node("h3", label)); const list = node("div", null, "chip-list"); ids.forEach((id) => list.append(button(id, "id-link", () => detail(resource, id)))); section.append(list); container.append(section); }
  async function openIncidentWorkspace(id) {
    const incident = state.data.incidents.find((item) => item.incident_id === id);
    if (!incident) return;
    state.selectedIncident = id; $("workspace-title").textContent = incident.title || "Incident workspace"; const content = $("workspace-content"); content.replaceChildren(node("div", "Loading incident details…", "empty")); $("incident-workspace").classList.remove("hidden"); $("workspace-close").focus();
    try {
      const detailValue = await api.detail("incidents", id); const risk = riskFor(detailValue); content.replaceChildren();
      const summary = node("section", null, "workspace-summary"); summary.append(node("p", detailValue.description, "muted")); const badges = node("div", null, "workspace-badges"); badges.append(badge(detailValue.severity, "severity-badge"), node("span", `${esc(risk.score)} · ${esc(risk.level)}`, "risk-badge"), badge(detailValue.status, "status-badge")); summary.append(badges); content.append(summary);
      const facts = node("div", null, "detail-grid"); appendValue(facts, "Incident ID", detailValue.incident_id, "mono"); appendValue(facts, "Created", date(detailValue.created_at)); appendValue(facts, "Updated", date(detailValue.updated_at)); appendValue(facts, "Affected users", (detailValue.affected_users || []).join(", ")); appendValue(facts, "Affected entities", (detailValue.affected_entities || []).join(", ")); content.append(facts);
      if (detailValue.risk_assessment) { const riskSection = node("section", null, "detail-section"); riskSection.append(node("h3", "Risk assessment"), node("p", detailValue.risk_assessment.explanation || "No explanation provided.", "muted")); (detailValue.risk_assessment.factors || []).forEach((factor) => riskSection.append(node("div", factor, "factor"))); content.append(riskSection); }
      renderLinks(content, detailValue.related_alert_ids, "alerts", "Related alerts");
      renderCollection(content, detailValue.correlations, "Correlations", (value) => { const item = node("div", null, "fact-block"); item.append(node("strong", value.name || value.correlation_id), node("p", value.rationale || value.description)); return item; });
      renderCollection(content, detailValue.attack_mappings, "ATT&CK mappings", (value) => node("div", `${value.technique_id || value.id || "Technique"} · ${value.name || value.description || ""}`, "fact-block"));
      renderCollection(content, detailValue.threat_context, "Threat context", (value) => node("div", jsonText(value), "fact-block mono"));
      renderCollection(content, detailValue.evidence, "Evidence", (value) => renderEvidence(value, true));
      if (detailValue.evidence && detailValue.evidence.length) { const timelineValues = detailValue.evidence.map((value) => ({ timestamp: value.timestamp, evidence_id: value.evidence_id, summary: value.relevance || value.evidence_type || value.event && value.event.event_type })); content.append(node("section", null, "detail-section"),); const section = content.lastChild; section.append(node("h3", "Chronology"), renderTimeline(timelineValues.sort((a, b) => String(a.timestamp).localeCompare(String(b.timestamp))))); }
      const investigation = state.data.investigations.find((item) => item.incident_id === id); if (investigation) { const section = node("section", null, "detail-section"); section.append(node("h3", "Investigation"), button(`${investigation.investigation_id} · ${investigation.status}`, "id-link", () => detail("investigations", investigation.investigation_id))); if (investigation.timeline && investigation.timeline.length) section.append(renderTimeline(investigation.timeline)); content.append(section); }
    } catch (error) { content.replaceChildren(node("div", error.message, "message")); }
  }
  function closeWorkspace() { $("incident-workspace").classList.add("hidden"); state.selectedIncident = null; }
  function detail(resource, id) {
    api.detail(resource, id).then((item) => { $("detail-title").textContent = `${resource.slice(0, -1).toUpperCase()} DETAILS`; const content = $("detail-content"); content.replaceChildren(); const heading = node("div", null, "detail-grid"); Object.entries(item).filter(([key]) => !["evidence", "timeline", "analyst_notes"].includes(key)).forEach(([key, value]) => appendValue(heading, key.replaceAll("_", " "), typeof value === "object" ? jsonText(value) : value, typeof value === "string" && value.length > 28 ? "mono" : "")); content.append(heading); renderCollection(content, item.evidence, "Evidence", (value) => renderEvidence(value, true)); if (item.timeline && item.timeline.length) { const section = node("section", null, "detail-section"); section.append(node("h3", "Chronology"), renderTimeline(item.timeline)); content.append(section); } renderCollection(content, item.analyst_notes, "Analyst notes", (value) => node("div", value.content, "fact-block")); $("detail-modal").classList.remove("hidden"); $("modal-close").focus(); }).catch((error) => showMessage(error.message));
  }
  function showPage(page) { state.page = page; document.querySelectorAll(".page").forEach((element) => element.classList.toggle("active", element.id === `page-${page}`)); document.querySelectorAll(".nav-item").forEach((element) => element.classList.toggle("active", element.dataset.page === page)); $("main").focus(); }
  document.querySelectorAll(".nav-item,[data-page-link]").forEach((element) => element.addEventListener("click", () => showPage(element.dataset.page || element.dataset.pageLink)));
  $("refresh-btn").addEventListener("click", load); $("alert-severity").addEventListener("change", renderAlerts); $("alert-rule").addEventListener("input", renderAlerts); $("incident-severity").addEventListener("change", renderIncidents);
  $("modal-close").addEventListener("click", () => $("detail-modal").classList.add("hidden")); $("workspace-close").addEventListener("click", closeWorkspace); $("detail-modal").addEventListener("click", (event) => { if (event.target === $("detail-modal")) $("detail-modal").classList.add("hidden"); }); document.addEventListener("keydown", (event) => { if (event.key === "Escape") { $("detail-modal").classList.add("hidden"); closeWorkspace(); } });
  $("analyze-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = new FormData(event.target); const body = {}; for (const [key, value] of form.entries()) if (value) body[key] = value; $("analyze-result").classList.remove("hidden"); $("analyze-result").textContent = "Running analysis…"; try { const result = await api.analyze(body); $("analyze-result").textContent = `Analysis complete: ${result.alerts.length} alerts, ${result.incidents.length} incidents, ${result.investigations.length} investigations.`; await load(); } catch (error) { $("analyze-result").textContent = error.message; } });
  $("login-form").addEventListener("submit", async (event) => { event.preventDefault(); const form = new FormData(event.target); const message = $("login-message"); message.classList.remove("hidden"); message.textContent = "Signing in…"; try { const user = await api.login({ username: form.get("username"), password: form.get("password") }); event.target.reset(); message.classList.add("hidden"); state.accessToken = user && (user.access_token || user.token || user.data && (user.data.access_token || user.data.token)) || null; setUser(normalizeUser(user)); await load(); } catch (error) { message.textContent = error.status === 401 ? "Invalid username or password." : error.message; } });
  $("logout-btn").addEventListener("click", async () => { try { await api.logout(); } catch (_) {} state.accessToken = null; setUser(null); showLogin(); });
  api.me().then((user) => { const currentUser = normalizeUser(user); if (!currentUser) throw Object.assign(new Error("Authentication required."), { status: 401 }); setUser(currentUser); load(); }).catch(() => { setUser(null); showLogin(); });
}());
