"use strict";
const $ = (id) => document.getElementById(id);
const state = {
  token: "",
  view: "overview",
  alertsOffset: 0,
  eventsOffset: 0,
  charts: [],
  alert: null,
};
const pageSize = 25;
function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text != null) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function message(text = "") {
  $("message").textContent = text;
}
function modeParams() {
  const value = $("data-mode").value;
  return value === "all"
    ? new URLSearchParams()
    : new URLSearchParams({ synthetic: value });
}
function tableParams() {
  const params = modeParams();
  for (const [id, field] of [
    ["os-filter", "operating_system"],
    ["host-filter", "hostname"],
    ["rule-filter", "rule_id"],
  ])
    if ($(id).value) params.set(field, $(id).value);
  for (const [id, field] of [
    ["since-filter", "since"],
    ["until-filter", "until"],
  ])
    if ($(id).value)
      params.set(field, new Date($(id).value + "Z").toISOString());
  return params;
}
async function api(path, options = {}) {
  const response = await fetch(path, {
    ...options,
    headers: {
      Authorization: `Bearer ${state.token}`,
      "Content-Type": "application/json",
      ...options.headers,
    },
  });
  if (!response.ok) {
    if (response.status === 401) lock();
    throw new Error(
      `Request failed (${response.status}). Check the token, input and server logs.`,
    );
  }
  return response.json();
}
function lock() {
  state.token = "";
  state.alert = null;
  $("token").value = "";
  $("workspace").hidden = true;
  $("login").hidden = false;
  $("connection-state").textContent = "Locked";
  $("dialog-content").replaceChildren();
  $("investigation").close();
}
function badge(text, severity = false) {
  return el(
    "span",
    text.replaceAll("_", " "),
    `badge${severity ? ` ${text}` : ""}`,
  );
}
function date(value) {
  return value.slice(0, 19).replace("T", " ") + "Z";
}
function emptyRow(body, columns, text) {
  const row = el("tr"),
    cell = el("td", text, "empty");
  cell.colSpan = columns;
  row.append(cell);
  body.append(row);
}
function chart(id, type, labels, data, colors) {
  if (!window.Chart) {
    $(id).replaceWith(
      el(
        "p",
        "Chart library unavailable. Counts remain visible in the metrics and tables.",
        "muted",
      ),
    );
    return;
  }
  state.charts.push(
    new Chart($(id), {
      type,
      data: {
        labels,
        datasets: [
          {
            label: "Stored observations",
            data,
            backgroundColor: colors,
            borderColor: colors,
            borderWidth: type === "bar" ? 0 : 2,
            borderRadius: type === "bar" ? 4 : 0,
          },
        ],
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: type !== "bar",
            position: "bottom",
            labels: { color: "#aab7d0", boxWidth: 9, padding: 16 },
          },
        },
        scales:
          type === "bar"
            ? {
                x: {
                  ticks: { color: "#8b9bb7", maxTicksLimit: 8 },
                  grid: { display: false },
                },
                y: {
                  beginAtZero: true,
                  ticks: { color: "#8b9bb7", precision: 0 },
                  grid: { color: "#26304a" },
                },
              }
            : {},
      },
    }),
  );
}
async function overview() {
  const [data, recentReports] = await Promise.all([
    api(`/api/summary?${modeParams()}`),
    api(`/api/incidents?${modeParams()}&limit=5`),
  ]);
  $("metrics").replaceChildren();
  const metrics = [
    ["Events collected", data.total_events, "Stored evidence"],
    ["Events analysed", data.events_analysed, "Shared detection engine"],
    ["Total alerts", data.total_alerts, "All investigation statuses"],
    ["New alerts", data.statuses.new || 0, "Awaiting triage"],
    ["Critical alerts", data.severity.critical || 0, "Highest severity"],
    [
      "High-severity alerts",
      data.severity.high || 0,
      "Prioritise investigation",
    ],
    ["Windows hosts observed", data.hosts.windows || 0, "Evidence coverage"],
    ["Linux hosts observed", data.hosts.linux || 0, "Evidence coverage"],
    [
      "Authentication failures",
      data.authentication_failures,
      "Source event outcomes",
    ],
    [
      "Network policy findings",
      data.network_alerts,
      "Configured network rules",
    ],
    [
      "Saved incidents",
      data.incident_count,
      "Preserved investigation snapshots",
    ],
    [
      "Investigating",
      data.statuses.investigating || 0,
      "Active analyst workflow",
    ],
  ];
  for (const [label, value, note] of metrics) {
    const card = el("article", null, "metric");
    card.append(el("p", label), el("strong", value), el("small", note));
    $("metrics").append(card);
  }
  state.charts.forEach((item) => item.destroy());
  state.charts = [];
  chart(
    "activity-chart",
    "bar",
    data.authentication_timeline.map((x) => x.hour.slice(5)),
    data.authentication_timeline.map((x) => x.count),
    "#8d80e4",
  );
  const severityNames = ["critical", "high", "medium", "low"];
  chart(
    "severity-chart",
    "doughnut",
    severityNames,
    severityNames.map((x) => data.severity[x] || 0),
    ["#d9567b", "#fa8eaa", "#d9b770", "#78b9e6"],
  );
  chart(
    "os-chart",
    "doughnut",
    ["Windows", "Linux"],
    [data.hosts.windows || 0, data.hosts.linux || 0],
    ["#8a85e8", "#5aa6ce"],
  );
  $("top-sources").replaceChildren();
  if (!data.top_sources.length)
    $("top-sources").append(
      el(
        "p",
        "No source addresses associated with findings in this selection.",
        "empty",
      ),
    );
  for (const source of data.top_sources) {
    const row = el("div", null, "source-row");
    row.append(
      el("code", source.address),
      el("span", `${source.count} finding${source.count === 1 ? "" : "s"}`),
    );
    $("top-sources").append(row);
  }
  let recent = $("recent-incidents");
  if (!recent) {
    recent = el("article", null, "panel");
    recent.id = "recent-incidents";
    $("overview-view").append(recent);
  }
  recent.replaceChildren(el("h2", "Recent incidents"));
  if (!recentReports.length)
    recent.append(
      el(
        "p",
        "No saved incident snapshots in this evidence selection.",
        "empty",
      ),
    );
  for (const report of recentReports) {
    const row = el("div", null, "source-row");
    row.append(
      el("span", report.title),
      el("span", `${date(report.created_at)} · ${report.status}`),
    );
    recent.append(row);
  }
}
async function alerts() {
  const params = tableParams();
  params.set("limit", pageSize);
  params.set("offset", state.alertsOffset);
  if ($("severity-filter").value)
    params.set("severity", $("severity-filter").value);
  if ($("status-filter").value) params.set("status", $("status-filter").value);
  const data = await api(`/api/alerts?${params}`),
    body = $("alert-rows");
  body.replaceChildren();
  if (!data.length)
    emptyRow(body, 6, "No alerts match this evidence selection.");
  for (const alert of data) {
    const row = el("tr"),
      name = el("td", alert.name);
    name.append(
      el(
        "small",
        `${alert.hostname} · ${alert.operating_system} · ${alert.rule_id}`,
      ),
    );
    const severity = el("td");
    severity.append(badge(alert.severity, true));
    const status = el("td");
    status.append(badge(alert.status));
    const action = el("td"),
      button = el("button", "Open case");
    button.addEventListener("click", () =>
      investigate(alert.alert_id).catch((e) => message(e.message)),
    );
    action.append(button);
    row.append(
      name,
      severity,
      el("td", date(alert.timestamp)),
      status,
      el("td", `${alert.evidence_count} events`),
      action,
    );
    body.append(row);
  }
  $("alerts-prev").disabled = state.alertsOffset === 0;
  $("alerts-next").disabled = data.length < pageSize;
  $("alerts-page").textContent = `Page ${state.alertsOffset / pageSize + 1}`;
}
async function events() {
  const params = tableParams();
  params.set("limit", pageSize);
  params.set("offset", state.eventsOffset);
  if (["windows", "linux"].includes(state.view))
    params.set("operating_system", state.view);
  if (state.view === "authentication") params.set("category", "authentication");
  if (state.view === "network") params.set("category", "network");
  const data = await api(`/api/events?${params}`),
    body = $("event-rows");
  body.replaceChildren();
  if (!data.length) emptyRow(body, 6, "No stored events match this view.");
  for (const event of data) {
    const row = el("tr"),
      host = el("td", event.hostname);
    host.append(el("small", event.operating_system));
    const action = el("td"),
      button = el("button", "Evidence");
    button.addEventListener("click", () => {
      $("dialog-title").textContent = "Native and normalised event evidence";
      $("dialog-content").replaceChildren(
        el("pre", JSON.stringify(event, null, 2)),
      );
      $("investigation").showModal();
    });
    action.append(button);
    row.append(
      el("td", date(event.timestamp)),
      el("td", event.event_type.replaceAll("_", " ")),
      host,
      el("td", event.username || "Unavailable"),
      el("td", event.source_ip || event.source),
      action,
    );
    body.append(row);
  }
  $("events-prev").disabled = state.eventsOffset === 0;
  $("events-next").disabled = data.length < pageSize;
  $("events-page").textContent = `Page ${state.eventsOffset / pageSize + 1}`;
}
async function rules() {
  const data = await api("/api/rules");
  $("rule-cards").replaceChildren();
  for (const rule of data) {
    const card = el("article", null, "panel");
    card.append(
      el("code", rule.rule_id),
      el("h3", rule.name),
      badge(rule.severity, true),
      el("p", rule.description),
      el(
        "p",
        `${rule.mode} · threshold ${rule.threshold} · ${rule.window_seconds}s · ${rule.operating_systems.join(" / ")}`,
      ),
      el("p", `Required: ${rule.required_sources.join(", ")}`),
      el("p", `False positives: ${rule.false_positives}`),
      el("p", `Investigate: ${rule.investigation}`),
    );
    $("rule-cards").append(card);
  }
}
async function investigate(id) {
  const data = await api(`/api/alerts/${id}`),
    alert = data.alert;
  state.alert = alert;
  $("dialog-title").textContent = alert.name;
  const content = $("dialog-content");
  content.replaceChildren();
  content.append(
    badge(alert.severity, true),
    el("p", alert.assessment),
    el("p", alert.description),
    el("h3", "Investigation guidance"),
    el("p", alert.investigation),
    el("p", `Possible false positives: ${alert.false_positives}`),
    el("p", `Defensive actions: ${alert.defensive_actions}`),
    el(
      "p",
      `ATT&CK: ${alert.mitre_techniques.join(", ") || "No automatic mapping"}`,
    ),
  );
  const evidence = el("details"),
    summary = el(
      "summary",
      `Supporting evidence · ${data.events.length} events`,
    );
  evidence.append(summary, el("pre", JSON.stringify(data.events, null, 2)));
  content.append(evidence);
  if (Object.keys(alert.context || {}).length)
    content.append(
      el("h3", "Detection context"),
      el("pre", JSON.stringify(alert.context, null, 2)),
    );
  if (alert.history.length)
    content.append(
      el("h3", "Status history"),
      el("pre", JSON.stringify(alert.history, null, 2)),
    );
  const form = el("form"),
    select = el("select");
  select.id = "case-status";
  for (const status of ["new", "investigating", "resolved", "false_positive"]) {
    const option = el("option", status.replaceAll("_", " "));
    option.value = status;
    option.selected = status === alert.status;
    select.append(option);
  }
  const actor = el("input"),
    note = el("textarea");
  actor.id = "case-actor";
  actor.required = true;
  actor.maxLength = 200;
  note.id = "case-note";
  note.required = true;
  note.maxLength = 4000;
  for (const [text, id, control] of [
    ["New status", select.id, select],
    ["Analyst name (self-reported)", actor.id, actor],
    ["Investigation note", note.id, note],
  ]) {
    const label = el("label", text);
    label.htmlFor = id;
    form.append(label, control);
  }
  const submit = el("button", "Save investigation status", "primary"),
    feedback = el("p");
  submit.type = "submit";
  feedback.setAttribute("role", "status");
  form.append(submit, feedback);
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    submit.disabled = true;
    try {
      await api(`/api/alerts/${id}/status`, {
        method: "PATCH",
        body: JSON.stringify({
          status: select.value,
          actor: actor.value,
          note: note.value,
          expected_revision: alert.revision,
        }),
      });
      $("investigation").close();
      await refresh();
      message("Investigation status saved.");
    } catch (error) {
      feedback.textContent = error.message;
    } finally {
      submit.disabled = false;
    }
  });
  content.append(form);
  content.append(incidentForm(alert));
  $("investigation").showModal();
}

function incidentForm(alert) {
  const section = el("section"),
    form = el("form"),
    inputs = {};
  section.append(
    el("h3", "Save an incident snapshot"),
    el(
      "p",
      "Preserve this alert and its evidence with your interpretation. Saved reports can be exported from Incident Reports.",
      "muted",
    ),
  );
  for (const [name, labelText, initial, maxLength] of [
    ["title", "Incident title", alert.name, 200],
    ["summary", "Incident summary", alert.description, 8000],
    ["analyst", "Report analyst", "", 200],
    [
      "analyst_findings",
      "Analyst interpretation",
      "No analyst interpretation recorded.",
      16000,
    ],
  ]) {
    const input = el(
      name === "summary" || name === "analyst_findings" ? "textarea" : "input",
    );
    input.id = `incident-${name}`;
    input.required = true;
    input.maxLength = maxLength;
    input.value = initial;
    const label = el("label", labelText);
    label.htmlFor = input.id;
    inputs[name] = input;
    form.append(label, input);
  }
  const save = el("button", "Save incident snapshot", "primary"),
    feedback = el("p");
  save.type = "submit";
  feedback.setAttribute("role", "status");
  form.append(save, feedback);
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    save.disabled = true;
    try {
      const values = Object.fromEntries(
        Object.entries(inputs).map(([name, input]) => [name, input.value]),
      );
      await api("/api/incidents", {
        method: "POST",
        body: JSON.stringify({ alert_ids: [alert.alert_id], ...values }),
      });
      $("investigation").close();
      state.view = "reports";
      document
        .querySelectorAll("nav button")
        .forEach((button) =>
          button.classList.toggle("active", button.dataset.view === "reports"),
        );
      await refresh();
      message("Incident snapshot saved.");
    } catch (error) {
      feedback.textContent = error.message;
    } finally {
      save.disabled = false;
    }
  });
  section.append(form);
  return section;
}

async function downloadReport(id, format) {
  const response = await fetch(`/api/incidents/${id}/export?format=${format}`, {
    headers: { Authorization: `Bearer ${state.token}` },
  });
  if (!response.ok) throw new Error(`Export failed (${response.status}).`);
  const url = URL.createObjectURL(await response.blob()),
    link = el("a");
  link.href = url;
  link.download = `scry-${id}.${format}`;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
}

async function reports() {
  const records = await api(`/api/incidents?${modeParams()}`),
    container = $("other-view");
  container.replaceChildren(
    el("h2", "Saved incident snapshots"),
    el(
      "p",
      "Create a report from an alert investigation. Each saved snapshot preserves its original evidence and analyst interpretation.",
      "muted",
    ),
  );
  if (!records.length)
    container.append(
      el("p", "No incident reports in this evidence selection.", "empty"),
    );
  for (const record of records) {
    const card = el("article", null, "panel"),
      controls = el("div", null, "controls");
    card.append(
      el("h3", record.title),
      el(
        "p",
        `${date(record.created_at)} · ${record.affected_hosts.join(", ")} · ${record.status}`,
      ),
      badge(record.synthetic ? "synthetic lab" : "real evidence"),
    );
    const inspect = el("button", "Read snapshot");
    inspect.addEventListener("click", async () => {
      try {
        const report = await api(`/api/incidents/${record.incident_id}`);
        $("dialog-title").textContent = report.title;
        $("dialog-content").replaceChildren(
          el("h3", "Observed evidence"),
          ...report.observed_evidence.map((text) => el("p", text)),
          el("h3", "Analyst interpretation"),
          el("p", report.analyst_findings),
          el("h3", "Complete snapshot"),
          el("pre", JSON.stringify(report, null, 2)),
        );
        $("investigation").showModal();
      } catch (error) {
        message(error.message);
      }
    });
    controls.append(inspect);
    for (const format of ["json", "csv", "html"]) {
      const button = el("button", `Export ${format.toUpperCase()}`);
      button.addEventListener("click", () =>
        downloadReport(record.incident_id, format).catch((error) =>
          message(error.message),
        ),
      );
      controls.append(button);
    }
    card.append(controls);
    container.append(card);
  }
}

async function integrity() {
  const records = await api(`/api/integrity?${modeParams()}`),
    container = $("other-view");
  container.replaceChildren(
    el("h2", "Approved file baselines"),
    el(
      "p",
      "Create baselines and run comparisons with the CLI. The dashboard reads saved results and never grants itself filesystem monitoring access.",
      "muted",
    ),
  );
  if (!records.length)
    container.append(
      el(
        "p",
        "No file baselines in this evidence selection. See the file-integrity setup guide.",
        "empty",
      ),
    );
  for (const record of records) {
    const card = el("article", null, "panel");
    card.append(
      el("h3", record.hostname),
      el(
        "p",
        `Approved by ${record.approved_by} · ${date(record.created_at)} · ${record.file_count} baseline files`,
      ),
      el("p", record.approval_note),
      el("pre", Object.keys(record.roots).join("\n")),
    );
    if (record.latest_scan) {
      const scan = record.latest_scan;
      card.append(
        el(
          "p",
          `${date(scan.timestamp)} · ${scan.files_checked} files checked · ${scan.events.length} changes`,
        ),
      );
      if (scan.errors.length)
        card.append(el("p", scan.errors.join(" "), "notice"));
      if (scan.events.length) {
        const detail = el("details");
        detail.append(
          el("summary", "Change evidence"),
          el("pre", JSON.stringify(scan.events, null, 2)),
        );
        card.append(detail);
      }
    } else card.append(el("p", "No comparison has been recorded.", "muted"));
    container.append(card);
  }
}

async function settings() {
  const [records, policy] = await Promise.all([
      api("/api/sources"),
      api("/api/policy"),
    ]),
    container = $("other-view");
  container.replaceChildren(
    el("h2", "Collector health"),
    el(
      "p",
      "The web process does not collect logs. Run the explicit monitoring CLI separately; this view shows its last committed source checks.",
      "muted",
    ),
  );
  const policyCard = el("article", null, "panel");
  policyCard.append(
    el("h3", "Detection policy"),
    el(
      "p",
      `${policy.policy_id} · ${policy.hosts.length} explicitly configured host scopes`,
    ),
    el(
      "p",
      "Host-policy detections stay inactive on unconfigured hosts. Configure expected behaviour with --policy; saved alerts retain the policy hash and review reasons.",
      "muted",
    ),
  );
  container.append(policyCard);
  if (!records.length)
    container.append(
      el(
        "p",
        "No collector checks recorded. Configure sources before starting --monitor or --collect-once.",
        "empty",
      ),
    );
  for (const record of records) {
    const card = el("article", null, "panel");
    card.append(
      el("h3", record.source_id),
      badge(record.stale ? "stale" : record.status),
      el("p", record.message),
      el(
        "p",
        `Last checked ${date(record.last_checked)} · ${record.events} parsed events · ${record.errors} errors · ${record.skipped} skipped`,
      ),
    );
    if (record.stale)
      card.append(
        el(
          "p",
          "The last source check is stale. Verify that the collector process is still running.",
          "notice",
        ),
      );
    container.append(card);
  }
}
const titles = {
  overview: "Security overview",
  events: "Security events",
  detection: "Threat detection",
  alerts: "Alert investigations",
  authentication: "Authentication monitoring",
  windows: "Windows monitoring",
  linux: "Linux monitoring",
  network: "Network analysis",
  files: "File integrity",
  reports: "Incident reports",
  rules: "Detection rules",
  settings: "Workspace settings",
};
async function refresh() {
  message();
  const view = state.view;
  $("view-title").textContent = titles[view];
  $("data-notice").textContent =
    $("data-mode").value === "true"
      ? "Synthetic lab evidence. Findings describe scenarios, not real incidents."
      : $("data-mode").value === "false"
        ? "Real evidence only. Source permissions and auditing determine visibility."
        : "Mixed evidence: synthetic and real records are included. Inspect each record's synthetic label.";
  for (const id of ["overview", "alerts", "events", "rules", "other"])
    $(`${id}-view`).hidden = true;
  if (view === "overview") {
    $("overview-view").hidden = false;
    $("alerts-view").hidden = false;
    await Promise.all([overview(), alerts()]);
  } else if (view === "alerts") {
    $("alerts-view").hidden = false;
    await alerts();
  } else if (
    ["events", "authentication", "windows", "linux", "network"].includes(view)
  ) {
    $("events-view").hidden = false;
    await events();
  } else if (["rules", "detection"].includes(view)) {
    $("rules-view").hidden = false;
    await rules();
  } else if (view === "reports") {
    $("other-view").hidden = false;
    await reports();
  } else if (view === "files") {
    $("other-view").hidden = false;
    await integrity();
  } else if (view === "settings") {
    $("other-view").hidden = false;
    await settings();
  } else {
    $("other-view").hidden = false;
    const text =
      "Local bearer-token access. The token stays in page memory. No collector runs in the web process. Choose synthetic or real evidence above; configure collectors and rules using the documented command-line workflow.";
    $("other-view").replaceChildren(
      el("h2", titles[view]),
      el("p", text, "muted"),
    );
  }
}
$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  state.token = $("token").value;
  try {
    await api("/api/summary");
    $("token").value = "";
    $("login").hidden = true;
    $("workspace").hidden = false;
    $("connection-state").textContent = "Authenticated · local";
    await refresh();
  } catch (error) {
    message(error.message);
  }
});
$("navigation").addEventListener("click", (e) => {
  if (!e.target.dataset.view) return;
  state.view = e.target.dataset.view;
  state.eventsOffset = state.alertsOffset = 0;
  document
    .querySelectorAll("nav button")
    .forEach((b) => b.classList.toggle("active", b === e.target));
  if (state.token) refresh().catch((error) => message(error.message));
});
$("refresh").addEventListener("click", () =>
  refresh().catch((e) => message(e.message)),
);
$("lock").addEventListener("click", lock);
$("close-dialog").addEventListener("click", () => $("investigation").close());
for (const id of ["data-mode", "severity-filter", "status-filter"])
  $(id).addEventListener("change", () => {
    state.eventsOffset = state.alertsOffset = 0;
    refresh().catch((e) => message(e.message));
  });
for (const type of ["events", "alerts"])
  for (const direction of ["prev", "next"])
    $(`${type}-${direction}`).addEventListener("click", () => {
      state[`${type}Offset`] += direction === "next" ? pageSize : -pageSize;
      refresh().catch((e) => message(e.message));
    });

$("apply-filters").addEventListener("click", () => {
  state.eventsOffset = state.alertsOffset = 0;
  refresh().catch((e) => message(e.message));
});
