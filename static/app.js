const form = document.querySelector("#analysis-form");
const fileInput = document.querySelector("#file");
const fileLabel = document.querySelector("#file-label");
const dropZone = document.querySelector("#drop-zone");
const progress = document.querySelector("#progress");
const report = document.querySelector("#report");
const errorBox = document.querySelector("#error");
const submit = document.querySelector("#submit");
const vtStatus = document.querySelector("#vt-status");
const progressTitle = document.querySelector("#progress-title");
const progressDetail = document.querySelector("#progress-detail");
const progressBar = document.querySelector("#progress-bar");
const progressSpinner = document.querySelector("#progress-spinner");
const terminalOutput = document.querySelector("#terminal-output");
const elapsedTime = document.querySelector("#elapsed-time");
const autoScroll = document.querySelector("#auto-scroll");
const copyLog = document.querySelector("#copy-log");
const dynamicEnabled = document.querySelector("#dynamic-enabled");
const dynamicStatus = document.querySelector("#dynamic-status");
const stageList = document.querySelector("#stage-list");
const stageSummaryTitle = document.querySelector("#stage-summary-title");
const stageSummaryDetail = document.querySelector("#stage-summary-detail");
let pollTimer = null;
let elapsedTimer = null;
let analysisStartedAt = 0;
let currentReport = null;
let environmentState = null;
let assessmentStages = [];

const STAGE_DEFINITIONS = [
  {id: "upload", title: "文件上传", detail: "接收待评估安装包"},
  {id: "fingerprint", title: "文件识别", detail: "计算哈希、大小和文件类型"},
  {id: "reputation", title: "来源与产品信誉", detail: "核对官网和公开维护信号"},
  {id: "package", title: "安装包解析", detail: "展开 ZIP、PKG 或只读挂载 DMG"},
  {id: "static", title: "静态安全与数据检查", detail: "检查签名、权限、脚本、组件和数据能力"},
  {id: "local_av", title: "本地恶意内容扫描", detail: "使用可用的本地杀毒引擎"},
  {id: "virustotal", title: "VirusTotal 信誉", detail: "只按 SHA-256 查询已有报告"},
  {id: "dynamic", title: "Tart 隔离动态观察", detail: "在一次性 macOS VM 中限时运行"},
  {id: "report", title: "生成评估报告", detail: "汇总结论、风险和证据"}
];

refreshEnvironment();
resetAssessmentStages(true);

document.querySelectorAll(".page-tab").forEach(tab => tab.addEventListener("click", () => {
  document.querySelectorAll(".page-tab").forEach(item => item.classList.remove("active"));
  tab.classList.add("active");
  const page = tab.dataset.page;
  document.querySelector("#assessment-page").classList.toggle("hidden", page !== "assessment");
  document.querySelector("#quickstart-page").classList.toggle("hidden", page !== "quickstart");
  document.querySelector("#capabilities-page").classList.toggle("hidden", page !== "capabilities");
  document.querySelector("#environment-page").classList.toggle("hidden", page !== "environment");
  if (page === "capabilities") loadCapabilities();
  if (page === "environment") renderEnvironment();
}));

async function refreshEnvironment() {
  try {
    const response = await fetch("/api/environment", {cache: "no-store"});
    environmentState = await response.json();
    if (!response.ok) throw new Error(environmentState.error || "环境检查失败");
    renderAssessmentEnvironmentNotice();
    renderEnvironment();
  } catch (error) {
    vtStatus.textContent = "无法读取环境状态。";
    const notice = document.querySelector("#environment-notice");
    notice.classList.add("warning");
    notice.innerHTML = `<strong>环境检查失败</strong><p>${escapeHtml(error.message)}</p>`;
  }
}

function renderAssessmentEnvironmentNotice() {
  if (!environmentState) return;
  const missing = environmentState.missingEffects || [];
  const core = environmentState.groups.find(group => group.id === "core");
  const missingCore = (core?.items || []).filter(item => !item.available);
  vtStatus.textContent = environmentState.virusTotalConfigured
    ? "VirusTotal 已配置：仅查询文件哈希，不会上传文件。"
    : "VirusTotal 未配置：将跳过多引擎哈希信誉查询。";
  const tartReady = Boolean(environmentState.tart?.ready);
  dynamicEnabled.disabled = !tartReady;
  dynamicEnabled.checked = tartReady;
  dynamicStatus.textContent = tartReady
    ? `已就绪：将从 ${environmentState.tart.baseVm} 创建一次性 VM，使用主机隔离网络。`
    : `不可用：需要 Tart CLI 和基础 VM ${environmentState.tart?.baseVm || "tahoe-base"}。`;
  const notice = document.querySelector("#environment-notice");
  notice.classList.toggle("warning", missing.length > 0);
  if (!missing.length) {
    notice.innerHTML = `<strong>分析环境完整</strong><p>当前检查到的核心、增强和观察工具均可用。</p>`;
    return;
  }
  const headline = missingCore.length
    ? `缺少 ${missingCore.length} 个核心工具，部分基础检查无法执行`
    : `有 ${missing.length} 项可选能力未配置`;
  notice.innerHTML = `
    <strong>${escapeHtml(headline)}</strong>
    <ul>${missing.slice(0, 4).map(item => `<li>${escapeHtml(item.effect)}</li>`).join("")}</ul>
    ${missing.length > 4 ? `<p>另有 ${missing.length - 4} 项，请在“环境与配置”中查看。</p>` : ""}
  `;
}

function renderEnvironment() {
  if (!environmentState) return;
  const configured = environmentState.virusTotalConfigured;
  const badge = document.querySelector("#config-vt-badge");
  badge.textContent = configured ? "已配置" : "未配置";
  badge.className = `health-status ${configured ? "ok" : "missing"}`;
  document.querySelector("#config-vt-state").textContent = configured
    ? "已启用 SHA-256 多引擎报告查询，不会上传文件。"
    : "未启用 VirusTotal 查询，不影响其他本地分析。";
  document.querySelector("#environment-tools").innerHTML = environmentState.groups.map(group => `
    <section class="settings-panel tool-group card">
      <div class="panel-heading">
        <div>
          <h3>${escapeHtml(group.title)}</h3>
          <p>${group.items.filter(item => item.available).length} 项可用，${group.items.filter(item => !item.available).length} 项缺失</p>
        </div>
        <span class="panel-count">${group.items.filter(item => item.available).length}/${group.items.length}</span>
      </div>
      ${group.items.map(item => `
        <article class="tool-row">
          <div class="tool-identity">
            <strong>${escapeHtml(item.id)}</strong>
            ${item.path ? `<code>${escapeHtml(item.path)}</code>` : ""}
          </div>
          <p class="tool-effect">${escapeHtml(item.effect)}</p>
          <span class="health-status ${item.available ? "ok" : "missing"}">${item.available ? "可用" : "缺失"}</span>
        </article>
      `).join("")}
    </section>
  `).join("");
}

document.querySelector("#vt-config-form").addEventListener("submit", async event => {
  event.preventDefault();
  const input = document.querySelector("#vt-api-key");
  const apiKey = input.value.trim();
  if (!apiKey) {
    showConfigMessage("请输入新的 API Key。", true);
    return;
  }
  await updateVirusTotalConfig({virusTotalApiKey: apiKey});
  input.value = "";
});

document.querySelector("#clear-vt-key").addEventListener("click", async () => {
  if (!window.confirm("确定清除本机保存的 VirusTotal API Key？")) return;
  await updateVirusTotalConfig({clearVirusTotal: true});
  document.querySelector("#vt-api-key").value = "";
});

async function updateVirusTotalConfig(payload) {
  try {
    const response = await fetch("/api/config", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify(payload)
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "保存失败");
    showConfigMessage(result.message, false);
    await refreshEnvironment();
  } catch (error) {
    showConfigMessage(error.message, true);
  }
}

function showConfigMessage(message, failed) {
  const element = document.querySelector("#config-message");
  element.textContent = message;
  element.classList.toggle("failed", failed);
}

fileInput.addEventListener("change", () => {
  if (fileInput.files[0]) fileLabel.textContent = fileInput.files[0].name;
});
["dragenter", "dragover"].forEach(event => dropZone.addEventListener(event, e => {
  e.preventDefault(); dropZone.classList.add("drag");
}));
["dragleave", "drop"].forEach(event => dropZone.addEventListener(event, e => {
  e.preventDefault(); dropZone.classList.remove("drag");
}));
dropZone.addEventListener("drop", e => {
  if (e.dataTransfer.files.length) {
    fileInput.files = e.dataTransfer.files;
    fileLabel.textContent = e.dataTransfer.files[0].name;
  }
});

form.addEventListener("submit", async event => {
  event.preventDefault();
  errorBox.classList.add("hidden");
  report.classList.add("hidden");
  progress.classList.remove("hidden");
  submit.disabled = true;
  terminalOutput.replaceChildren();
  progressSpinner.classList.remove("done", "failed");
  progressBar.classList.remove("indeterminate");
  progressBar.style.width = "0%";
  progressTitle.textContent = "正在上传文件";
  progressDetail.textContent = "浏览器正在把安装包发送到本地分析服务。";
  resetAssessmentStages(dynamicEnabled.checked);
  analysisStartedAt = Date.now();
  startElapsedTimer();
  appendLog({time: new Date().toISOString(), level: "info", kind: "system", message: "准备提交分析任务…"});
  const data = new FormData();
  if (fileInput.files[0]) {
    data.append("file", fileInput.files[0]);
  }
  data.append("homepage", document.querySelector("#homepage").value);
  data.append("dynamic", dynamicEnabled.checked ? "true" : "false");
  try {
    const payload = await createJob(data);
    setStageState("upload", "completed");
    setStageState("fingerprint", "active");
    progressTitle.textContent = "正在评估";
    progressDetail.textContent = "任务已建立，等待新的分析事件。";
    progressBar.style.width = "100%";
    progressBar.classList.add("indeterminate");
    await pollJob(payload.jobId);
  } catch (error) {
    failActiveAssessmentStage();
    finishProgress("failed", "分析失败", error.message);
    errorBox.textContent = error.message;
    errorBox.classList.remove("hidden");
  } finally {
    submit.disabled = false;
  }
});

let capabilitiesLoaded = false;
async function loadCapabilities() {
  if (capabilitiesLoaded) return;
  const container = document.querySelector("#capability-list");
  container.innerHTML = `<p class="capability-loading">正在读取当前评估能力…</p>`;
  try {
    const response = await fetch("/api/capabilities", {cache: "no-store"});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "读取失败");
    container.innerHTML = payload.groups.map(group => `
      <section class="capability-group card">
        <div class="capability-heading">
          <h3>${escapeHtml(group.title)}</h3>
          <span>${group.items.length} 项</span>
        </div>
        ${group.items.map(item => `
          <article class="capability-item">
            <h4>${escapeHtml(item.title)}</h4>
            <dl>
              <dt>如何评估</dt>
              <dd>${escapeHtml(item.method)}</dd>
              <dt>处理方式</dt>
              <dd>${escapeHtml(item.action)}</dd>
            </dl>
          </article>
        `).join("")}
      </section>
    `).join("");
    capabilitiesLoaded = true;
  } catch (error) {
    container.innerHTML = `<p class="error">评估能力说明加载失败：${escapeHtml(error.message)}</p>`;
  }
}

function createJob(data) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", "/api/analyze");
    xhr.upload.addEventListener("progress", event => {
      if (!event.lengthComputable) {
        progressBar.classList.add("indeterminate");
        return;
      }
      const percent = Math.round(event.loaded / event.total * 100);
      progressBar.classList.remove("indeterminate");
      progressBar.style.width = `${percent}%`;
      progressDetail.textContent = `${formatBytes(event.loaded)} / ${formatBytes(event.total)} · ${percent}%`;
    });
    xhr.addEventListener("load", () => {
      let payload = {};
      try { payload = JSON.parse(xhr.responseText); } catch {}
      if (xhr.status >= 200 && xhr.status < 300) resolve(payload);
      else reject(new Error(payload.error || `提交失败（HTTP ${xhr.status}）`));
    });
    xhr.addEventListener("error", () => reject(new Error("无法连接本地分析服务。")));
    xhr.send(data);
  });
}

async function pollJob(jobId) {
  let next = 0;
  while (true) {
    const response = await fetch(`/api/jobs/${encodeURIComponent(jobId)}?since=${next}`, {cache: "no-store"});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || "无法读取任务进度");
    payload.events.forEach(appendLog);
    payload.events.forEach(updateStageFromEvent);
    next = payload.next;
    progressDetail.textContent = statusDescription(payload.status, payload.events);
    if (payload.status === "completed") {
      completeAssessmentStages();
      finishProgress("done", "评估完成", "报告已生成，控制台日志会保留在页面中。");
      renderReport(payload.report);
      return;
    }
    if (payload.status === "failed") {
      throw new Error(payload.error || "分析任务失败");
    }
    await new Promise(resolve => { pollTimer = setTimeout(resolve, 500); });
  }
}

function appendLog(event) {
  const line = document.createElement("div");
  line.className = `log-line ${event.level || "info"} ${event.kind || "step"}`;
  const stamp = document.createElement("span");
  stamp.className = "log-time";
  stamp.textContent = formatLogTime(event.time);
  const content = document.createElement("span");
  content.className = "log-message";
  content.textContent = event.message;
  line.append(stamp, content);
  terminalOutput.append(line);
  if (autoScroll.checked) terminalOutput.scrollTop = terminalOutput.scrollHeight;
}

function formatLogTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? "--:--:--" : date.toLocaleTimeString("zh-CN", {hour12: false});
}

function statusDescription(status, events) {
  if (events.length) return `最近活动：${events[events.length - 1].message.split("\n")[0]}`;
  return status === "queued" ? "等待分析线程…" : "分析仍在运行，等待下一条输出…";
}

function resetAssessmentStages(includeDynamic) {
  assessmentStages = STAGE_DEFINITIONS
    .filter(stage => includeDynamic || stage.id !== "dynamic")
    .map((stage, index) => ({
      ...stage,
      state: index === 0 ? "active" : "pending"
    }));
  renderAssessmentStages();
}

function setStageState(id, state) {
  const target = assessmentStages.find(stage => stage.id === id);
  if (!target || target.state === state) return;
  if (state === "active") {
    const targetIndex = assessmentStages.findIndex(stage => stage.id === id);
    assessmentStages.forEach((stage, index) => {
      if (index < targetIndex && stage.state !== "completed") stage.state = "completed";
      if (stage.state === "active") stage.state = "completed";
    });
  }
  target.state = state;
  renderAssessmentStages();
}

function updateStageFromEvent(event) {
  const message = String(event.message || "");
  if (message.startsWith("计算 SHA-256")) setStageState("fingerprint", "active");
  else if (message.startsWith("检查下载来源")) setStageState("reputation", "active");
  else if (message.startsWith("识别安装包类型")) setStageState("package", "active");
  else if (message.startsWith("分析应用结构")) setStageState("static", "active");
  else if (message.startsWith("运行本地恶意软件检查")) setStageState("local_av", "active");
  else if (message.startsWith("查询 VirusTotal")) setStageState("virustotal", "active");
  else if (message.startsWith("启动 Tart")) setStageState("dynamic", "active");
  else if (message.startsWith("清理挂载点") || event.kind === "complete") setStageState("report", "active");
}

function completeAssessmentStages() {
  assessmentStages.forEach(stage => { stage.state = "completed"; });
  renderAssessmentStages();
}

function failActiveAssessmentStage() {
  const active = assessmentStages.find(stage => stage.state === "active");
  if (active) active.state = "failed";
  renderAssessmentStages();
}

function renderAssessmentStages() {
  const completed = assessmentStages.filter(stage => stage.state === "completed").length;
  const active = assessmentStages.filter(stage => stage.state === "active").length;
  const failed = assessmentStages.filter(stage => stage.state === "failed").length;
  const pending = assessmentStages.length - completed - active - failed;
  stageSummaryTitle.textContent = `${completed}/${assessmentStages.length} 项已完成`;
  stageSummaryDetail.textContent = [
    `${active} 项评估中`,
    `${pending} 项待进行`,
    failed ? `${failed} 项失败` : ""
  ].filter(Boolean).join(" · ");
  stageList.innerHTML = assessmentStages.map((stage, index) => `
    <li class="stage-item ${stage.state}">
      <span class="stage-marker">${stage.state === "completed" ? "✓" : stage.state === "failed" ? "!" : index + 1}</span>
      <span class="stage-copy">
        <strong>${escapeHtml(stage.title)}</strong>
        <small>${escapeHtml(stage.detail)}</small>
      </span>
      <span class="stage-state">${stageStateName(stage.state)}</span>
    </li>
  `).join("");
}

function stageStateName(state) {
  return {completed: "已完成", active: "评估中", pending: "待进行", failed: "失败"}[state] || "待进行";
}

function startElapsedTimer() {
  clearInterval(elapsedTimer);
  const render = () => {
    const seconds = Math.floor((Date.now() - analysisStartedAt) / 1000);
    elapsedTime.textContent = `${String(Math.floor(seconds / 60)).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
  };
  render();
  elapsedTimer = setInterval(render, 1000);
}

function finishProgress(state, title, detail) {
  clearInterval(elapsedTimer);
  clearTimeout(pollTimer);
  progressBar.classList.remove("indeterminate");
  progressBar.style.width = "100%";
  progressSpinner.classList.add(state);
  progressTitle.textContent = title;
  progressDetail.textContent = detail;
}

copyLog.addEventListener("click", async () => {
  const text = [...terminalOutput.querySelectorAll(".log-line")]
    .map(line => line.textContent).join("\n");
  await navigator.clipboard.writeText(text);
  const previous = copyLog.textContent;
  copyLog.textContent = "已复制";
  setTimeout(() => { copyLog.textContent = previous; }, 1200);
});

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, char => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;"
  })[char]);
}

function formatBytes(bytes) {
  const units = ["B", "KB", "MB", "GB"];
  let value = Number(bytes || 0), index = 0;
  while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
  return `${value.toFixed(index ? 1 : 0)} ${units[index]}`;
}

function renderReport(data) {
  currentReport = data;
  const summary = data.summary;
  const color = summary.riskLevel === "低" ? "#167548"
    : summary.riskLevel === "中" ? "#d49a22" : "#c73f32";
  const riskFindings = data.findings.filter(item => item.severity !== "info");
  const riskCounts = ["critical", "high", "medium", "low"].map(severity => ({
    severity,
    count: riskFindings.filter(item => item.severity === severity).length
  }));
  const basicInfo = buildBasicInfo(data);
  const riskOverview = riskFindings.length ? riskFindings.map(item => `
    <li class="risk-item">
      <span class="severity-mark ${escapeHtml(item.severity)}">${severityName(item.severity)}</span>
      <div>
        <strong>${escapeHtml(item.title)}</strong>
        <p>${escapeHtml(item.description)}</p>
        <small>${escapeHtml(item.category)}${item.points > 0 ? ` · +${item.points} 分` : ""}</small>
      </div>
    </li>
  `).join("") : `<li class="empty-state">本次没有产生低级别以上的风险发现。</li>`;
  const assessment = data.assessment.map(group => `
    <section class="assessment-group card">
      <div class="assessment-heading">
        <h3>${escapeHtml(group.title)}</h3>
        <span>${group.items.filter(item => item.status !== "not_run").length}/${group.items.length} 已评估</span>
      </div>
      ${group.items.map(item => `
        <article class="control-row">
          <span class="control-status ${escapeHtml(item.status)}">${controlStatus(item.status)}</span>
          <div>
            <strong>${escapeHtml(item.title)}</strong>
            <p>${escapeHtml(item.summary)}</p>
            ${item.action && (item.status !== "pass" || item.id === "components") ? `
              <div class="control-action">
                <b>${item.requiresHumanReview ? "人工复核方法" : "处理建议"}</b>
                <span>${escapeHtml(item.action)}</span>
              </div>
            ` : ""}
            ${renderControlEvidence(item)}
          </div>
        </article>
      `).join("")}
    </section>
  `).join("");

  report.innerHTML = `
    <section class="summary card" style="--score-color:${color}">
      <div class="score" style="--score-color:${color}">
        <div class="score-number">${summary.score}<small>/ 100</small></div>
        <span>风险评分</span>
      </div>
      <div>
        <div class="summary-head">
          <div>
            <div class="summary-kicker">软件准入评估结论</div>
            <h2><span style="color:${color}">${escapeHtml(summary.riskLevel)}风险</span></h2>
          </div>
          <div class="export-actions">
            <button type="button" id="export-markdown">导出 Markdown</button>
            <button type="button" id="export-html">导出 HTML</button>
          </div>
        </div>
        <p>${escapeHtml(summary.recommendation)}</p>
        <div class="meta">
          <span class="pill">置信度 ${escapeHtml(summary.confidence)}</span>
          <span class="pill">覆盖 ${escapeHtml(data.coverage.assessed)}/${escapeHtml(data.coverage.total)} 项</span>
        </div>
      </div>
    </section>
    <h2 class="section-title">文件基础信息</h2>
    <section class="card basic-info">
      ${basicInfo.map(item => `
        <div class="info-row">
          <dt>${escapeHtml(item.label)}</dt>
          <dd class="${item.mono ? "mono" : ""}">${escapeHtml(item.value)}</dd>
        </div>
      `).join("")}
    </section>
    <h2 class="section-title">风险摘要</h2>
    <section class="card risk-overview">
      <div class="risk-counts">
        ${riskCounts.map(item => `
          <div>
            <strong class="${escapeHtml(item.severity)}">${item.count}</strong>
            <span>${severityName(item.severity)}风险项</span>
          </div>
        `).join("")}
      </div>
      <ul class="risk-list">${riskOverview}</ul>
    </section>
    <div class="section-heading">
      <div>
        <h2 class="section-title">详细评估报告</h2>
        <p>按评估维度逐项列出结论。未执行和证据不足不会显示成“通过”。</p>
      </div>
    </div>
    <div class="assessment-report">${assessment}</div>
    <h2 class="section-title">分析边界</h2>
    <section class="card limitations"><div style="padding:18px 24px">
      ${data.limitations.map(item => `<p>• ${escapeHtml(item)}</p>`).join("")}
      <p>已运行：${escapeHtml(data.coverage.run.join("、") || "无")}</p>
      <p>未运行：${escapeHtml(data.coverage.notRun.join("、") || "无")}</p>
    </div></section>
  `;
  document.querySelector("#export-markdown").addEventListener("click", () => {
    downloadReport("md", buildMarkdownReport(currentReport));
  });
  document.querySelector("#export-html").addEventListener("click", () => {
    downloadReport("html", buildHtmlReport(currentReport));
  });
  report.classList.remove("hidden");
  report.scrollIntoView({ behavior: "smooth", block: "start" });
}

function buildBasicInfo(data) {
  const metadata = data.metadata || {};
  const source = data.source || {};
  const values = [
    ["文件名", metadata.filename || source.name || "未知"],
    ["文件类型", String(metadata.inputType || "未知").toUpperCase()],
    ["文件大小", formatBytes(metadata.size)],
    ["SHA-256", metadata.sha256 || "未生成", true],
    ["分析时间", formatDateTime(metadata.analyzedAt)],
    ["包含的应用", joinValues(metadata.applications)],
    ["Bundle ID", joinValues(metadata.bundleIds), true],
    ["开发者 Team ID", joinValues(metadata.teamIds), true],
    ["产品主页", source.homepage || "未提供"],
    ["下载来源", source.finalUrl || source.originalUrl || (source.type === "file" ? "本地上传文件" : "未记录")]
  ];
  return values.map(([label, value, mono = false]) => ({label, value, mono}));
}

function joinValues(value) {
  return Array.isArray(value) && value.length ? value.join("、") : "未提取到";
}

function formatDateTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? "未知"
    : date.toLocaleString("zh-CN", {hour12: false});
}

function reportFilename(data, extension) {
  const raw = String(data?.metadata?.filename || "canuinstall-report");
  const safe = raw.replace(/[\\/:*?"<>|]+/g, "-");
  return `${safe}-评估报告.${extension}`;
}

function downloadReport(extension, content) {
  const blob = new Blob([content], {
    type: extension === "html" ? "text/html;charset=utf-8" : "text/markdown;charset=utf-8"
  });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = reportFilename(currentReport, extension);
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

function buildMarkdownReport(data) {
  const basic = buildBasicInfo(data);
  const risks = data.findings.filter(item => item.severity !== "info");
  const lines = [
    `# ${data.metadata.filename || "软件"} 软件准入评估报告`,
    "",
    "## 评估结论",
    "",
    `- 风险评分：${data.summary.score}/100`,
    `- 风险等级：${data.summary.riskLevel}`,
    `- 建议：${data.summary.recommendation}`,
    `- 置信度：${data.summary.confidence}`,
    `- 评估覆盖：${data.coverage.assessed}/${data.coverage.total}`,
    "",
    "## 文件基础信息",
    "",
    ...basic.map(item => `- ${item.label}：${item.value}`),
    "",
    "## 风险摘要",
    ""
  ];
  if (risks.length) {
    risks.forEach(item => lines.push(
      `### ${severityName(item.severity)} · ${item.title}`,
      "",
      item.description,
      "",
      `- 分类：${item.category}`,
      `- 风险分：${item.points}`,
      ""
    ));
  } else {
    lines.push("本次没有产生低级别以上的风险发现。", "");
  }
  lines.push("## 详细评估报告", "");
  data.assessment.forEach(group => {
    lines.push(`### ${group.title}`, "");
    group.items.forEach(item => {
      lines.push(
        `#### ${controlStatus(item.status)} · ${item.title}`,
        "",
        item.summary,
        ""
      );
      if (item.action) lines.push(`处理建议：${item.action}`, "");
      if (item.evidence) lines.push("```text", item.evidence, "```", "");
      (item.relatedFindings || []).forEach(finding => {
        lines.push(`- ${severityName(finding.severity)} · ${finding.title}：${finding.description}`);
        if (finding.evidence) lines.push("", "```text", finding.evidence, "```");
      });
      if ((item.relatedFindings || []).length) lines.push("");
    });
  });
  lines.push(
    "## 分析边界",
    "",
    ...data.limitations.map(item => `- ${item}`),
    "",
    `- 已运行：${data.coverage.run.join("、") || "无"}`,
    `- 未运行：${data.coverage.notRun.join("、") || "无"}`,
    ""
  );
  return lines.join("\n");
}

function buildHtmlReport(data) {
  const title = `${data.metadata.filename || "软件"}准入评估报告`;
  const markdown = buildMarkdownReport(data);
  const body = markdownToReportHtml(markdown);
  return `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>${escapeHtml(title)}</title>
<style>
body{max-width:900px;margin:40px auto;padding:0 24px;color:#17201b;font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
h1{font-size:30px;border-bottom:2px solid #167548;padding-bottom:14px}h2{font-size:21px;margin-top:32px;border-bottom:1px solid #ddd;padding-bottom:7px}
h3{font-size:17px;margin-top:24px}h4{font-size:15px;margin:20px 0 6px}pre{white-space:pre-wrap;word-break:break-word;background:#f5f6f3;border:1px solid #ddd;padding:12px}
li{margin:5px 0}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}@media print{body{margin:0;max-width:none}}
</style></head><body>${body}</body></html>`;
}

function markdownToReportHtml(markdown) {
  const lines = markdown.split("\n");
  let inCode = false;
  let listOpen = false;
  const html = [];
  const closeList = () => {
    if (listOpen) {
      html.push("</ul>");
      listOpen = false;
    }
  };
  for (const line of lines) {
    if (line === "```text") {
      closeList();
      inCode = true;
      html.push("<pre>");
      continue;
    }
    if (line === "```") {
      inCode = false;
      html.push("</pre>");
      continue;
    }
    if (inCode) {
      html.push(`${escapeHtml(line)}\n`);
      continue;
    }
    const heading = line.match(/^(#{1,4}) (.+)$/);
    if (heading) {
      closeList();
      const level = heading[1].length;
      html.push(`<h${level}>${escapeHtml(heading[2])}</h${level}>`);
    } else if (line.startsWith("- ")) {
      if (!listOpen) {
        html.push("<ul>");
        listOpen = true;
      }
      html.push(`<li>${escapeHtml(line.slice(2))}</li>`);
    } else if (line.trim()) {
      closeList();
      html.push(`<p>${escapeHtml(line)}</p>`);
    }
  }
  closeList();
  return html.join("\n");
}

function severityName(value) {
  return ({ info: "通过", low: "低", medium: "中", high: "高", critical: "阻断" })[value] || value;
}

function controlStatus(value) {
  return ({
    pass: "通过",
    observe: "提示",
    review: "复核",
    risk: "风险",
    unknown: "证据不足",
    not_run: "未执行"
  })[value] || value;
}

function renderControlEvidence(item) {
  const findings = item.relatedFindings || [];
  if (!item.evidence && !findings.length) return "";
  const findingHtml = findings.map(finding => `
    <div class="control-finding">
      <div class="control-finding-head">
        <span class="mini-severity ${escapeHtml(finding.severity)}">${severityName(finding.severity)}</span>
        <strong>${escapeHtml(finding.title)}</strong>
        <small>${finding.points > 0 ? `+${finding.points} 分` : "信息"}</small>
      </div>
      <p>${escapeHtml(finding.description)}</p>
      ${finding.evidence ? `<pre>${escapeHtml(finding.evidence)}</pre>` : ""}
    </div>
  `).join("");
  return `
    <details class="control-evidence" ${item.status === "risk" ? "open" : ""}>
      <summary>查看依据${findings.length ? `（${findings.length} 条发现）` : ""}</summary>
      ${item.evidence ? `<div class="control-raw"><strong>评估依据</strong><pre>${escapeHtml(item.evidence)}</pre></div>` : ""}
      ${findingHtml}
    </details>
  `;
}
