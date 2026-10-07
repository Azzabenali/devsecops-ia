
/* =========================================================
   DEVSECOPS AI DASHBOARD
   FastAPI + XGBoost
   ========================================================= */

const API_URL = "http://127.0.0.1:8000";

let allVulnerabilities = [];
let allScans = [];
let selectedScanId = null;

/*
 * XGBoost benchmark obtained during the ML comparison.
 * These are TEST-SET metrics, not probabilities of the current scan.
 */
const XGBOOST_METRICS = {
    accuracy: 64.85,
    precision: 68.69,
    recall: 74.63,
    f1: 71.54
};

/* =========================================================
   HELPERS
   ========================================================= */

function esc(value) {
    if (value === null || value === undefined) {
        return "";
    }

    return String(value)
        .replaceAll("&", "&amp;")
        .replaceAll("<", "&lt;")
        .replaceAll(">", "&gt;")
        .replaceAll('"', "&quot;")
        .replaceAll("'", "&#039;");
}

function sevKey(severity) {
    return String(severity || "")
        .trim()
        .toUpperCase();
}

function priorityKey(priority) {
    return String(priority || "")
        .trim()
        .toUpperCase();
}

function setStatus(online, text) {
    const statusText = document.getElementById("api-status-text");
    const dot = document.querySelector(".status-dot");

    if (statusText) {
        statusText.textContent = text;
    }

    if (dot) {
        dot.classList.remove("online", "offline");

        if (online) {
            dot.classList.add("online");
        } else {
            dot.classList.add("offline");
        }
    }
}

function showMessage(message, type = "info") {
    const element = document.getElementById("global-message");

    if (!element) {
        return;
    }

    element.textContent = message;

    element.style.color =
        type === "error"
            ? "#dc2626"
            : type === "success"
                ? "#15803d"
                : "#334155";

    element.style.background =
        type === "error"
            ? "#fef2f2"
            : type === "success"
                ? "#f0fdf4"
                : "#f8fafc";

    element.style.borderColor =
        type === "error"
            ? "#fecaca"
            : type === "success"
                ? "#bbf7d0"
                : "#e2e8f0";

    element.classList.add("show");

    setTimeout(() => {
        element.classList.remove("show");
    }, 4500);
}

function formatDate(value) {
    if (!value) {
        return "—";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString("fr-FR", {
        dateStyle: "medium",
        timeStyle: "short"
    });
}

function calculateDuration(start, end) {
    if (!start || !end) {
        return "—";
    }

    const diff = new Date(end) - new Date(start);

    if (Number.isNaN(diff)) {
        return "—";
    }

    if (diff < 1000) {
        return "< 1 s";
    }

    if (diff < 60000) {
        return `${Math.round(diff / 1000)} s`;
    }

    return `${Math.floor(diff / 60000)} min`;
}

function severityBadge(severity) {
    const key = sevKey(severity);

    if (key === "ERROR" || key === "CRITICAL") {
        return `<span class="badge badge-error">${esc(severity)}</span>`;
    }

    if (key === "WARNING" || key === "HIGH") {
        return `<span class="badge badge-warning">${esc(severity)}</span>`;
    }

    return `<span class="badge badge-info">${esc(severity || "INFO")}</span>`;
}

function priorityBadge(priority) {
    const key = priorityKey(priority);

    if (key === "CRITIQUE") {
        return `<span class="badge badge-critical">CRITIQUE</span>`;
    }

    if (key === "ÉLEVÉE" || key === "ELEVEE" || key === "HIGH") {
        return `<span class="badge badge-high">ÉLEVÉE</span>`;
    }

    if (key === "MOYENNE" || key === "MEDIUM") {
        return `<span class="badge badge-medium">MOYENNE</span>`;
    }

    return `<span class="badge badge-low">FAIBLE</span>`;
}

function probabilityClass(probability) {
    const p = Number(probability || 0);

    if (p >= 0.8) {
        return "probability-high";
    }

    if (p >= 0.5) {
        return "probability-medium";
    }

    return "probability-low";
}

function probabilityHTML(probability) {
    if (probability === null || probability === undefined) {
        return "—";
    }

    const value = Number(probability);

    if (Number.isNaN(value)) {
        return "—";
    }

    const percent = (value * 100).toFixed(2);

    return `
        <span class="probability ${probabilityClass(value)}">
            ${percent}%
        </span>
    `;
}

/* =========================================================
   API
   ========================================================= */

async function apiGet(endpoint) {
    const response = await fetch(`${API_URL}${endpoint}`);

    if (!response.ok) {
        throw new Error(`Erreur API ${response.status}`);
    }

    return response.json();
}

/* =========================================================
   DASHBOARD
   ========================================================= */

async function loadDashboard() {
    try {
        setStatus(true, "API connectée");

        await Promise.all([
            loadScans(),
            loadVulnerabilities()
        ]);

        updateModelPerformance();

    } catch (error) {
        console.error(error);

        setStatus(false, "API inaccessible");

        showMessage(
            "Impossible de contacter l'API FastAPI.",
            "error"
        );
    }
}

/* =========================================================
   VULNERABILITIES
   ========================================================= */

async function loadVulnerabilities() {
    const loading = document.getElementById("loading");
    const error = document.getElementById("error-message");

    if (loading) {
        loading.classList.remove("hidden");
    }

    if (error) {
        error.classList.add("hidden");
    }

    try {
        const data = await apiGet("/vulnerabilities");

        if (Array.isArray(data)) {
            allVulnerabilities = data;
        } else if (Array.isArray(data.vulnerabilities)) {
            allVulnerabilities = data.vulnerabilities;
        } else {
            allVulnerabilities = [];
        }

        displayStatistics(allVulnerabilities);
        displayRiskAnalysis(allVulnerabilities);
        displayAIAnalysis(allVulnerabilities);
        displayPipeline(allVulnerabilities);

        fillFilters(allVulnerabilities);

        applyFilters();

    } catch (error) {
        console.error(error);

        if (error) {
            error.classList.remove("hidden");
        }

        throw error;

    } finally {
        if (loading) {
            loading.classList.add("hidden");
        }
    }
}

/* =========================================================
   SCANS
   ========================================================= */

async function loadScans() {
    const data = await apiGet("/scans");

    if (Array.isArray(data)) {
        allScans = data;
    } else if (Array.isArray(data.scans)) {
        allScans = data.scans;
    } else {
        allScans = [];
    }

    displayScanHistory(allScans);

    const count = document.getElementById("history-count");

    if (count) {
        count.textContent =
            `${allScans.length} scan${allScans.length > 1 ? "s" : ""}`;
    }

    if (allScans.length > 0) {
        const latest = allScans[0];

        if (selectedScanId === null) {
            selectedScanId = latest.id;
        }

        updateCurrentScan(latest);
    }
}

/* =========================================================
   STATISTICS
   ========================================================= */

function displayStatistics(list) {
    const total = list.length;

    const errors = list.filter(
        v => sevKey(v.severity) === "ERROR"
    ).length;

    const warnings = list.filter(
        v => sevKey(v.severity) === "WARNING"
    ).length;

    const highPriority = list.filter(v => {
        const p = priorityKey(v.ml_priority);

        return (
            p === "CRITIQUE" ||
            p === "ÉLEVÉE" ||
            p === "ELEVEE" ||
            p === "HIGH"
        );
    }).length;

    setText("total-alerts", total);
    setText("error-alerts", errors);
    setText("warning-alerts", warnings);
    setText("high-priority-alerts", highPriority);

    setText("risk-total", total);
    setText("risk-error-count", errors);
    setText("risk-warning-count", warnings);

    const info = list.filter(
        v => !["ERROR", "WARNING"].includes(sevKey(v.severity))
    ).length;

    setText("risk-info-count", info);
}

/* =========================================================
   RISK ANALYSIS
   ========================================================= */

function displayRiskAnalysis(list) {
    const total = list.length || 1;

    const errors = list.filter(
        v => sevKey(v.severity) === "ERROR"
    ).length;

    const warnings = list.filter(
        v => sevKey(v.severity) === "WARNING"
    ).length;

    const info = list.filter(
        v => !["ERROR", "WARNING"].includes(sevKey(v.severity))
    ).length;

    setWidth(
        "risk-error-bar",
        (errors / total) * 100
    );

    setWidth(
        "risk-warning-bar",
        (warnings / total) * 100
    );

    setWidth(
        "risk-info-bar",
        (info / total) * 100
    );
}

/* =========================================================
   AI / XGBOOST ANALYSIS
   ========================================================= */

function displayAIAnalysis(list) {
    if (!list.length) {
        setText("ai-average", "0%");
        setText("priority-critical", 0);
        setText("priority-high", 0);
        setText("priority-medium", 0);
        setText("priority-low", 0);

        return;
    }

    const probabilities = list
        .map(v => Number(v.ml_probability))
        .filter(p => !Number.isNaN(p));

    const average =
        probabilities.length > 0
            ? probabilities.reduce((sum, p) => sum + p, 0) /
              probabilities.length
            : 0;

    setText(
        "ai-average",
        `${(average * 100).toFixed(2)}%`
    );

    const critical = list.filter(
        v => priorityKey(v.ml_priority) === "CRITIQUE"
    ).length;

    const high = list.filter(v => {
        const p = priorityKey(v.ml_priority);

        return (
            p === "ÉLEVÉE" ||
            p === "ELEVEE" ||
            p === "HIGH"
        );
    }).length;

    const medium = list.filter(v => {
        const p = priorityKey(v.ml_priority);

        return p === "MOYENNE" || p === "MEDIUM";
    }).length;

    const low = list.filter(v => {
        const p = priorityKey(v.ml_priority);

        return (
            p === "FAIBLE" ||
            p === "LOW" ||
            p === ""
        );
    }).length;

    setText("priority-critical", critical);
    setText("priority-high", high);
    setText("priority-medium", medium);
    setText("priority-low", low);

    /*
     * Optional circular score.
     */
    const circle = document.querySelector(".ai-circle");

    if (circle) {
        const degrees = average * 360;

        circle.style.setProperty(
            "--score",
            `${degrees}deg`
        );

        const value = circle.querySelector("span");

        if (value) {
            value.textContent =
                `${Math.round(average * 100)}%`;
        }
    }
}

/* =========================================================
   MODEL PERFORMANCE
   ========================================================= */

function updateModelPerformance() {
    setText(
        "model-accuracy",
        `${XGBOOST_METRICS.accuracy.toFixed(2)}%`
    );

    setText(
        "model-precision",
        `${XGBOOST_METRICS.precision.toFixed(2)}%`
    );

    setText(
        "model-recall",
        `${XGBOOST_METRICS.recall.toFixed(2)}%`
    );

    setText(
        "model-f1",
        `${XGBOOST_METRICS.f1.toFixed(2)}%`
    );
}

/* =========================================================
   PIPELINE
   ========================================================= */

function displayPipeline(list) {
    const semgrep = list.filter(
        v => String(v.tool || "").toLowerCase() === "semgrep"
    ).length;

    const gitleaks = list.filter(
        v => String(v.tool || "").toLowerCase() === "gitleaks"
    ).length;

    const trivy = list.filter(
        v => String(v.tool || "").toLowerCase() === "trivy"
    ).length;

    setText("semgrep-count", semgrep);
    setText("gitleaks-count", gitleaks);
    setText("trivy-count", trivy);

    setText(
        "xgboost-count",
        list.filter(v =>
            v.ml_prediction !== null &&
            v.ml_prediction !== undefined
        ).length
    );
}

/* =========================================================
   FILTERS
   ========================================================= */

function fillFilters(list) {
    const tools = [
        ...new Set(
            list
                .map(v => v.tool)
                .filter(Boolean)
        )
    ];

    fillSelect(
        "filter-tool",
        tools
    );
}

function fillSelect(id, values) {
    const select = document.getElementById(id);

    if (!select) {
        return;
    }

    const current = select.value;

    const firstOption =
        select.querySelector("option:first-child");

    select.innerHTML = "";

    if (firstOption) {
        select.appendChild(firstOption);
    } else {
        const option = document.createElement("option");

        option.value = "";
        option.textContent = "Tous";

        select.appendChild(option);
    }

    values.forEach(value => {
        const option = document.createElement("option");

        option.value = value;
        option.textContent = value;

        select.appendChild(option);
    });

    if (
        [...select.options]
            .some(option => option.value === current)
    ) {
        select.value = current;
    }
}

function applyFilters() {
    const search =
        document.getElementById("search")?.value
            ?.toLowerCase()
            .trim() || "";

    const severity =
        document.getElementById("filter-severity")?.value
            ?.toUpperCase() || "";

    const tool =
        document.getElementById("filter-tool")?.value
            ?.toLowerCase() || "";

    const filtered = allVulnerabilities.filter(v => {
        const searchable = [
            v.id,
            v.tool,
            v.vuln_type,
            v.file,
            v.message,
            v.cwe,
            v.owasp,
            v.ml_priority
        ]
            .join(" ")
            .toLowerCase();

        const matchesSearch =
            !search ||
            searchable.includes(search);

        const matchesSeverity =
            !severity ||
            sevKey(v.severity) === severity;

        const matchesTool =
            !tool ||
            String(v.tool || "").toLowerCase() === tool;

        return (
            matchesSearch &&
            matchesSeverity &&
            matchesTool
        );
    });

    displayVulnerabilities(filtered);

    setText(
        "result-count",
        `${filtered.length} résultat${filtered.length > 1 ? "s" : ""}`
    );
}

/* =========================================================
   VULNERABILITY TABLE
   ========================================================= */

function displayVulnerabilities(list) {
    const body =
        document.getElementById("vulnerabilities-body");

    const empty =
        document.getElementById("empty");

    if (!body) {
        return;
    }

    body.innerHTML = "";

    if (!list.length) {
        if (empty) {
            empty.classList.remove("hidden");
        }

        return;
    }

    if (empty) {
        empty.classList.add("hidden");
    }

    list.forEach(vulnerability => {
        const row = document.createElement("tr");

        const probability =
            vulnerability.ml_probability;

        row.innerHTML = `
            <td>
                <strong>#${esc(vulnerability.id)}</strong>
            </td>

            <td>
                <div class="vuln-type">
                    ${esc(vulnerability.vuln_type || "Vulnérabilité")}
                </div>

                ${
                    vulnerability.cwe
                        ? `<div class="line-number">${esc(vulnerability.cwe)}</div>`
                        : ""
                }
            </td>

            <td>
                <span class="badge badge-info">
                    ${esc(vulnerability.tool || "—")}
                </span>
            </td>

            <td>
                ${severityBadge(vulnerability.severity)}
            </td>

            <td>
                ${priorityBadge(vulnerability.ml_priority)}
            </td>

            <td>
                ${probabilityHTML(probability)}
            </td>

            <td>
                <div class="file-name">
                    ${esc(vulnerability.file || "—")}
                </div>

                <div class="line-number">
                    Ligne ${esc(vulnerability.line || "—")}
                </div>
            </td>

            <td>
                <button
                    class="action-button"
                    onclick="openDetails(${Number(vulnerability.id)})"
                >
                    Détails
                </button>
            </td>
        `;

        body.appendChild(row);
    });
}

/* =========================================================
   DETAILS DRAWER
   ========================================================= */

function openDetails(id) {
    const vulnerability =
        allVulnerabilities.find(
            v => Number(v.id) === Number(id)
        );

    if (!vulnerability) {
        return;
    }

    const overlay =
        document.getElementById("overlay");

    const drawer =
        document.getElementById("drawer");

    const severity =
        document.getElementById("drawer-severity");

    const title =
        document.getElementById("drawer-title");

    const location =
        document.getElementById("drawer-location");

    const body =
        document.getElementById("drawer-body");

    if (!drawer || !body) {
        return;
    }

    if (severity) {
        severity.innerHTML =
            severityBadge(vulnerability.severity);
    }

    if (title) {
        title.textContent =
            vulnerability.vuln_type ||
            "Vulnérabilité";
    }

    if (location) {
        location.textContent =
            `${vulnerability.file || "—"} : ligne ${vulnerability.line || "—"}`;
    }

    const probability =
        vulnerability.ml_probability !== null &&
        vulnerability.ml_probability !== undefined
            ? `${(Number(vulnerability.ml_probability) * 100).toFixed(2)}%`
            : "—";

    body.innerHTML = `
        <div class="detail-section">

            <h3>Analyse de sécurité</h3>

            <div class="detail-grid">

                <div class="detail-item">
                    <span>Scanner</span>
                    <strong>${esc(vulnerability.tool || "—")}</strong>
                </div>

                <div class="detail-item">
                    <span>Règle</span>
                    <strong>${esc(vulnerability.rule_id || "—")}</strong>
                </div>

                <div class="detail-item">
                    <span>Sévérité scanner</span>
                    <strong>${esc(vulnerability.severity || "—")}</strong>
                </div>

                <div class="detail-item">
                    <span>CWE</span>
                    <strong>${esc(vulnerability.cwe || "—")}</strong>
                </div>

                <div class="detail-item">
                    <span>OWASP</span>
                    <strong>${esc(vulnerability.owasp || "—")}</strong>
                </div>

                <div class="detail-item">
                    <span>Langage</span>
                    <strong>${esc(vulnerability.language || "—")}</strong>
                </div>

            </div>

        </div>

        <div class="detail-section">

            <h3>Analyse XGBoost</h3>

            <div class="ai-detail">

                <div class="ai-detail-title">
                    🤖 Priorisation par intelligence artificielle
                </div>

                <div class="ai-detail-grid">

                    <div class="ai-detail-item">
                        <span>Prédiction</span>
                        <strong>
                            ${esc(vulnerability.ml_prediction ?? "—")}
                        </strong>
                    </div>

                    <div class="ai-detail-item">
                        <span>Probabilité prédite</span>
                        <strong>${probability}</strong>
                    </div>

                    <div class="ai-detail-item">
                        <span>Priorité XGBoost</span>
                        <strong>
                            ${esc(vulnerability.ml_priority || "—")}
                        </strong>
                    </div>

                </div>

            </div>

        </div>

        <div class="detail-section">

            <h3>Description</h3>

            <div class="detail-item">
                ${esc(
                    vulnerability.message ||
                    vulnerability.description ||
                    "Aucune description disponible."
                )}
            </div>

        </div>

        <div class="detail-section">

            <h3>Impact</h3>

            <div class="detail-item">
                ${esc(
                    vulnerability.impact ||
                    "Impact non renseigné."
                )}
            </div>

        </div>

        <div class="detail-section">

            <h3>Likelihood</h3>

            <div class="detail-item">
                ${esc(
                    vulnerability.likelihood ||
                    "Non renseigné."
                )}
            </div>

        </div>

        <div class="detail-section">

            <h3>Code / emplacement</h3>

            <pre class="code-block">${esc(
                vulnerability.code_excerpt ||
                vulnerability.code ||
                vulnerability.message ||
                "Extrait de code non disponible."
            )}</pre>

        </div>
    `;

    if (overlay) {
        overlay.classList.add("open");
    }

    drawer.classList.add("open");
}

function closeDetails() {
    const overlay =
        document.getElementById("overlay");

    const drawer =
        document.getElementById("drawer");

    if (overlay) {
        overlay.classList.remove("open");
    }

    if (drawer) {
        drawer.classList.remove("open");
    }
}

/* =========================================================
   SCAN HISTORY
   ========================================================= */

function displayScanHistory(scans) {
    const body =
        document.getElementById("scans-body");

    const empty =
        document.getElementById("history-empty");

    if (!body) {
        return;
    }

    body.innerHTML = "";

    if (!scans.length) {
        if (empty) {
            empty.classList.remove("hidden");
        }

        return;
    }

    if (empty) {
        empty.classList.add("hidden");
    }

    scans.forEach(scan => {
        const row = document.createElement("tr");

        if (Number(scan.id) === Number(selectedScanId)) {
            row.classList.add("selected");
        }

        row.classList.add("scan-row");

        row.onclick = () => selectScan(scan.id);

        row.innerHTML = `
            <td>
                <strong>#${esc(scan.id)}</strong>
            </td>

            <td>
                ${esc(scan.project || "DevSecOps")}
            </td>

            <td>
                ${formatDate(scan.started_at)}
            </td>

            <td>
                ${formatDate(scan.finished_at)}
            </td>

            <td>
                ${calculateDuration(
                    scan.started_at,
                    scan.finished_at
                )}
            </td>

            <td>
                ${esc(
                    scan.total_alerts ??
                    scan.total_vulnerabilities ??
                    "—"
                )}
            </td>

            <td>
                ${
                    String(scan.status || "").toLowerCase() === "success"
                        ? `<span class="badge badge-success">SUCCÈS</span>`
                        : `<span class="badge badge-warning">${esc(scan.status || "—")}</span>`
                }
            </td>
        `;

        body.appendChild(row);
    });
}

function selectScan(scanId) {
    selectedScanId = scanId;

    const scan =
        allScans.find(
            s => Number(s.id) === Number(scanId)
        );

    if (scan) {
        updateCurrentScan(scan);
    }

    displayScanHistory(allScans);

    /*
     * The backend currently returns all vulnerabilities.
     * Filter locally by scan_id.
     */
    const scanVulnerabilities =
        allVulnerabilities.filter(
            v => Number(v.scan_id) === Number(scanId)
        );

    if (scanVulnerabilities.length > 0) {
        displayStatistics(scanVulnerabilities);
        displayRiskAnalysis(scanVulnerabilities);
        displayAIAnalysis(scanVulnerabilities);
        displayPipeline(scanVulnerabilities);
        displayVulnerabilities(scanVulnerabilities);

        setText(
            "result-count",
            `${scanVulnerabilities.length} résultat${scanVulnerabilities.length > 1 ? "s" : ""}`
        );
    } else {
        displayVulnerabilities([]);
        setText("result-count", "0 résultat");
    }
}

function updateCurrentScan(scan) {
    setText(
        "current-project",
        scan.project || "DevSecOps AI"
    );

    setText(
        "current-scan-id",
        `#${scan.id ?? "—"}`
    );

    setText(
        "current-scan-status",
        scan.status || "—"
    );

    setText(
        "current-scan-date",
        formatDate(
            scan.started_at ||
            scan.finished_at
        )
    );
}

/* =========================================================
   SCAN LAUNCH
   ========================================================= */

async function launchScan() {
    const button =
        document.getElementById("scan-button");

    if (button) {
        button.disabled = true;
        button.textContent = "Scan en cours...";
    }

    try {
        const response =
            await fetch(`${API_URL}/scan`, {
                method: "POST"
            });

        if (!response.ok) {
            throw new Error(
                `Erreur scan : ${response.status}`
            );
        }

        const result =
            await response.json();

        showMessage(
            `Scan terminé : ${result.total_alerts ?? 0} alerte(s).`,
            "success"
        );

        selectedScanId =
            result.scan_id ?? null;

        await loadDashboard();

    } catch (error) {
        console.error(error);

        showMessage(
            "Le scan n'a pas pu être exécuté.",
            "error"
        );

    } finally {
        if (button) {
            button.disabled = false;
            button.textContent = "Lancer un scan";
        }
    }
}

/* =========================================================
   DOM HELPERS
   ========================================================= */

function setText(id, value) {
    const element =
        document.getElementById(id);

    if (element) {
        element.textContent = value;
    }
}

function setWidth(id, percentage) {
    const element =
        document.getElementById(id);

    if (!element) {
        return;
    }

    const safe =
        Math.max(
            0,
            Math.min(100, Number(percentage) || 0)
        );

    element.style.width = `${safe}%`;
}

/* =========================================================
   EVENTS
   ========================================================= */

document.addEventListener("DOMContentLoaded", () => {

    const search =
        document.getElementById("search");

    const severity =
        document.getElementById("filter-severity");

    const tool =
        document.getElementById("filter-tool");

    const refresh =
        document.getElementById("refresh-button");

    const scanButton =
        document.getElementById("scan-button");

    const closeButton =
        document.getElementById("drawer-close");

    const overlay =
        document.getElementById("overlay");

    if (search) {
        search.addEventListener(
            "input",
            applyFilters
        );
    }

    if (severity) {
        severity.addEventListener(
            "change",
            applyFilters
        );
    }

    if (tool) {
        tool.addEventListener(
            "change",
            applyFilters
        );
    }

    if (refresh) {
        refresh.addEventListener(
            "click",
            loadDashboard
        );
    }

    if (scanButton) {
        scanButton.addEventListener(
            "click",
            launchScan
        );
    }

    if (closeButton) {
        closeButton.addEventListener(
            "click",
            closeDetails
        );
    }

    if (overlay) {
        overlay.addEventListener(
            "click",
            closeDetails
        );
    }

    updateModelPerformance();

    loadDashboard();
});

/* =========================================================
   GLOBAL
   ========================================================= */

window.openDetails = openDetails;
window.closeDetails = closeDetails;

