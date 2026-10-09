
const API_URL = "http://127.0.0.1:8000";

let allVulnerabilities = [];
let allScans = [];

let selectedScanId = null;


/* =========================================================
   UTILITAIRES
========================================================= */

function esc(value) {
    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
    }

    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;");
}


function sevKey(severity) {

    const s = String(severity || "").toUpperCase();

    return ["ERROR", "WARNING", "INFO"].includes(s)
        ? s
        : "OTHER";
}


function setStatus(ok) {

    const box = document.getElementById("api-status");

    box.classList.toggle("ok", ok);
    box.classList.toggle("down", !ok);

    document.getElementById("api-status-text").textContent =
        ok
            ? "API connectée"
            : "API injoignable";
}


function showMessage(message, type = "info") {

    const box = document.getElementById("global-message");

    box.textContent = message;

    box.className = "global-message";

    if (type === "success") {
        box.classList.add("success");
    }

    if (type === "error") {
        box.classList.add("error");
    }

    box.hidden = false;

    setTimeout(() => {
        box.hidden = true;
    }, 4000);
}


function formatDate(value) {

    if (!value) {
        return "-";
    }

    const date = new Date(value);

    if (Number.isNaN(date.getTime())) {
        return value;
    }

    return date.toLocaleString("fr-FR", {
        dateStyle: "short",
        timeStyle: "medium"
    });
}


function calculateDuration(start, end) {

    if (!start || !end) {
        return "-";
    }

    const startDate = new Date(start);
    const endDate = new Date(end);

    const seconds =
        Math.max(
            0,
            Math.round(
                (endDate - startDate) / 1000
            )
        );

    if (seconds < 60) {
        return `${seconds}s`;
    }

    const minutes = Math.floor(seconds / 60);
    const remainingSeconds = seconds % 60;

    return `${minutes}m ${remainingSeconds}s`;
}


/* =========================================================
   CHARGEMENT INITIAL
========================================================= */

async function loadDashboard() {

    const loading =
        document.getElementById("loading");

    const errorMessage =
        document.getElementById("error-message");

    loading.style.display = "block";

    errorMessage.textContent = "";

    try {

        setStatus(false);

        await loadScans();

        const response =
            await fetch(`${API_URL}/vulnerabilities`);

        if (!response.ok) {
            throw new Error(
                "Erreur lors de la récupération des vulnérabilités"
            );
        }

        allVulnerabilities =
            await response.json();

        setStatus(true);

        if (!selectedScanId) {

            displayStatistics([]);
            displayDistribution([]);
            displayVulnerabilities([]);

            return;
        }

        selectScan(selectedScanId);

    } catch (error) {

        console.error(error);

        setStatus(false);

        errorMessage.textContent =
            "Impossible de contacter l'API FastAPI. " +
            "Vérifiez qu'elle tourne sur " +
            API_URL +
            ".";

    } finally {

        loading.style.display = "none";
    }
}


/* =========================================================
   HISTORIQUE DES SCANS
========================================================= */

async function loadScans() {

    const loading =
        document.getElementById("history-loading");

    const empty =
        document.getElementById("history-empty");

    const body =
        document.getElementById("scans-body");

    loading.style.display = "block";

    try {

        const response =
            await fetch(`${API_URL}/scans`);

        if (!response.ok) {
            throw new Error(
                "Impossible de récupérer les scans"
            );
        }

        allScans =
            await response.json();

        body.innerHTML = "";

        document.getElementById(
            "history-count"
        ).textContent =
            `${allScans.length} scan${allScans.length > 1 ? "s" : ""}`;

        if (allScans.length === 0) {

            empty.hidden = false;

            selectedScanId = null;

            return;
        }

        empty.hidden = true;

        allScans.forEach(scan => {

            const row =
                document.createElement("tr");

            const status =
                String(scan.status || "").toLowerCase();

            const statusClass =
                status === "success"
                    ? "success"
                    : "error";

            row.innerHTML = `
                <td>
                    <strong>#${esc(scan.id)}</strong>
                </td>

                <td>
                    ${esc(scan.project)}
                </td>

                <td>
                    ${esc(formatDate(scan.started_at))}
                </td>

                <td>
                    ${esc(
                        calculateDuration(
                            scan.started_at,
                            scan.finished_at
                        )
                    )}
                </td>

                <td>
                    <span class="status-badge ${statusClass}">
                        ${esc(scan.status)}
                    </span>
                </td>

                <td class="num">
                    <strong>
                        ${esc(scan.total_alerts)}
                    </strong>
                </td>

                <td>
                    <button
                        class="btn-history ${String(selectedScanId) === String(scan.id) ? "active" : ""}"
                        data-scan-id="${esc(scan.id)}"
                    >
                        Voir
                    </button>
                </td>
            `;

            body.appendChild(row);
        });

        if (!selectedScanId) {
            selectedScanId = allScans[0].id;
        }

    } catch (error) {

        console.error(error);

        body.innerHTML = "";

        empty.hidden = false;

        empty.textContent =
            "Impossible de charger l'historique.";

    } finally {

        loading.style.display = "none";
    }
}


/* =========================================================
   SÉLECTION D'UN SCAN
========================================================= */

function selectScan(scanId) {

    selectedScanId = Number(scanId);

    const scan =
        allScans.find(
            s => Number(s.id) === selectedScanId
        );

    if (!scan) {
        return;
    }

    const vulnerabilities =
        allVulnerabilities.filter(
            vulnerability =>
                Number(vulnerability.scan_id) ===
                selectedScanId
        );

    document.getElementById(
        "selected-scan-info"
    ).textContent =
        `Analyse #${scan.id} du projet ${scan.project}`;

    document.getElementById(
        "current-project"
    ).textContent =
        scan.project || "-";

    document.getElementById(
        "current-scan-id"
    ).textContent =
        `#${scan.id}`;

    const statusElement =
        document.getElementById(
            "current-scan-status"
        );

    statusElement.textContent =
        scan.status || "-";

    statusElement.className =
        "status-badge " +
        (
            scan.status === "success"
                ? ""
                : "error"
        );

    document.getElementById(
        "current-scan-date"
    ).textContent =
        formatDate(scan.started_at);

    displayStatistics(
        vulnerabilities
    );

    displayDistribution(
        vulnerabilities
    );

    fillFilters(
        vulnerabilities
    );

    applyFilters(
        vulnerabilities
    );

    document
        .querySelectorAll(".btn-history")
        .forEach(button => {

            button.classList.toggle(
                "active",
                Number(button.dataset.scanId) ===
                selectedScanId
            );
        });
}


/* =========================================================
   STATISTIQUES
========================================================= */

function displayStatistics(list) {

    const count =
        severity =>
            list.filter(
                vulnerability =>
                    sevKey(vulnerability.severity) ===
                    severity
            ).length;

    document.getElementById(
        "total-alerts"
    ).textContent =
        list.length;

    document.getElementById(
        "error-alerts"
    ).textContent =
        count("ERROR");

    document.getElementById(
        "warning-alerts"
    ).textContent =
        count("WARNING");

    document.getElementById(
        "tools-count"
    ).textContent =
        new Set(
            list.map(
                vulnerability =>
                    vulnerability.tool
            )
        ).size;
}


/* =========================================================
   DISTRIBUTION
========================================================= */

function displayDistribution(list) {

    const bar =
        document.getElementById(
            "severity-bar"
        );

    const legend =
        document.getElementById(
            "legend"
        );

    bar.innerHTML = "";
    legend.innerHTML = "";

    if (list.length === 0) {

        bar.innerHTML =
            `<span style="width:100%"></span>`;

        return;
    }

    const counts = {};

    list.forEach(vulnerability => {

        const key =
            sevKey(vulnerability.severity);

        counts[key] =
            (counts[key] || 0) + 1;
    });

    const keys =
        Object.keys(counts);

    keys.forEach(key => {

        const percentage =
            (counts[key] / list.length) * 100;

        const segment =
            document.createElement("span");

        segment.className =
            `sev-${key}`;

        segment.style.width =
            `${percentage}%`;

        segment.style.background =
            "var(--c)";

        segment.title =
            `${key} : ${counts[key]}`;

        bar.appendChild(segment);

        const legendItem =
            document.createElement("span");

        legendItem.className =
            `sev-${key}`;

        legendItem.innerHTML =
            `
                <i style="background:var(--c)"></i>
                ${esc(key)} (${counts[key]})
            `;

        legend.appendChild(
            legendItem
        );
    });
}


/* =========================================================
   FILTRES
========================================================= */

function fillFilters(list) {

    fillSelect(
        "filter-severity",
        "Toutes les sévérités",
        [
            ...new Set(
                list.map(
                    vulnerability =>
                        vulnerability.severity
                )
            )
        ]
    );

    fillSelect(
        "filter-tool",
        "Tous les outils",
        [
            ...new Set(
                list.map(
                    vulnerability =>
                        vulnerability.tool
                )
            )
        ]
    );
}


function fillSelect(
    id,
    placeholder,
    values
) {

    const select =
        document.getElementById(id);

    const current =
        select.value;

    select.innerHTML =
        `<option value="">${placeholder}</option>` +
        values
            .filter(Boolean)
            .sort()
            .map(
                value =>
                    `
                    <option value="${esc(value)}">
                        ${esc(value)}
                    </option>
                    `
            )
            .join("");

    select.value =
        current;
}


function applyFilters(
    sourceList = null
) {

    const list =
        sourceList ||
        allVulnerabilities.filter(
            vulnerability =>
                Number(vulnerability.scan_id) ===
                Number(selectedScanId)
        );

    const text =
        document
            .getElementById("search")
            .value
            .trim()
            .toLowerCase();

    const severity =
        document
            .getElementById(
                "filter-severity"
            )
            .value;

    const tool =
        document
            .getElementById(
                "filter-tool"
            )
            .value;

    const filtered =
        list.filter(vulnerability => {

            if (
                severity &&
                vulnerability.severity !==
                severity
            ) {
                return false;
            }

            if (
                tool &&
                vulnerability.tool !==
                tool
            ) {
                return false;
            }

            if (!text) {
                return true;
            }

            return [
                vulnerability.tool,
                vulnerability.vuln_type,
                vulnerability.file,
                vulnerability.id
            ].some(
                value =>
                    String(
                        value ?? ""
                    )
                        .toLowerCase()
                        .includes(text)
            );
        });

    displayVulnerabilities(
        filtered
    );

    document.getElementById(
        "result-count"
    ).textContent =
        `${filtered.length} résultat${filtered.length > 1 ? "s" : ""} sur ${list.length}`;
}


/* =========================================================
   TABLEAU VULNÉRABILITÉS
========================================================= */

function displayVulnerabilities(list) {

    const tableBody =
        document.getElementById(
            "vulnerabilities-body"
        );

    tableBody.innerHTML = "";

    const empty =
        document.getElementById(
            "empty"
        );

    empty.hidden =
        list.length > 0;

    list.forEach(vulnerability => {

        const row =
            document.createElement("tr");

        const severity =
            sevKey(
                vulnerability.severity
            );

        row.innerHTML =
            `
            <td class="id">
                ${esc(vulnerability.id)}
            </td>

            <td>
                ${esc(vulnerability.tool)}
            </td>

            <td>
                ${esc(vulnerability.vuln_type)}
            </td>

            <td>
                <span class="severity sev-${severity}">
                    ${esc(vulnerability.severity)}
                </span>
            </td>

            <td
                class="file"
                title="${esc(vulnerability.file)}"
            >
                ${esc(vulnerability.file)}
            </td>

            <td class="num">
                ${esc(vulnerability.line)}
            </td>

            <td>
                <button
                    class="btn-detail"
                    data-id="${esc(vulnerability.id)}"
                >
                    Voir détails
                </button>
            </td>
            `;

        tableBody.appendChild(
            row
        );
    });
}


/* =========================================================
   PANNEAU DE DÉTAILS
========================================================= */

const drawer =
    document.getElementById(
        "drawer"
    );

const overlay =
    document.getElementById(
        "overlay"
    );

let lastFocus = null;


/*
 * Transforme l'extrait de code retourné par FastAPI
 * en HTML affichable dans le drawer.
 */
function renderCodeExcerpt(codeExcerpt) {

    if (
        !codeExcerpt ||
        !Array.isArray(codeExcerpt.lines) ||
        codeExcerpt.lines.length === 0
    ) {
        return `
            <div class="code-empty">
                Aucun extrait de code disponible.
            </div>
        `;
    }

    const lines =
        codeExcerpt.lines
            .map(item => {

                const lineClass =
                    item.vulnerable
                        ? "code-line vulnerable"
                        : "code-line";

                const marker =
                    item.vulnerable
                        ? "⚠"
                        : "";

                return `
                    <div class="${lineClass}">
                        <span class="line-marker">
                            ${marker}
                        </span>

                        <span class="line-number">
                            ${esc(item.line)}
                        </span>

                        <code>
                            ${esc(item.code)}
                        </code>
                    </div>
                `;
            })
            .join("");

    return `
        <section class="code-section">

            <div class="code-header">
                <strong>Extrait du code</strong>

                <span>
                    Lignes
                    ${esc(codeExcerpt.start_line)}
                    -
                    ${esc(codeExcerpt.end_line)}
                </span>
            </div>

            <div class="code-block">
                ${lines}
            </div>

        </section>
    `;
}


async function openDetails(id) {

    /*
     * On récupère d'abord les informations déjà présentes
     * dans le dashboard.
     */
    let vulnerability =
        allVulnerabilities.find(
            item =>
                String(item.id) ===
                String(id)
        );

    if (!vulnerability) {
        return;
    }


    /*
     * IMPORTANT :
     * On appelle maintenant FastAPI pour récupérer
     * le détail complet + code_excerpt.
     */
    try {

        const response =
            await fetch(
                `${API_URL}/vulnerabilities/${id}`
            );

        if (response.ok) {

            const detailedVulnerability =
                await response.json();

            vulnerability = {
                ...vulnerability,
                ...detailedVulnerability
            };
        }

    } catch (error) {

        console.error(
            "Impossible de récupérer le détail :",
            error
        );
    }


    const severity =
        sevKey(
            vulnerability.severity
        );


    document.getElementById(
        "drawer-severity"
    ).innerHTML =
        `
        <span class="severity sev-${severity}">
            ${esc(vulnerability.severity)}
        </span>
        `;


    document.getElementById(
        "drawer-title"
    ).textContent =
        vulnerability.vuln_type ||
        "Vulnérabilité";


    document.getElementById(
        "drawer-location"
    ).textContent =
        `${vulnerability.file ?? "-"}${
            vulnerability.line != null
                ? ":" + vulnerability.line
                : ""
        }`;


    /*
     * Informations principales + code.
     */
    document.getElementById(
        "drawer-body"
    ).innerHTML =
        `
        <div class="grid-3">

            <div class="field">
                <dt>Outil</dt>
                <dd>
                    ${esc(vulnerability.tool)}
                </dd>
            </div>

            <div class="field">
                <dt>ID</dt>
                <dd>
                    #${esc(vulnerability.id)}
                </dd>
            </div>

            <div class="field">
                <dt>Scan</dt>
                <dd>
                    #${esc(vulnerability.scan_id)}
                </dd>
            </div>

        </div>


        <dl class="field">
            <dt>CWE</dt>
            <dd>
                ${tag(vulnerability.cwe)}
            </dd>
        </dl>


        <dl class="field">
            <dt>OWASP</dt>
            <dd>
                ${tag(vulnerability.owasp)}
            </dd>
        </dl>


        <dl class="field">
            <dt>Message</dt>

            <dd class="message">
                ${esc(vulnerability.message)}
            </dd>
        </dl>


        <div class="grid-3">

            <div class="field">
                <dt>Impact</dt>
                <dd>
                    ${esc(vulnerability.impact)}
                </dd>
            </div>

            <div class="field">
                <dt>Likelihood</dt>
                <dd>
                    ${esc(vulnerability.likelihood)}
                </dd>
            </div>

            <div class="field">
                <dt>Confidence</dt>
                <dd>
                    ${esc(vulnerability.confidence)}
                </dd>
            </div>

        </div>


        ${renderCodeExcerpt(vulnerability.code_excerpt)}
        `;


    lastFocus =
        document.activeElement;


    drawer.classList.add(
        "open"
    );


    drawer.setAttribute(
        "aria-hidden",
        "false"
    );


    overlay.hidden =
        false;


    document
        .getElementById(
            "drawer-close"
        )
        .focus();
}


function tag(value) {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {
        return "-";
    }

    const items =
        Array.isArray(value)
            ? value
            : [value];

    return items
        .map(
            item =>
                `<span class="tag">${esc(item)}</span>`
        )
        .join(" ");
}


function closeDetails() {

    drawer.classList.remove(
        "open"
    );

    drawer.setAttribute(
        "aria-hidden",
        "true"
    );

    overlay.hidden =
        true;

    if (lastFocus) {
        lastFocus.focus();
    }
}


/* =========================================================
   LANCER UN SCAN
========================================================= */

async function launchScan() {

    const button =
        document.getElementById(
            "scan-button"
        );

    const oldText =
        button.textContent;

    button.disabled =
        true;

    button.textContent =
        "Scan en cours…";

    try {

        const response =
            await fetch(
                `${API_URL}/scan`,
                {
                    method: "POST"
                }
            );

        const result =
            await response.json();

        if (!response.ok) {

            throw new Error(
                result.message ||
                "Le scan a échoué."
            );
        }

        if (
            result.status !==
            "success"
        ) {

            throw new Error(
                "Le scan n'a pas réussi."
            );
        }

        showMessage(
            `Scan #${result.scan_id} terminé : ${result.total_alerts} alertes détectées.`,
            "success"
        );

        await loadDashboard();

    } catch (error) {

        console.error(error);

        showMessage(
            "Impossible de lancer le scan : " +
            error.message,
            "error"
        );

    } finally {

        button.disabled =
            false;

        button.textContent =
            oldText;
    }
}


/* =========================================================
   ÉVÉNEMENTS
========================================================= */

document
    .getElementById("scans-body")
    .addEventListener(
        "click",
        event => {

            const button =
                event.target.closest(
                    ".btn-history"
                );

            if (!button) {
                return;
            }

            selectScan(
                Number(
                    button.dataset.scanId
                )
            );
        }
    );


document
    .getElementById(
        "vulnerabilities-body"
    )
    .addEventListener(
        "click",
        event => {

            const button =
                event.target.closest(
                    ".btn-detail"
                );

            if (!button) {
                return;
            }

            openDetails(
                button.dataset.id
            );
        }
    );


document
    .getElementById(
        "drawer-close"
    )
    .addEventListener(
        "click",
        closeDetails
    );


overlay.addEventListener(
    "click",
    closeDetails
);


document.addEventListener(
    "keydown",
    event => {

        if (
            event.key ===
            "Escape"
        ) {
            closeDetails();
        }
    }
);


document
    .getElementById(
        "search"
    )
    .addEventListener(
        "input",
        () => applyFilters()
    );


document
    .getElementById(
        "filter-severity"
    )
    .addEventListener(
        "change",
        () => applyFilters()
    );


document
    .getElementById(
        "filter-tool"
    )
    .addEventListener(
        "change",
        () => applyFilters()
    );


document
    .getElementById(
        "refresh-button"
    )
    .addEventListener(
        "click",
        async () => {

            await loadDashboard();

            showMessage(
                "Dashboard actualisé.",
                "success"
            );
        }
    );


document
    .getElementById(
        "scan-button"
    )
    .addEventListener(
        "click",
        launchScan
    );


/* =========================================================
   DÉMARRAGE
========================================================= */

loadDashboard();

