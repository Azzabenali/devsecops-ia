import json
from pathlib import Path


def language_of(path):
    extension = Path(path).suffix.lower()

    languages = {
        ".py": "python",
        ".js": "javascript",
        ".ts": "typescript",
        ".java": "java",
        ".php": "php",
        ".go": "go",
        ".cs": "csharp",
        ".rb": "ruby",
    }

    return languages.get(extension, "other")


def classify_semgrep_rule(check_id, message):
    check_id = check_id.lower()
    message = message.lower()

    if "tainted-sql" in check_id or "sql injection" in message:
        return "SQL Injection", "CWE-89", "A03:2021 Injection"

    if (
        "raw-html" in check_id
        or "cross-site scripting" in message
        or "xss" in message
    ):
        return "Cross-Site-Scripting (XSS)", "CWE-79", "A03:2021 Injection"

    if "subprocess-injection" in check_id or "dangerous-subprocess" in check_id:
        return "Command Injection", "CWE-78", "A03:2021 Injection"

    if "subprocess-shell-true" in check_id:
        return "Command Injection", "CWE-78", "A03:2021 Injection"

    if "debug-enabled" in check_id:
        return "Active Debug Code", "CWE-489", "A05:2021 Security Misconfiguration"

    return "Security Issue", None, None


def parse_semgrep(file_path="semgrep.json"):
    """
    Lit le rapport JSON de Semgrep
    et transforme chaque résultat dans notre format commun.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = []

    for result in data.get("results", []):
        extra = result.get("extra", {})
        metadata = extra.get("metadata", {})

        check_id = result.get("check_id", "")
        message = extra.get("message", "")

        # Classification personnalisée de la vulnérabilité
        vuln_type, detected_cwe, detected_owasp = classify_semgrep_rule(
            check_id,
            message
        )

        # Normalisation CWE :
        # on utilise notre classification si elle existe,
        # sinon on utilise la valeur fournie par Semgrep.
        cwe = detected_cwe or (
            metadata.get("cwe", [None])[0]
            if metadata.get("cwe")
            else None
        )

        # Normalisation OWASP :
        # on utilise notre classification si elle existe,
        # sinon on utilise la valeur fournie par Semgrep.
        owasp = detected_owasp or (
            metadata.get("owasp", [None])[0]
            if metadata.get("owasp")
            else None
        )

        alert = {
            "tool": "semgrep",
            "rule_id": check_id,
            "vuln_type": vuln_type,
            "severity": extra.get("severity", "UNKNOWN"),
            "cwe": cwe,
            "owasp": owasp,
            "file": result.get("path"),
            "line": result.get("start", {}).get("line"),
            "message": message,
            "language": language_of(result.get("path", "")),
            "impact": metadata.get("impact"),
            "likelihood": metadata.get("likelihood"),
            "confidence": metadata.get("confidence"),
        }

        alerts.append(alert)

    return alerts


def parse_gitleaks(file_path="gitleaks.json"):
    """
    Lit le rapport JSON de Gitleaks
    et transforme chaque secret détecté dans le format commun.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = []

    for result in data:
        alert = {
            "tool": "gitleaks",
            "rule_id": result.get("RuleID"),
            "vuln_type": "Secret Exposure",
            "severity": "HIGH",
            "cwe": None,
            "owasp": None,
            "file": result.get("File"),
            "line": result.get("StartLine"),
            "message": result.get("Description"),
            "language": language_of(result.get("File", "")),
            "impact": None,
            "likelihood": None,
            "confidence": None,
        }

        alerts.append(alert)

    return alerts


def parse_trivy(file_path="trivy.json"):
    """
    Lit le rapport JSON de Trivy
    et transforme les vulnérabilités de dépendances
    dans le format commun.
    """

    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)

    alerts = []

    for result in data.get("Results", []):
        target = result.get("Target", "")
        package_type = result.get("Type", "dependency")

        vulnerabilities = result.get("Vulnerabilities", [])

        for vulnerability in vulnerabilities:
            locations = vulnerability.get("Locations", [])

            line = None

            if locations:
                line = locations[0].get("StartLine")

            alert = {
                "tool": "trivy",
                "rule_id": vulnerability.get("VulnerabilityID"),
                "vuln_type": "Dependency Vulnerability",
                "severity": vulnerability.get("Severity", "UNKNOWN"),
                "cwe": (
                    vulnerability.get("CweIDs", [None])[0]
                    if vulnerability.get("CweIDs")
                    else None
                ),
                "owasp": None,
                "file": target,
                "line": line,
                "message": (
                    vulnerability.get("Description")
                    or vulnerability.get("Title")
                    or "Dependency vulnerability detected"
                ),
                "language": "dependency",
                "impact": None,
                "likelihood": None,
                "confidence": None,
                "package": vulnerability.get("PkgName"),
                "installed_version": vulnerability.get("InstalledVersion"),
                "fixed_version": vulnerability.get("FixedVersion"),
                "package_type": package_type,
            }

            alerts.append(alert)

    return alerts


def parse_all():
    """
    Exécute tous les parsers et rassemble
    les résultats dans une seule liste.
    """

    alerts = []

    alerts.extend(parse_semgrep())
    alerts.extend(parse_gitleaks())
    alerts.extend(parse_trivy())

    return alerts