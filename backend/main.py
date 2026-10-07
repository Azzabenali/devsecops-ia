
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from backend.database import (
    get_connection,
    insert_alerts,
    insert_gemini_analysis,
    get_gemini_analysis
)
from backend.scanner import run_all_scanners
from backend.parsers import parse_all
from backend.ml_predictor import predict_alert
from backend.gemini_analyzer import analyze_vulnerability
from pathlib import Path
from datetime import datetime
import os


app = FastAPI(
    title="DevSecOps IA",
    description="API de gestion des vulnérabilités détectées par les outils de sécurité",
    version="1.0.0"
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# Accueil
# ============================================================

@app.get("/")
def root():
    return {
        "message": "API DevSecOps IA fonctionne"
    }


# ============================================================
# Liste de toutes les vulnérabilités
# ============================================================

@app.get("/vulnerabilities")
def get_vulnerabilities():

    connection = get_connection()

    rows = connection.execute(
        """
        SELECT
            id,
            scan_id,
            tool,
            rule_id,
            vuln_type,
            severity,
            cwe,
            owasp,
            file,
            line,
            message,
            language,
            impact,
            likelihood,
            confidence,
            package,
            installed_version,
            fixed_version,
            package_type,
            ml_prediction,
            ml_probability,
            ml_priority
        FROM vulnerabilities
        ORDER BY id
        """
    ).fetchall()

    connection.close()

    return [dict(row) for row in rows]


# ============================================================
# Récupérer une vulnérabilité + extrait du code
# ============================================================

@app.get("/vulnerabilities/{vulnerability_id}")
def get_vulnerability(vulnerability_id: int):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT
            id,
            scan_id,
            tool,
            rule_id,
            vuln_type,
            severity,
            cwe,
            owasp,
            file,
            line,
            message,
            language,
            impact,
            likelihood,
            confidence,
            package,
            installed_version,
            fixed_version,
            package_type,
            ml_prediction,
            ml_probability,
            ml_priority
        FROM vulnerabilities
        WHERE id = ?
        """,
        (vulnerability_id,)
    ).fetchone()

    connection.close()

    if row is None:
        return {
            "error": "Vulnerability not found"
        }

    vulnerability = dict(row)

    if vulnerability["file"] and vulnerability["line"]:

        vulnerability["code_excerpt"] = get_code_excerpt(
            vulnerability["file"],
            vulnerability["line"]
        )

    else:

        vulnerability["code_excerpt"] = {
            "error": "Extrait de code indisponible",
            "lines": []
        }

    return vulnerability


# ============================================================
# Extrait du code autour d'une ligne
# ============================================================

def get_code_excerpt(file_path, line_number, context=3):

    path = Path(file_path)

    if not path.exists():
        return {
            "error": "Fichier introuvable",
            "lines": []
        }

    try:
        lines = path.read_text(
            encoding="utf-8"
        ).splitlines()

    except Exception as error:
        return {
            "error": f"Impossible de lire le fichier : {error}",
            "lines": []
        }

    start = max(1, line_number - context)
    end = min(len(lines), line_number + context)

    excerpt = []

    for number in range(start, end + 1):

        excerpt.append({
            "line": number,
            "code": lines[number - 1],
            "vulnerable": number == line_number
        })

    return {
        "start_line": start,
        "end_line": end,
        "lines": excerpt
    }


# ============================================================
# Lancer un scan
# ============================================================

@app.post("/scan")
def launch_scan():

    # 1. Heure de début
    started_at = datetime.now().isoformat()

    # 2. Lancer les scanners
    scanner_results = run_all_scanners()

    # 3. Vérifier les erreurs
    errors = {}

    for tool, result in scanner_results.items():

        if result["returncode"] != 0:
            errors[tool] = result["stderr"]

    # 4. Si un scanner échoue
    if errors:

        connection = get_connection()

        connection.execute(
            """
            INSERT INTO scans (
                project,
                started_at,
                finished_at,
                status,
                total_alerts
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "demo-app",
                started_at,
                datetime.now().isoformat(),
                "error",
                0
            )
        )

        connection.commit()
        connection.close()

        return {
            "status": "error",
            "errors": errors
        }

    # 5. Parser les résultats
        # 5. Parser les résultats
    alerts = parse_all()

    # 6. Appliquer le modèle XGBoost
    for alert in alerts:
        try:
            ml_result = predict_alert(alert)

            alert["ml_prediction"] = ml_result["ml_prediction"]
            alert["ml_probability"] = ml_result["ml_probability"]
            alert["ml_priority"] = ml_result["ml_priority"]

        except Exception as e:
            print(
                f"Erreur ML pour {alert.get('vuln_type')}: {e}"
            )

            alert["ml_prediction"] = None
            alert["ml_probability"] = None
            alert["ml_priority"] = None

    # 7. Créer un nouvel enregistrement de scan
    connection = get_connection()
    cursor = connection.execute(
        """
        INSERT INTO scans (
            project,
            started_at,
            finished_at,
            status,
            total_alerts
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            "demo-app",
            started_at,
            datetime.now().isoformat(),
            "success",
            len(alerts)
        )
    )

    scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    # 8. Enregistrer les vulnérabilités
    #    avec les résultats ML
    insert_alerts(alerts, scan_id)

    # 9. Réponse
    return {
        "status": "success",
        "message": "Scan terminé avec succès",
        "scan_id": scan_id,
        "total_alerts": len(alerts),
        "scanners": {
            "semgrep": len(
                [a for a in alerts if a["tool"] == "semgrep"]
            ),
            "gitleaks": len(
                [a for a in alerts if a["tool"] == "gitleaks"]
            ),
            "trivy": len(
                [a for a in alerts if a["tool"] == "trivy"]
            )
        }
    }


# ============================================================
# Historique des scans
# ============================================================

@app.get("/scans")
def get_scans():

    connection = get_connection()

    scans = connection.execute(
        """
        SELECT
            id,
            project,
            started_at,
            finished_at,
            status,
            total_alerts
        FROM scans
        ORDER BY id DESC
        """
    ).fetchall()

    connection.close()

    return [dict(scan) for scan in scans]
# ============================================================
# Analyse d'une vulnérabilité avec Gemini
# ============================================================

@app.post("/analysis/{vulnerability_id}")
def analyze_with_gemini(vulnerability_id: int):

    connection = get_connection()

    row = connection.execute(
        """
        SELECT
            id,
            scan_id,
            tool,
            rule_id,
            vuln_type,
            severity,
            cwe,
            owasp,
            file,
            line,
            message,
            language,
            impact,
            likelihood,
            confidence,
            package,
            installed_version,
            fixed_version,
            package_type,
            ml_prediction,
            ml_probability,
            ml_priority
        FROM vulnerabilities
        WHERE id = ?
        """,
        (vulnerability_id,)
    ).fetchone()

    connection.close()

    if row is None:
        return {
            "status": "error",
            "message": "Vulnérabilité introuvable"
        }

    vulnerability = dict(row)

    # Ajouter l'extrait de code à envoyer à Gemini
    if vulnerability["file"] and vulnerability["line"]:
        code_excerpt = get_code_excerpt(
            vulnerability["file"],
            vulnerability["line"]
        )

        vulnerability["code_line"] = "\n".join(
            line["code"]
            for line in code_excerpt.get("lines", [])
        )

    # Appel Gemini
    analysis = analyze_vulnerability(vulnerability)

    status = analysis.get("status", "success")

    # Sauvegarde de l'analyse
    analysis_id = insert_gemini_analysis(
        vulnerability_id=vulnerability_id,
        model=os.getenv("GEMINI_MODEL", ""),
        analysis=analysis,
        status=status
    )

    return {
        "status": status,
        "analysis_id": analysis_id,
        "vulnerability_id": vulnerability_id,
        "model": os.getenv("GEMINI_MODEL", ""),
        "analysis": analysis
    }


# ============================================================
# Récupérer la dernière analyse Gemini
# ============================================================

@app.get("/analysis/{vulnerability_id}")
def get_analysis(vulnerability_id: int):

    analysis = get_gemini_analysis(vulnerability_id)

    if analysis is None:
        return {
            "status": "not_found",
            "message": "Aucune analyse Gemini trouvée"
        }

    return analysis
# ============================================================
# Rescan d'un scan existant + comparaison
# ============================================================

@app.post("/rescan/{scan_id}")
def rescan(scan_id: int):

    # 1. Vérifier que le scan existe
    connection = get_connection()

    old_scan = connection.execute(
        """
        SELECT id, project, total_alerts
        FROM scans
        WHERE id = ?
        """,
        (scan_id,)
    ).fetchone()

    connection.close()

    if old_scan is None:
        return {
            "status": "error",
            "message": "Scan introuvable"
        }

    # 2. Lancer les scanners
    started_at = datetime.now().isoformat()

    scanner_results = run_all_scanners()

    # 3. Vérifier les erreurs
    errors = {}

    for tool, result in scanner_results.items():

        if result["returncode"] != 0:
            errors[tool] = result["stderr"]

    if errors:

        connection = get_connection()

        connection.execute(
            """
            INSERT INTO scans (
                project,
                started_at,
                finished_at,
                status,
                total_alerts
            )
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                old_scan["project"],
                started_at,
                datetime.now().isoformat(),
                "error",
                0
            )
        )

        connection.commit()
        connection.close()

        return {
            "status": "error",
            "errors": errors
        }

    # 4. Parser les nouveaux résultats
    alerts = parse_all()

    # 5. Appliquer XGBoost
    for alert in alerts:

        try:

            ml_result = predict_alert(alert)

            alert["ml_prediction"] = ml_result["ml_prediction"]
            alert["ml_probability"] = ml_result["ml_probability"]
            alert["ml_priority"] = ml_result["ml_priority"]

        except Exception as e:

            print(
                f"Erreur ML pour {alert.get('vuln_type')}: {e}"
            )

            alert["ml_prediction"] = None
            alert["ml_probability"] = None
            alert["ml_priority"] = None

    # 6. Créer le nouveau scan
    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO scans (
            project,
            started_at,
            finished_at,
            status,
            total_alerts
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            old_scan["project"],
            started_at,
            datetime.now().isoformat(),
            "success",
            len(alerts)
        )
    )

    new_scan_id = cursor.lastrowid

    connection.commit()
    connection.close()

    # 7. Enregistrer les nouvelles vulnérabilités
    insert_alerts(alerts, new_scan_id)

    # 8. Récupérer les vulnérabilités de l'ancien scan
    connection = get_connection()

    old_vulnerabilities = connection.execute(
        """
        SELECT vuln_type, file, line, cwe
        FROM vulnerabilities
        WHERE scan_id = ?
        """,
        (scan_id,)
    ).fetchall()

    # 9. Récupérer les vulnérabilités du nouveau scan
    new_vulnerabilities = connection.execute(
        """
        SELECT vuln_type, file, line, cwe
        FROM vulnerabilities
        WHERE scan_id = ?
        """,
        (new_scan_id,)
    ).fetchall()

    connection.close()

    # 10. Transformer en ensembles pour comparaison
    old_set = {
        (
            row["vuln_type"],
            row["file"],
            row["line"],
            row["cwe"]
        )
        for row in old_vulnerabilities
    }

    new_set = {
        (
            row["vuln_type"],
            row["file"],
            row["line"],
            row["cwe"]
        )
        for row in new_vulnerabilities
    }

    # 11. Vulnérabilités corrigées
    fixed = old_set - new_set

    # 12. Nouvelles vulnérabilités
    new = new_set - old_set

    # 13. Vulnérabilités toujours présentes
    remaining = old_set & new_set

    # 14. Transformer les tuples en JSON
    def format_vulnerability(item):

        vuln_type, file, line, cwe = item

        return {
            "vuln_type": vuln_type,
            "file": file,
            "line": line,
            "cwe": cwe
        }

    return {
        "status": "success",
        "message": "Rescan terminé avec succès",

        "previous_scan_id": scan_id,
        "new_scan_id": new_scan_id,

        "previous_total": len(old_set),
        "new_total": len(new_set),

        "fixed": [
            format_vulnerability(item)
            for item in fixed
        ],

        "new_vulnerabilities": [
            format_vulnerability(item)
            for item in new
        ],

        "remaining": [
            format_vulnerability(item)
            for item in remaining
        ]
    }