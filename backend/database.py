import sqlite3
from datetime import datetime


DATABASE = "devsecops.db"


def get_connection():
    connection = sqlite3.connect(DATABASE)
    connection.row_factory = sqlite3.Row
    return connection


def create_tables():
    connection = get_connection()

    # ============================================================
    # Table des scans
    # ============================================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            project TEXT NOT NULL,
            started_at TEXT NOT NULL,
            finished_at TEXT,
            status TEXT NOT NULL,
            total_alerts INTEGER DEFAULT 0
        )
    """)

    # ============================================================
    # Table des vulnérabilités
    # ============================================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            tool TEXT NOT NULL,
            rule_id TEXT,
            vuln_type TEXT,
            severity TEXT,
            cwe TEXT,
            owasp TEXT,
            file TEXT,
            line INTEGER,
            message TEXT,
            language TEXT,
            impact TEXT,
            likelihood TEXT,
            confidence TEXT,
            package TEXT,
            installed_version TEXT,
            fixed_version TEXT,
            package_type TEXT,
            ml_prediction INTEGER,
            ml_probability REAL,
            ml_priority TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    """)

    # ============================================================
    # Table des analyses Gemini
    # ============================================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS gemini_analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            vulnerability_id INTEGER NOT NULL,
            model TEXT,
            explanation TEXT,
            impact TEXT,
            cause TEXT,
            recommendation TEXT,
            suggested_fix TEXT,
            status TEXT DEFAULT 'success',
            created_at TEXT NOT NULL,
            FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities(id)
        )
    """)

    connection.commit()
    connection.close()


# ============================================================
# Insérer les vulnérabilités
# ============================================================

def insert_alerts(alerts, scan_id=None):
    connection = get_connection()

    for alert in alerts:
        connection.execute(
            """
            INSERT INTO vulnerabilities (
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
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                alert.get("tool"),
                alert.get("rule_id"),
                alert.get("vuln_type"),
                alert.get("severity"),
                alert.get("cwe"),
                alert.get("owasp"),
                alert.get("file"),
                alert.get("line"),
                alert.get("message"),
                alert.get("language"),
                alert.get("impact"),
                alert.get("likelihood"),
                alert.get("confidence"),
                alert.get("package"),
                alert.get("installed_version"),
                alert.get("fixed_version"),
                alert.get("package_type"),
                alert.get("ml_prediction"),
                alert.get("ml_probability"),
                alert.get("ml_priority"),
            )
        )

    connection.commit()
    connection.close()


# ============================================================
# Insérer une analyse Gemini
# ============================================================

def insert_gemini_analysis(
    vulnerability_id,
    model,
    analysis,
    status="success"
):
    connection = get_connection()

    cursor = connection.execute(
        """
        INSERT INTO gemini_analyses (
            vulnerability_id,
            model,
            explanation,
            impact,
            cause,
            recommendation,
            suggested_fix,
            status,
            created_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            vulnerability_id,
            model,
            analysis.get("explanation", ""),
            analysis.get("impact", ""),
            analysis.get("cause", ""),
            analysis.get("recommendation", ""),
            analysis.get("suggested_fix", ""),
            status,
            datetime.now().isoformat()
        )
    )

    connection.commit()

    analysis_id = cursor.lastrowid

    connection.close()

    return analysis_id


# ============================================================
# Récupérer la dernière analyse Gemini
# ============================================================

def get_gemini_analysis(vulnerability_id):
    connection = get_connection()

    row = connection.execute(
        """
        SELECT
            id,
            vulnerability_id,
            model,
            explanation,
            impact,
            cause,
            recommendation,
            suggested_fix,
            status,
            created_at
        FROM gemini_analyses
        WHERE vulnerability_id = ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (vulnerability_id,)
    ).fetchone()

    connection.close()

    if row is None:
        return None

    return dict(row)