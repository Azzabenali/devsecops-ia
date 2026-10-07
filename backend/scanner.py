import subprocess
from pathlib import Path


PROJECT_DIR = Path(__file__).resolve().parent.parent
TARGET_DIR = PROJECT_DIR / "demo-app"


def run_command(command):
    """
    Exécute une commande et retourne le résultat.
    """
    result = subprocess.run(
        command,
        cwd=PROJECT_DIR,
        capture_output=True,
        text=True
    )

    return {
        "command": command,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr
    }


def run_semgrep():
    """
    Lance Semgrep sur le projet demo-app.
    """

    return run_command([
        "semgrep",
        "--config",
        "p/python",
        "--json",
        "--output",
        "semgrep.json",
        "demo-app"
    ])


def run_gitleaks():
    """
    Lance Gitleaks sur le projet.
    """

    return run_command([
        "gitleaks",
        "detect",
        "--source",
        "demo-app",
        "--report-format",
        "json",
        "--report-path",
        "gitleaks.json",
        "--no-git"
    ])


def run_trivy():
    return run_command([
        "trivy",
        "fs",
        "--skip-db-update",
        "--scanners", "vuln",
        "--skip-dirs", "./venv",
        "--skip-dirs", "./.venv-wsl",
        "--skip-dirs", "./ml/data/raw/BenchmarkJava",
        "--format", "json",
        "--output", "trivy.json",
        "."
    ])


def run_all_scanners():
    """
    Lance les trois scanners.
    """

    results = {}

    results["semgrep"] = run_semgrep()
    results["gitleaks"] = run_gitleaks()
    results["trivy"] = run_trivy()

    return results