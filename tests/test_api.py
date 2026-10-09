import sys
import sqlite3
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from fastapi.testclient import TestClient

from backend import database
from backend import main

@pytest.fixture
def client(tmp_path, monkeypatch):
    """Utilise une base de données temporaire pour chaque test."""

    db_path = tmp_path / "test_devsecops.db"

    def test_connection():
        connection = sqlite3.connect(str(db_path))
        connection.row_factory = sqlite3.Row
        return connection

    # Rediriger les accès à la base vers le fichier de test
    monkeypatch.setattr(database, "get_connection", test_connection)
    monkeypatch.setattr(main, "get_connection", test_connection)

    # Créer les tables sans toucher à devsecops.db
    database.create_tables()

    with TestClient(main.app) as test_client:
        yield test_client


def test_root_returns_success(client):
    response = client.get("/")

    assert response.status_code == 200
    assert response.json() == {
        "message": "API DevSecOps IA fonctionne"
    }


def test_vulnerabilities_returns_empty_list(client):
    response = client.get("/vulnerabilities")

    assert response.status_code == 200
    assert response.json() == []


def test_unknown_vulnerability_returns_error(client):
    response = client.get("/vulnerabilities/999999")

    assert response.status_code == 200
    assert response.json() == {
        "error": "Vulnerability not found"
    }
    
def test_scans_returns_empty_list(client):
    response = client.get("/scans")

    assert response.status_code == 200
    assert response.json() == []


def test_get_analysis_not_found(client, monkeypatch):
    monkeypatch.setattr(
        main,
        "get_gemini_analysis",
        lambda vulnerability_id: None
    )

    response = client.get("/analysis/999999")

    assert response.status_code == 200
    assert response.json() == {
        "status": "not_found",
        "message": "Aucune analyse Gemini trouvée"
    }


def test_analyze_unknown_vulnerability(client, monkeypatch):
    def fail_if_called(*args, **kwargs):
        pytest.fail("Gemini ne doit pas être appelé")

    monkeypatch.setattr(
        main,
        "analyze_vulnerability",
        fail_if_called
    )

    response = client.post("/analysis/999999")

    assert response.status_code == 200
    assert response.json() == {
        "status": "error",
        "message": "Vulnérabilité introuvable"
    }


def test_rescan_unknown_scan(client, monkeypatch):
    def fail_if_called(*args, **kwargs):
        pytest.fail("Les scanners ne doivent pas être appelés")

    monkeypatch.setattr(
        main,
        "run_all_scanners",
        fail_if_called
    )

    response = client.post("/rescan/999999")

    assert response.status_code == 200
    assert response.json() == {
        "status": "error",
        "message": "Scan introuvable"
    }
