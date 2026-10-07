import joblib
import pandas as pd

from pathlib import Path
import sys
from scipy.sparse import hstack, csr_matrix


# ============================================================
# Chemins
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent
sys.path.insert(0, str(PROJECT_DIR))

MODELS_DIR = BASE_DIR / "models"

MODEL_PATH = MODELS_DIR / "xgboost_enriched.joblib"
TFIDF_PATH = MODELS_DIR / "tfidf_vectorizer.joblib"
ENCODER_PATH = MODELS_DIR / "categorical_encoder.joblib"


# ============================================================
# Chargement des modèles
# ============================================================

model = joblib.load(MODEL_PATH)
tfidf = joblib.load(TFIDF_PATH)
encoder = joblib.load(ENCODER_PATH)


# ============================================================
# Normalisation du type de vulnérabilité
# ============================================================

VULN_TYPE_MAPPING = {
    "SQL Injection": "sqli",
    "Cross-Site-Scripting (XSS)": "xss",
    "Command Injection": "cmdi",
    "Path Traversal": "pathtraver",
    "Weak Cryptography": "crypto",
    "Weak Hash": "hash",
}


def normalize_vuln_type(vuln_type):
    """
    Convertit le type produit par le parser
    vers le format utilisé pendant l'entraînement.
    """

    if not vuln_type:
        return ""

    return VULN_TYPE_MAPPING.get(
        vuln_type,
        vuln_type.lower()
    )


# ============================================================
# Récupération de la ligne de code
# ============================================================

def get_code_line(file_path, line_number):
    """
    Récupère la ligne de code correspondant
    à l'alerte.
    """

    path = PROJECT_DIR / file_path

    if not path.exists():
        return ""

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        index = int(line_number) - 1

        if 0 <= index < len(lines):
            return lines[index].strip()

    except Exception:
        pass

    return ""


# ============================================================
# Prédiction
# ============================================================

def predict_vulnerability(alert: dict) -> dict:

    # --------------------------------------------------------
    # Récupération des données du parser
    # --------------------------------------------------------

    original_vuln_type = alert.get(
        "vuln_type",
        ""
    )

    vuln_type = normalize_vuln_type(
        original_vuln_type
    )

    cwe = alert.get(
        "cwe",
        ""
    )

    line = alert.get(
        "line",
        0
    )

    message = alert.get(
        "message",
        ""
    )

    file_path = alert.get(
        "file",
        ""
    )

    # --------------------------------------------------------
    # Conversion ligne
    # --------------------------------------------------------

    try:
        line = float(line)

    except (TypeError, ValueError):
        line = 0.0

    # --------------------------------------------------------
    # Récupération du vrai code source
    # --------------------------------------------------------

    code_line = get_code_line(
        file_path,
        line
    )

    # --------------------------------------------------------
    # Construction du texte
    #
    # Pendant l'entraînement :
    # title + description + code_line
    #
    # Ici :
    # vuln_type + message + code_line
    # --------------------------------------------------------

    title = original_vuln_type
    description = message

    text = (
        str(title)
        + " "
        + str(description)
        + " "
        + str(code_line)
    )

    text_df = pd.Series([text])

    # --------------------------------------------------------
    # TF-IDF
    # --------------------------------------------------------

    X_text = tfidf.transform(
        text_df
    )

    # --------------------------------------------------------
    # Encodage vuln_type + CWE
    # --------------------------------------------------------

    categorical_df = pd.DataFrame(
        [
            {
                "vuln_type": vuln_type,
                "cwe": cwe,
            }
        ]
    )

    X_categorical = encoder.transform(
        categorical_df
    )

    # --------------------------------------------------------
    # Ligne
    # --------------------------------------------------------

    X_line = csr_matrix(
        [[line]]
    )

    # --------------------------------------------------------
    # Combinaison
    # --------------------------------------------------------

    X = hstack(
        [
            X_text,
            X_categorical,
            X_line,
        ]
    )

    # --------------------------------------------------------
    # Prédiction
    # --------------------------------------------------------

    prediction = int(
        model.predict(X)[0]
    )

    probability = float(
        model.predict_proba(X)[0][1]
    )

    # --------------------------------------------------------
    # Priorité
    # --------------------------------------------------------

    if probability >= 0.80:
        priority = "CRITIQUE"

    elif probability >= 0.60:
        priority = "ÉLEVÉE"

    elif probability >= 0.40:
        priority = "MOYENNE"

    else:
        priority = "FAIBLE"

    return {
        "prediction": prediction,
        "probability": round(
            probability,
            4
        ),
        "probability_percent": round(
            probability * 100,
            2
        ),
        "priority": priority,
        "vuln_type_model": vuln_type,
        "code_line": code_line,
    }


# ============================================================
# Test avec les vraies alertes
# ============================================================

if __name__ == "__main__":

    from backend.parsers import parse_all

    alerts = parse_all()

    print()
    print("=" * 70)
    print("TEST XGBOOST SUR LES ALERTES RÉELLES")
    print("=" * 70)

    print(
        f"Nombre d'alertes : {len(alerts)}"
    )

    print()

    for i, alert in enumerate(
        alerts,
        start=1
    ):

        result = predict_vulnerability(
            alert
        )

        print(
            f"[{i}] "
            f"{alert.get('vuln_type')} "
            f"| CWE {alert.get('cwe')} "
            f"| ligne {alert.get('line')}"
        )

        print(
            f"    Type ML       : "
            f"{result['vuln_type_model']}"
        )

        print(
            f"    Prédiction     : "
            f"{result['prediction']}"
        )

        print(
            f"    Probabilité    : "
            f"{result['probability_percent']} %"
        )

        print(
            f"    Priorité       : "
            f"{result['priority']}"
        )

        print(
            f"    Code           : "
            f"{result['code_line']}"
        )

        print("-" * 70)