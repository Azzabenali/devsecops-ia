from pathlib import Path
import sys
import joblib
import pandas as pd


# ============================================================
# Chemins du projet
# ============================================================

BASE_DIR = Path(__file__).resolve().parent
PROJECT_DIR = BASE_DIR.parent

MODEL_DIR = PROJECT_DIR / "ml" / "models"

MODEL_PATH = MODEL_DIR / "xgboost_enriched.joblib"
TFIDF_PATH = MODEL_DIR / "tfidf_vectorizer.joblib"
ENCODER_PATH = MODEL_DIR / "categorical_encoder.joblib"


# ============================================================
# Chargement des modèles
# ============================================================

model = joblib.load(MODEL_PATH)
tfidf = joblib.load(TFIDF_PATH)
encoder = joblib.load(ENCODER_PATH)


# ============================================================
# Correspondance entre les types du scanner et OWASP
# ============================================================

VULN_TYPE_MAPPING = {
    "SQL Injection": "sqli",
    "Cross-Site-Scripting (XSS)": "xss",
    "Cross-Site-Scripting": "xss",
    "Command Injection": "cmdi",
    "Path Traversal": "pathtraver",
    "Weak Cryptography": "crypto",
    "Weak Hash": "hash",
}


# ============================================================
# Calcul de la priorité
# ============================================================

def get_priority(probability):

    if probability >= 0.80:
        return "CRITIQUE"

    elif probability >= 0.60:
        return "ÉLEVÉE"

    elif probability >= 0.40:
        return "MOYENNE"

    else:
        return "FAIBLE"


# ============================================================
# Prédiction pour une vulnérabilité
# ============================================================

def predict_alert(alert):

    vuln_type = alert.get("vuln_type", "")
    cwe = alert.get("cwe", "")
    line = alert.get("line", 0)

    # Correspondance avec les catégories du dataset OWASP
    ml_type = VULN_TYPE_MAPPING.get(vuln_type)

    if ml_type is None:
        ml_type = vuln_type.lower().replace(" ", "_")

    # Texte utilisé par le modèle
    title = vuln_type

    description = alert.get("message", "")

    code_line = ""

    file_path = alert.get("file")

    if file_path and line:

        path = Path(file_path)

        if not path.is_absolute():
            path = PROJECT_DIR / path

        try:
            lines = path.read_text(
                encoding="utf-8"
            ).splitlines()

            if 1 <= int(line) <= len(lines):
                code_line = lines[int(line) - 1]

        except Exception:
            code_line = ""

    text = (
        str(title)
        + " "
        + str(description)
        + " "
        + str(code_line)
    )

    # TF-IDF
    text_features = tfidf.transform([text])

    # Variables catégorielles
    categorical = pd.DataFrame(
        [{
            "vuln_type": ml_type,
            "cwe": cwe
        }]
    )

    categorical_features = encoder.transform(categorical)

    # Ligne du code
    line_feature = [[float(line or 0)]]

    # Assemblage des caractéristiques
    from scipy.sparse import hstack

    features = hstack([
        text_features,
        categorical_features,
        line_feature
    ])

    # Prédiction
    prediction = int(model.predict(features)[0])

    probability = float(
        model.predict_proba(features)[0][1]
    )

    priority = get_priority(probability)

    return {
        "ml_prediction": prediction,
        "ml_probability": round(probability, 4),
        "ml_priority": priority
    }
