from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import GroupShuffleSplit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

from xgboost import XGBClassifier


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent

DATASET = BASE_DIR / "ml" / "data" / "processed" / "ml_dataset_enriched.csv"
MODELS_DIR = BASE_DIR / "ml" / "models"

MODELS_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# CHARGEMENT DATASET
# ============================================================

print("=" * 70)
print("CHARGEMENT DU DATASET")
print("=" * 70)

df = pd.read_csv(DATASET)

print(f"Dataset : {DATASET}")
print(f"Nombre de lignes : {len(df)}")
print(f"Colonnes : {list(df.columns)}")

# Supprimer les lignes sans label
df = df.dropna(subset=["real_vulnerability"])

# Label en entier
df["real_vulnerability"] = (
    df["real_vulnerability"]
    .astype(int)
)

# Nettoyage des colonnes texte
text_columns = [
    "title",
    "description",
    "code_line"
]

for column in text_columns:
    df[column] = (
        df[column]
        .fillna("")
        .astype(str)
    )

# Colonnes catégorielles
categorical_columns = [
    "vuln_type",
    "cwe"
]

for column in categorical_columns:
    df[column] = (
        df[column]
        .fillna("UNKNOWN")
        .astype(str)
    )

# Ligne
df["line"] = pd.to_numeric(
    df["line"],
    errors="coerce"
).fillna(0)


# ============================================================
# CONSTRUCTION DU TEXTE
# ============================================================

df["combined_text"] = (
    df["title"] + " " +
    df["description"] + " " +
    df["code_line"]
)

X = df[
    [
        "combined_text",
        "vuln_type",
        "cwe",
        "line"
    ]
]

y = df["real_vulnerability"]


# ============================================================
# SPLIT PAR GROUPE
# ============================================================

print()
print("=" * 70)
print("SPLIT TRAIN / TEST")
print("=" * 70)

groups = df["test_name"].astype(str)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42
)

train_idx, test_idx = next(
    splitter.split(
        X,
        y,
        groups=groups
    )
)

X_train = X.iloc[train_idx].copy()
X_test = X.iloc[test_idx].copy()

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

groups_train = groups.iloc[train_idx]
groups_test = groups.iloc[test_idx]

print(f"Train : {len(X_train)}")
print(f"Test  : {len(X_test)}")

print(
    f"Groupes train : {groups_train.nunique()}"
)

print(
    f"Groupes test  : {groups_test.nunique()}"
)

common_groups = (
    set(groups_train)
    .intersection(set(groups_test))
)

print(
    f"Groupes communs : {len(common_groups)}"
)


# ============================================================
# TF-IDF
# ============================================================

print()
print("=" * 70)
print("TF-IDF")
print("=" * 70)

tfidf = TfidfVectorizer(
    max_features=5000,
    ngram_range=(1, 2),
    lowercase=True,
    strip_accents="unicode"
)

X_train_text = tfidf.fit_transform(
    X_train["combined_text"]
)

X_test_text = tfidf.transform(
    X_test["combined_text"]
)

print(
    f"Nombre de features TF-IDF : "
    f"{X_train_text.shape[1]}"
)


# ============================================================
# ENCODAGE CATEGORIEL
# ============================================================

print()
print("=" * 70)
print("ENCODAGE CATEGORIEL")
print("=" * 70)

encoder = OneHotEncoder(
    handle_unknown="ignore",
    sparse_output=False
)

X_train_cat = encoder.fit_transform(
    X_train[
        [
            "vuln_type",
            "cwe"
        ]
    ]
)

X_test_cat = encoder.transform(
    X_test[
        [
            "vuln_type",
            "cwe"
        ]
    ]
)

print(
    f"Features catégorielles : "
    f"{X_train_cat.shape[1]}"
)


# ============================================================
# FEATURE NUMERIQUE
# ============================================================

X_train_line = X_train[
    ["line"]
].values

X_test_line = X_test[
    ["line"]
].values


# ============================================================
# COMBINAISON DES FEATURES
# ============================================================

X_train_final = np.hstack(
    [
        X_train_text.toarray(),
        X_train_cat,
        X_train_line
    ]
)

X_test_final = np.hstack(
    [
        X_test_text.toarray(),
        X_test_cat,
        X_test_line
    ]
)

print()
print(
    f"Shape X_train final : {X_train_final.shape}"
)

print(
    f"Shape X_test final  : {X_test_final.shape}"
)


# ============================================================
# FONCTION EVALUATION
# ============================================================

def evaluate_model(name, model):

    print()
    print("-" * 70)
    print(f"ENTRAINEMENT : {name}")
    print("-" * 70)

    model.fit(
        X_train_final,
        y_train
    )

    predictions = model.predict(
        X_test_final
    )

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0
    )

    print(f"Accuracy  : {accuracy:.6f}")
    print(f"Precision : {precision:.6f}")
    print(f"Recall    : {recall:.6f}")
    print(f"F1-score  : {f1:.6f}")

    print()
    print("Matrice de confusion :")
    print(
        confusion_matrix(
            y_test,
            predictions
        )
    )

    return {
        "model": name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "trained_model": model
    }


# ============================================================
# 1. DECISION TREE
# ============================================================

decision_tree = DecisionTreeClassifier(
    random_state=42,
    max_depth=20,
    min_samples_split=5
)

result_dt = evaluate_model(
    "Decision Tree",
    decision_tree
)


# ============================================================
# 2. XGBOOST
# ============================================================

xgboost_model = XGBClassifier(
    n_estimators=250,
    max_depth=6,
    learning_rate=0.08,
    subsample=0.9,
    colsample_bytree=0.9,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    n_jobs=2
)

result_xgb = evaluate_model(
    "XGBoost",
    xgboost_model
)


# ============================================================
# 3. RANDOM FOREST
# ============================================================

random_forest = RandomForestClassifier(
    n_estimators=200,
    max_depth=20,
    min_samples_split=5,
    random_state=42,
    n_jobs=2
)

result_rf = evaluate_model(
    "Random Forest",
    random_forest
)


# ============================================================
# COMPARAISON
# ============================================================

results = [
    result_dt,
    result_xgb,
    result_rf
]

comparison = pd.DataFrame(
    [
        {
            "Model": result["model"],
            "Accuracy": result["accuracy"],
            "Precision": result["precision"],
            "Recall": result["recall"],
            "F1": result["f1"]
        }
        for result in results
    ]
)

print()
print("=" * 70)
print("COMPARAISON DES MODELES")
print("=" * 70)

print(
    comparison.to_string(
        index=False,
        float_format=lambda x: f"{x:.6f}"
    )
)


# ============================================================
# SAUVEGARDE DES MODELES
# ============================================================

print()
print("=" * 70)
print("SAUVEGARDE")
print("=" * 70)

# Modèle XGBoost utilisé par FastAPI
xgb_path = MODELS_DIR / "xgboost_enriched.joblib"

joblib.dump(
    xgboost_model,
    xgb_path
)

print(
    f"XGBoost sauvegardé : {xgb_path}"
)


# TF-IDF utilisé par le predictor
tfidf_path = MODELS_DIR / "tfidf_vectorizer.joblib"

joblib.dump(
    tfidf,
    tfidf_path
)

print(
    f"TF-IDF sauvegardé : {tfidf_path}"
)


# Encodeur catégoriel
encoder_path = MODELS_DIR / "categorical_encoder.joblib"

joblib.dump(
    encoder,
    encoder_path
)

print(
    f"Encoder sauvegardé : {encoder_path}"
)


# ============================================================
# SAUVEGARDE DES AUTRES MODELES
# ============================================================

joblib.dump(
    decision_tree,
    MODELS_DIR / "decision_tree_enriched.joblib"
)

joblib.dump(
    random_forest,
    MODELS_DIR / "random_forest_enriched.joblib"
)

# Sauvegarde du tableau de comparaison
comparison.to_csv(
    MODELS_DIR / "model_comparison.csv",
    index=False
)

print()
print("Autres fichiers sauvegardés :")
print(" - decision_tree_enriched.joblib")
print(" - random_forest_enriched.joblib")
print(" - model_comparison.csv")


# ============================================================
# FIN
# ============================================================

print()
print("=" * 70)
print("ENTRAINEMENT TERMINE")
print("=" * 70)

print()
print("Fichiers nécessaires au backend :")

print(
    f"✓ {xgb_path}"
)

print(
    f"✓ {tfidf_path}"
)

print(
    f"✓ {encoder_path}"
)

print()
print("XGBoost est maintenant prêt pour FastAPI.")