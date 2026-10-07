from pathlib import Path
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import GroupShuffleSplit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
)
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier


# ============================================================
# CHEMINS
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATASET = (
    BASE_DIR
    / "ml"
    / "data"
    / "raw"
    / "python_security_dataset_v2.csv"
)

MODEL_DIR = BASE_DIR / "ml" / "models"
RESULT_DIR = BASE_DIR / "ml" / "data" / "processed"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# CHARGEMENT
# ============================================================

print("=" * 70)
print("ENTRAÎNEMENT DES MODÈLES — PYTHON V2")
print("=" * 70)

df = pd.read_csv(DATASET)

print("\nDataset chargé :", DATASET)
print("Nombre de lignes :", len(df))

print("\nColonnes :")
print(df.columns.tolist())


# ============================================================
# VÉRIFICATIONS
# ============================================================

required_columns = [
    "group_id",
    "vuln_type",
    "cwe",
    "title",
    "description",
    "code_line",
    "real_vulnerability",
    "language",
    "file_type",
]

missing = [
    col for col in required_columns
    if col not in df.columns
]

if missing:
    raise ValueError(
        f"Colonnes manquantes : {missing}"
    )

print("\nValeurs manquantes :")
print(df[required_columns].isnull().sum())

print("\nDistribution cible :")
print(df["real_vulnerability"].value_counts())

print("\nNombre de groupes :", df["group_id"].nunique())


# ============================================================
# CONSTRUCTION DU TEXTE
# ============================================================

df["text"] = (
    df["title"].fillna("")
    + " "
    + df["description"].fillna("")
    + " "
    + df["code_line"].fillna("")
)


# ============================================================
# TRAIN / TEST PAR GROUPE
# ============================================================

X = df[
    [
        "text",
        "vuln_type",
        "cwe",
        "language",
        "file_type",
    ]
]

y = df["real_vulnerability"].astype(int)

groups = df["group_id"]


splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(X, y, groups)
)


X_train = X.iloc[train_idx].copy()
X_test = X.iloc[test_idx].copy()

y_train = y.iloc[train_idx]
y_test = y.iloc[test_idx]

groups_train = groups.iloc[train_idx]
groups_test = groups.iloc[test_idx]


print("\n" + "=" * 70)
print("SPLIT TRAIN / TEST")
print("=" * 70)

print("Train :", len(X_train))
print("Test  :", len(X_test))

print("Groupes train :", groups_train.nunique())
print("Groupes test  :", groups_test.nunique())

common_groups = set(groups_train) & set(groups_test)

print("Groupes communs :", len(common_groups))

if common_groups:
    raise ValueError(
        "ERREUR : fuite de données entre train et test !"
    )


# ============================================================
# PRÉTRAITEMENT
# ============================================================

text_vectorizer = TfidfVectorizer(
    max_features=3000,
    ngram_range=(1, 2),
    min_df=1,
    max_df=0.95,
    sublinear_tf=True,
)

categorical_encoder = OneHotEncoder(
    handle_unknown="ignore",
)

preprocessor = ColumnTransformer(
    transformers=[
        (
            "text",
            text_vectorizer,
            "text",
        ),
        (
            "categorical",
            categorical_encoder,
            [
                "vuln_type",
                "cwe",
                "language",
                "file_type",
            ],
        ),
    ]
)


# ============================================================
# TRANSFORMATION
# ============================================================

print("\nTransformation des données...")

X_train_transformed = preprocessor.fit_transform(X_train)
X_test_transformed = preprocessor.transform(X_test)

print(
    "Dimensions train :",
    X_train_transformed.shape,
)

print(
    "Dimensions test  :",
    X_test_transformed.shape,
)


# ============================================================
# MODÈLES
# ============================================================

models = {

    "Decision Tree": DecisionTreeClassifier(
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=2,
    ),

    "XGBoost": XGBClassifier(
        n_estimators=150,
        max_depth=6,
        learning_rate=0.08,
        subsample=0.8,
        colsample_bytree=0.8,
        min_child_weight=2,
        reg_lambda=1,
        random_state=42,
        eval_metric="logloss",
        n_jobs=2,
        tree_method="hist",
    ),
}


# ============================================================
# ENTRAÎNEMENT
# ============================================================

results = []


for name, model in models.items():

    print("\n" + "=" * 70)
    print(f"MODÈLE : {name}")
    print("=" * 70)

    model.fit(
        X_train_transformed,
        y_train,
    )

    predictions = model.predict(
        X_test_transformed
    )

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    precision = precision_score(
        y_test,
        predictions,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        predictions,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        predictions,
        zero_division=0,
    )

    cm = confusion_matrix(
        y_test,
        predictions,
    )

    print("\nRésultats :")

    print(
        f"Accuracy  : {accuracy:.4f}"
    )

    print(
        f"Precision : {precision:.4f}"
    )

    print(
        f"Recall    : {recall:.4f}"
    )

    print(
        f"F1-score  : {f1:.4f}"
    )

    print("\nMatrice de confusion :")
    print(cm)

    print("\nClassification report :")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    results.append({
        "model": name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    })

    # ========================================================
    # SAUVEGARDE DU MODÈLE
    # ========================================================

    filename = (
        name.lower()
        .replace(" ", "_")
        + "_python_v2.joblib"
    )

    output_model = MODEL_DIR / filename

    joblib.dump(
        model,
        output_model,
    )

    print(
        f"Modèle sauvegardé : {output_model}"
    )


# ============================================================
# SAUVEGARDE DU PREPROCESSOR
# ============================================================

preprocessor_file = (
    MODEL_DIR
    / "preprocessor_python_v2.joblib"
)

joblib.dump(
    preprocessor,
    preprocessor_file,
)

print(
    "\nPreprocessor sauvegardé :",
    preprocessor_file,
)


# ============================================================
# COMPARAISON
# ============================================================

results_df = pd.DataFrame(results)

results_df = results_df.sort_values(
    by="f1",
    ascending=False,
)

result_file = (
    RESULT_DIR
    / "model_comparison_python_v2.csv"
)

results_df.to_csv(
    result_file,
    index=False,
)


# ============================================================
# AFFICHAGE FINAL
# ============================================================

print("\n" + "=" * 70)
print("COMPARAISON FINALE")
print("=" * 70)

print(
    results_df.to_string(
        index=False
    )
)

print("\nMeilleur modèle selon le F1-score :")

best = results_df.iloc[0]

print(
    f"  {best['model']}"
)

print(
    f"  F1 = {best['f1']:.4f}"
)

print(
    f"\nRésultats sauvegardés : {result_file}"
)

print("\nEntraînement terminé.")