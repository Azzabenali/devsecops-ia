from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier
from xgboost import XGBClassifier


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

DATASET = (
    BASE_DIR
    / "ml"
    / "data"
    / "raw"
    / "python_security_dataset_v3.csv"
)

MODEL_DIR = BASE_DIR / "ml" / "models"
RESULT_DIR = BASE_DIR / "ml" / "data" / "processed"

MODEL_DIR.mkdir(parents=True, exist_ok=True)
RESULT_DIR.mkdir(parents=True, exist_ok=True)


# ============================================================
# CHARGEMENT
# ============================================================

print("=" * 70)
print("ENTRAÎNEMENT DES MODÈLES — PYTHON V3")
print("=" * 70)

print("\nDataset :", DATASET)

df = pd.read_csv(DATASET)

print("Nombre de lignes :", len(df))
print("Nombre de groupes :", df["group_id"].nunique())


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
]

missing = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing:
    raise ValueError(
        f"Colonnes manquantes : {missing}"
    )


print("\nValeurs manquantes :")
print(df[required_columns].isnull().sum())

print("\nDistribution cible :")
print(df["real_vulnerability"].value_counts())

print("\nDistribution par type :")
print(df["vuln_type"].value_counts().sort_index())


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
# VARIABLES
# ============================================================

X = df[
    [
        "text",
        "vuln_type",
        "cwe",
    ]
]

y = df["real_vulnerability"]

groups = df["group_id"]


# ============================================================
# GROUP SHUFFLE SPLIT
# ============================================================

print("\n" + "=" * 70)
print("SPLIT TRAIN / TEST")
print("=" * 70)

splitter = GroupShuffleSplit(
    n_splits=1,
    test_size=0.20,
    random_state=42,
)

train_idx, test_idx = next(
    splitter.split(
        X,
        y,
        groups=groups,
    )
)

X_train = X.iloc[train_idx].copy()
X_test = X.iloc[test_idx].copy()

y_train = y.iloc[train_idx].copy()
y_test = y.iloc[test_idx].copy()

groups_train = groups.iloc[train_idx]
groups_test = groups.iloc[test_idx]

print("Train :", len(X_train))
print("Test  :", len(X_test))

print(
    "Groupes train :",
    groups_train.nunique(),
)

print(
    "Groupes test  :",
    groups_test.nunique(),
)


# ============================================================
# VÉRIFICATION FUITE DE GROUPES
# ============================================================

common_groups = set(
    groups_train
).intersection(
    set(groups_test)
)

print(
    "Groupes communs :",
    len(common_groups),
)

if len(common_groups) > 0:
    raise RuntimeError(
        "ERREUR : des groupes sont présents "
        "dans train et test !"
    )

print("Aucune fuite de groupes détectée.")


# ============================================================
# VÉRIFICATION DISTRIBUTION
# ============================================================

print("\nDistribution train :")
print(y_train.value_counts())

print("\nDistribution test :")
print(y_test.value_counts())


# ============================================================
# PRÉPROCESSEUR
# ============================================================

print("\n" + "=" * 70)
print("TRANSFORMATION DES DONNÉES")
print("=" * 70)

text_vectorizer = TfidfVectorizer(
    max_features=2000,
    ngram_range=(1, 2),
    min_df=1,
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
            ],
        ),
    ]
)


X_train_transformed = preprocessor.fit_transform(
    X_train
)

X_test_transformed = preprocessor.transform(
    X_test
)


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
        max_depth=8,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
    ),

    "Random Forest": RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=2,
    ),

    "XGBoost": XGBClassifier(
        n_estimators=150,
        max_depth=5,
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

    y_pred = model.predict(
        X_test_transformed
    )

    accuracy = accuracy_score(
        y_test,
        y_pred,
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0,
    )

    cm = confusion_matrix(
        y_test,
        y_pred,
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
            y_pred,
            zero_division=0,
        )
    )

    # --------------------------------------------------------
    # SAUVEGARDE DU MODÈLE
    # --------------------------------------------------------

    filename = (
        name.lower()
        .replace(" ", "_")
        + "_python_v3.joblib"
    )

    model_path = MODEL_DIR / filename

    joblib.dump(
        model,
        model_path,
    )

    print(
        "Modèle sauvegardé :",
        model_path,
    )

    results.append(
        {
            "model": name,
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        }
    )


# ============================================================
# SAUVEGARDE DU PRÉPROCESSEUR
# ============================================================

preprocessor_path = (
    MODEL_DIR
    / "preprocessor_python_v3.joblib"
)

joblib.dump(
    preprocessor,
    preprocessor_path,
)

print(
    "\nPreprocessor sauvegardé :",
    preprocessor_path,
)


# ============================================================
# COMPARAISON
# ============================================================

results_df = pd.DataFrame(
    results
)

results_df = results_df.sort_values(
    by="f1",
    ascending=False,
).reset_index(drop=True)


result_file = (
    RESULT_DIR
    / "model_comparison_python_v3.csv"
)

results_df.to_csv(
    result_file,
    index=False,
)


# ============================================================
# RÉSULTATS FINAUX
# ============================================================

print("\n" + "=" * 70)
print("COMPARAISON FINALE")
print("=" * 70)

print(
    results_df.to_string(
        index=False
    )
)

best = results_df.iloc[0]

print(
    "\nMeilleur modèle selon le F1-score :"
)

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
