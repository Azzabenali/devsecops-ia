import pandas as pd
import numpy as np
import joblib

from pathlib import Path
from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import OneHotEncoder
from sklearn.feature_extraction.text import TfidfVectorizer

from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report
)

from xgboost import XGBClassifier


# ============================================================
# CONFIGURATION
# ============================================================

DATASET = Path(
    "ml/data/processed/ml_dataset_enriched.csv"
)

MODELS_DIR = Path("ml/models")

RESULTS_FILE = Path(
    "ml/data/processed/model_comparison_enriched.csv"
)

RANDOM_STATE = 42


# ============================================================
# CHARGEMENT DU DATASET
# ============================================================

def load_dataset():

    print("=" * 70)
    print("CHARGEMENT DU DATASET ML ENRICHI")
    print("=" * 70)

    df = pd.read_csv(DATASET)

    print(f"Dataset : {DATASET}")
    print(f"Nombre de lignes : {len(df)}")
    print(f"Nombre de tests uniques : {df['test_name'].nunique()}")

    print("\nDistribution de la cible :")
    print(df["real_vulnerability"].value_counts())

    return df


# ============================================================
# PREPARATION DU TEXTE
# ============================================================

def prepare_text(df):

    print("\n" + "=" * 70)
    print("PREPARATION DU TEXTE")
    print("=" * 70)

    # On combine les trois informations textuelles.
    #
    # title       : titre du finding
    # description : explication du scanner
    # code_line   : ligne de code concernée
    #
    # Cela permet au TF-IDF d'exploiter le contexte
    # technique de chaque alerte.

    text = (
        df["title"].fillna("").astype(str)
        + " "
        + df["description"].fillna("").astype(str)
        + " "
        + df["code_line"].fillna("").astype(str)
    )

    print("Colonnes textuelles utilisées :")
    print(" - title")
    print(" - description")
    print(" - code_line")

    return text


# ============================================================
# CREATION DES FEATURES
# ============================================================

def build_features(df_train, df_test):

    print("\n" + "=" * 70)
    print("CREATION DES FEATURES")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. TF-IDF
    # --------------------------------------------------------

    print("\n[1/3] Création du TF-IDF...")

    vectorizer = TfidfVectorizer(
        max_features=3000,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        sublinear_tf=True
    )

    train_text = prepare_text(df_train)
    test_text = prepare_text(df_test)

    X_train_text = vectorizer.fit_transform(train_text)
    X_test_text = vectorizer.transform(test_text)

    print(
        f"Dimensions TF-IDF train : "
        f"{X_train_text.shape}"
    )

    print(
        f"Dimensions TF-IDF test  : "
        f"{X_test_text.shape}"
    )

    # --------------------------------------------------------
    # 2. Encodage vuln_type + CWE
    # --------------------------------------------------------

    print("\n[2/3] Encodage des catégories...")

    encoder = OneHotEncoder(
        handle_unknown="ignore",
        sparse_output=True
    )

    categorical_train = df_train[
        ["vuln_type", "cwe"]
    ]

    categorical_test = df_test[
        ["vuln_type", "cwe"]
    ]

    X_train_cat = encoder.fit_transform(
        categorical_train
    )

    X_test_cat = encoder.transform(
        categorical_test
    )

    print(
        f"Dimensions catégories train : "
        f"{X_train_cat.shape}"
    )

    print(
        f"Dimensions catégories test  : "
        f"{X_test_cat.shape}"
    )

    # --------------------------------------------------------
    # 3. Variable numérique : line
    # --------------------------------------------------------

    print("\n[3/3] Ajout de la ligne du code...")

    line_train = csr_matrix(
        df_train[["line"]].astype(float).values
    )

    line_test = csr_matrix(
        df_test[["line"]].astype(float).values
    )

    # --------------------------------------------------------
    # Combinaison de toutes les features
    # --------------------------------------------------------

    X_train = hstack(
        [
            X_train_text,
            X_train_cat,
            line_train
        ],
        format="csr"
    )

    X_test = hstack(
        [
            X_test_text,
            X_test_cat,
            line_test
        ],
        format="csr"
    )

    print("\nFeatures finales :")
    print(
        f"Train : {X_train.shape}"
    )

    print(
        f"Test  : {X_test.shape}"
    )

    return (
        X_train,
        X_test,
        vectorizer,
        encoder
    )


# ============================================================
# ENTRAINEMENT ET EVALUATION
# ============================================================

def evaluate_model(
    name,
    model,
    X_train,
    X_test,
    y_train,
    y_test
):

    print("\n" + "=" * 70)
    print(f"ENTRAINEMENT : {name}")
    print("=" * 70)

    model.fit(
        X_train,
        y_train
    )

    print("Entraînement terminé.")

    # Prédictions
    y_pred = model.predict(X_test)

    # Métriques
    accuracy = accuracy_score(
        y_test,
        y_pred
    )

    precision = precision_score(
        y_test,
        y_pred,
        zero_division=0
    )

    recall = recall_score(
        y_test,
        y_pred,
        zero_division=0
    )

    f1 = f1_score(
        y_test,
        y_pred,
        zero_division=0
    )

    # Matrice de confusion
    cm = confusion_matrix(
        y_test,
        y_pred
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
            target_names=[
                "False",
                "True"
            ],
            zero_division=0
        )
    )

    return {
        "Model": name,
        "Accuracy": accuracy,
        "Precision": precision,
        "Recall": recall,
        "F1": f1,
        "TN": int(cm[0, 0]),
        "FP": int(cm[0, 1]),
        "FN": int(cm[1, 0]),
        "TP": int(cm[1, 1])
    }, model


# ============================================================
# PROGRAMME PRINCIPAL
# ============================================================

def main():

    print("\n")
    print("=" * 70)
    print("EXPERIMENTATION ML ENRICHIE")
    print("Decision Tree vs XGBoost vs Random Forest")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. Chargement
    # --------------------------------------------------------

    df = load_dataset()

    # --------------------------------------------------------
    # 2. Séparation groupes train/test
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("SEPARATION TRAIN / TEST PAR GROUPE")
    print("=" * 70)

    groups = df["test_name"]

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=RANDOM_STATE
    )

    train_idx, test_idx = next(
        splitter.split(
            df,
            groups=groups
        )
    )

    df_train = df.iloc[train_idx].copy()
    df_test = df.iloc[test_idx].copy()

    print(
        f"Train : {len(df_train)} lignes"
    )

    print(
        f"Test  : {len(df_test)} lignes"
    )

    print(
        f"Tests uniques train : "
        f"{df_train['test_name'].nunique()}"
    )

    print(
        f"Tests uniques test : "
        f"{df_test['test_name'].nunique()}"
    )

    # Vérification très importante :
    # aucun test ne doit être présent
    # simultanément dans train et test.

    common_tests = set(
        df_train["test_name"]
    ).intersection(
        set(df_test["test_name"])
    )

    print(
        f"Tests communs : {len(common_tests)}"
    )

    if len(common_tests) != 0:

        raise RuntimeError(
            "ERREUR : certains test_name sont présents "
            "dans train et test."
        )

    print(
        "\nSplit par groupe validé."
    )

    # --------------------------------------------------------
    # 3. Variables cibles
    # --------------------------------------------------------

    y_train = (
        df_train["real_vulnerability"]
        .astype(int)
        .values
    )

    y_test = (
        df_test["real_vulnerability"]
        .astype(int)
        .values
    )

    # --------------------------------------------------------
    # 4. Création des features
    # --------------------------------------------------------

    (
        X_train,
        X_test,
        vectorizer,
        encoder
    ) = build_features(
        df_train,
        df_test
    )

    # --------------------------------------------------------
    # 5. Création du dossier modèles
    # --------------------------------------------------------

    MODELS_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    # --------------------------------------------------------
    # 6. Définition des modèles
    # --------------------------------------------------------

    models = {

        "Decision Tree":
            DecisionTreeClassifier(
                max_depth=12,
                min_samples_leaf=3,
                random_state=RANDOM_STATE,
                class_weight="balanced"
            ),

        "XGBoost":
            XGBClassifier(
                n_estimators=150,
                max_depth=6,
                learning_rate=0.08,
                subsample=0.8,
                colsample_bytree=0.8,
                min_child_weight=2,
                reg_lambda=1.0,
                random_state=RANDOM_STATE,
                eval_metric="logloss",
                n_jobs=2,
                tree_method="hist"
            ),

        "Random Forest":
            RandomForestClassifier(
                n_estimators=200,
                max_depth=12,
                min_samples_leaf=2,
                random_state=RANDOM_STATE,
                class_weight="balanced",
                n_jobs=2
            )
    }

    # --------------------------------------------------------
    # 7. Entraînement
    # --------------------------------------------------------

    results = []

    trained_models = {}

    for name, model in models.items():

        result, trained_model = evaluate_model(
            name,
            model,
            X_train,
            X_test,
            y_train,
            y_test
        )

        results.append(result)

        trained_models[name] = trained_model

    # --------------------------------------------------------
    # 8. Sauvegarde des modèles
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("SAUVEGARDE DES MODELES")
    print("=" * 70)

    model_paths = {

        "Decision Tree":
            MODELS_DIR / "decision_tree_enriched.joblib",

        "XGBoost":
            MODELS_DIR / "xgboost_enriched.joblib",

        "Random Forest":
            MODELS_DIR / "random_forest_enriched.joblib"
    }

    for name, model in trained_models.items():

        path = model_paths[name]

        joblib.dump(
            model,
            path
        )

        print(
            f"{name} -> {path}"
        )

    # --------------------------------------------------------
    # 9. Sauvegarde du TF-IDF
    # --------------------------------------------------------

    vectorizer_path = (
        MODELS_DIR / "tfidf_vectorizer.joblib"
    )

    joblib.dump(
        vectorizer,
        vectorizer_path
    )

    print(
        f"TF-IDF -> {vectorizer_path}"
    )

    # --------------------------------------------------------
    # 10. Sauvegarde de l'encodeur
    # --------------------------------------------------------

    encoder_path = (
        MODELS_DIR / "categorical_encoder.joblib"
    )

    joblib.dump(
        encoder,
        encoder_path
    )

    print(
        f"Encoder -> {encoder_path}"
    )

    # --------------------------------------------------------
    # 11. Comparaison des modèles
    # --------------------------------------------------------

    results_df = pd.DataFrame(
        results
    )

    results_df = results_df.sort_values(
        by="F1",
        ascending=False
    )

    results_df.to_csv(
        RESULTS_FILE,
        index=False
    )

    # --------------------------------------------------------
    # 12. Résultats finaux
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("COMPARAISON FINALE")
    print("=" * 70)

    print(
        results_df[
            [
                "Model",
                "Accuracy",
                "Precision",
                "Recall",
                "F1"
            ]
        ].to_string(
            index=False
        )
    )

    # --------------------------------------------------------
    # 13. Meilleur modèle
    # --------------------------------------------------------

    best_model = results_df.iloc[0]

    print("\n" + "=" * 70)
    print("MEILLEUR MODELE")
    print("=" * 70)

    print(
        f"Modèle : {best_model['Model']}"
    )

    print(
        f"Accuracy : "
        f"{best_model['Accuracy']:.4f}"
    )

    print(
        f"Precision : "
        f"{best_model['Precision']:.4f}"
    )

    print(
        f"Recall : "
        f"{best_model['Recall']:.4f}"
    )

    print(
        f"F1-score : "
        f"{best_model['F1']:.4f}"
    )

    print("\nFichier des résultats :")
    print(RESULTS_FILE)

    print("\nExpérimentation terminée avec succès.")


# ============================================================
# POINT D'ENTREE
# ============================================================

if __name__ == "__main__":
    main()
