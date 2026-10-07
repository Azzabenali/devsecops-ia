import pandas as pd
import joblib

from pathlib import Path
from scipy.sparse import hstack, csr_matrix

from sklearn.model_selection import GroupShuffleSplit
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import OneHotEncoder
from sklearn.tree import DecisionTreeClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
)

from xgboost import XGBClassifier


DATASET = Path("ml/data/processed/ml_dataset_combined.csv")
MODEL_DIR = Path("ml/models")
RESULTS = Path("ml/data/processed/model_comparison_combined.csv")


def evaluate_model(name, model, X_train, X_test, y_train, y_test):
    print(f"\n{'=' * 60}")
    print(name)
    print("=" * 60)

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    accuracy = accuracy_score(y_test, predictions)
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

    matrix = confusion_matrix(
        y_test,
        predictions
    )

    print(f"Accuracy  : {accuracy:.4f}")
    print(f"Precision : {precision:.4f}")
    print(f"Recall    : {recall:.4f}")
    print(f"F1-score  : {f1:.4f}")

    print("\nMatrice de confusion :")
    print(matrix)

    return {
        "model": name,
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
    }


def main():

    print("=" * 70)
    print("ENTRAINEMENT SUR DATASET OWASP + PYTHON")
    print("=" * 70)

    df = pd.read_csv(DATASET)

    print(f"\nDataset : {len(df)} lignes")
    print(f"Groupes uniques : {df['test_name'].nunique()}")

    # ---------------------------------------------------------
    # Préparation
    # ---------------------------------------------------------

    df["title"] = df["title"].fillna("")
    df["description"] = df["description"].fillna("")
    df["code_line"] = df["code_line"].fillna("")

    df["text"] = (
        df["title"].astype(str)
        + " "
        + df["description"].astype(str)
        + " "
        + df["code_line"].astype(str)
    )

    X_text = df["text"]
    X_cat = df[["vuln_type", "cwe", "language"]]
    X_line = df[["line"]]

    y = df["real_vulnerability"].astype(int)
    groups = df["test_name"]

    # ---------------------------------------------------------
    # Group Split
    # ---------------------------------------------------------

    splitter = GroupShuffleSplit(
        n_splits=1,
        test_size=0.20,
        random_state=42
    )

    train_idx, test_idx = next(
        splitter.split(
            df,
            y,
            groups
        )
    )

    train_df = df.iloc[train_idx]
    test_df = df.iloc[test_idx]

    print("\n" + "=" * 70)
    print("GROUP SPLIT")
    print("=" * 70)

    print(f"Train : {len(train_df)}")
    print(f"Test  : {len(test_df)}")

    train_groups = set(train_df["test_name"])
    test_groups = set(test_df["test_name"])

    print(
        f"Groupes train : {len(train_groups)}"
    )

    print(
        f"Groupes test  : {len(test_groups)}"
    )

    print(
        f"Groupes communs : "
        f"{len(train_groups.intersection(test_groups))}"
    )

    # ---------------------------------------------------------
    # TF-IDF
    # ---------------------------------------------------------

    print("\nConstruction TF-IDF...")

    vectorizer = TfidfVectorizer(
        max_features=3000,
        ngram_range=(1, 2),
        min_df=2,
        max_df=0.95,
        sublinear_tf=True
    )

    X_text_train = vectorizer.fit_transform(
        train_df["text"]
    )

    X_text_test = vectorizer.transform(
        test_df["text"]
    )

    print(
        f"TF-IDF train : {X_text_train.shape}"
    )

    print(
        f"TF-IDF test  : {X_text_test.shape}"
    )

    # ---------------------------------------------------------
    # Variables catégorielles
    # ---------------------------------------------------------

    encoder = OneHotEncoder(
        handle_unknown="ignore",
        sparse_output=True
    )

    X_cat_train = encoder.fit_transform(
        train_df[
            ["vuln_type", "cwe", "language"]
        ]
    )

    X_cat_test = encoder.transform(
        test_df[
            ["vuln_type", "cwe", "language"]
        ]
    )

    print(
        f"Categorical train : {X_cat_train.shape}"
    )

    # ---------------------------------------------------------
    # Ligne
    # ---------------------------------------------------------

    X_line_train = csr_matrix(
        train_df[["line"]].values
    )

    X_line_test = csr_matrix(
        test_df[["line"]].values
    )

    # ---------------------------------------------------------
    # Fusion des features
    # ---------------------------------------------------------

    X_train = hstack(
        [
            X_text_train,
            X_cat_train,
            X_line_train
        ]
    ).tocsr()

    X_test = hstack(
        [
            X_text_test,
            X_cat_test,
            X_line_test
        ]
    ).tocsr()

    y_train = train_df["real_vulnerability"].values
    y_test = test_df["real_vulnerability"].values

    print(
        f"\nFeatures finales train : {X_train.shape}"
    )

    print(
        f"Features finales test  : {X_test.shape}"
    )

    # ---------------------------------------------------------
    # Modèles
    # ---------------------------------------------------------

    models = {

        "Decision Tree": DecisionTreeClassifier(
            max_depth=12,
            min_samples_leaf=3,
            random_state=42,
            class_weight="balanced"
        ),

        "XGBoost": XGBClassifier(
            n_estimators=150,
            max_depth=6,
            learning_rate=0.08,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=2,
            reg_lambda=1.0,
            random_state=42,
            eval_metric="logloss",
            n_jobs=2,
            tree_method="hist"
        ),

        "Random Forest": RandomForestClassifier(
            n_estimators=200,
            max_depth=12,
            min_samples_leaf=2,
            random_state=42,
            class_weight="balanced",
            n_jobs=2
        ),
    }

    results = {}

    # ---------------------------------------------------------
    # Entraînement
    # ---------------------------------------------------------

    for name, model in models.items():

        result = evaluate_model(
            name,
            model,
            X_train,
            X_test,
            y_train,
            y_test
        )

        results[name] = result

        filename = (
            name.lower()
            .replace(" ", "_")
            + "_combined.joblib"
        )

        joblib.dump(
            model,
            MODEL_DIR / filename
        )

    # ---------------------------------------------------------
    # Comparaison
    # ---------------------------------------------------------

    results_df = pd.DataFrame(
        results.values()
    )

    results_df = results_df.sort_values(
        "f1",
        ascending=False
    )

    print("\n" + "=" * 70)
    print("COMPARAISON FINALE")
    print("=" * 70)

    print(
        results_df.to_string(index=False)
    )

    RESULTS.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    results_df.to_csv(
        RESULTS,
        index=False
    )

    # ---------------------------------------------------------
    # Sauvegarde preprocessing
    # ---------------------------------------------------------

    joblib.dump(
        vectorizer,
        MODEL_DIR / "tfidf_vectorizer_combined.joblib"
    )

    joblib.dump(
        encoder,
        MODEL_DIR / "categorical_encoder_combined.joblib"
    )

    print("\n" + "=" * 70)
    print(
        f"MEILLEUR MODELE : "
        f"{results_df.iloc[0]['model']}"
    )

    print(
        f"F1-score : "
        f"{results_df.iloc[0]['f1']:.4f}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()
