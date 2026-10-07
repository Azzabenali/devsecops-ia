import pandas as pd
from pathlib import Path


SOURCE = Path("ml/data/processed/dataset.csv")
OUTPUT = Path("ml/data/processed/ml_dataset_enriched.csv")


def main():
    print("=" * 60)
    print("CREATION DU DATASET ML ENRICHI")
    print("=" * 60)

    df = pd.read_csv(SOURCE)

    print(f"Dataset source : {len(df)} lignes")

    # Utilisé uniquement pour le Group Split
    group_column = "test_name"

    # Features structurées
    structured_features = [
        "vuln_type",
        "cwe",
        "line",
    ]

    # Features textuelles
    text_features = [
        "title",
        "description",
        "code_line",
    ]

    # Variable cible
    target = "real_vulnerability"

    required_columns = (
        [group_column]
        + structured_features
        + text_features
        + [target]
    )

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Colonnes manquantes : {missing}"
        )

    ml_df = df[required_columns].copy()

    # Nettoyage des textes
    for column in text_features:
        ml_df[column] = (
            ml_df[column]
            .fillna("")
            .astype(str)
        )

    # Conversion de la cible
    ml_df[target] = ml_df[target].astype(int)

    # Vérification des valeurs manquantes
    before = len(ml_df)

    ml_df = ml_df.dropna(
        subset=[
            group_column,
            "vuln_type",
            "cwe",
            "line",
            target,
        ]
    )

    after = len(ml_df)

    print(f"Lignes supprimées : {before - after}")

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    ml_df.to_csv(
        OUTPUT,
        index=False
    )

    print()
    print("Dataset enrichi créé avec succès.")
    print(f"Fichier : {OUTPUT}")
    print(f"Nombre de lignes : {len(ml_df)}")
    print(f"Nombre de colonnes : {len(ml_df.columns)}")

    print("\nColonnes :")
    for column in ml_df.columns:
        print(f" - {column}")

    print(
        f"\nTests uniques : "
        f"{ml_df[group_column].nunique()}"
    )

    print("\nDistribution de la cible :")
    print(
        ml_df[target]
        .value_counts()
        .sort_index()
    )


if __name__ == "__main__":
    main()