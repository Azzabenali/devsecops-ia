
import pandas as pd
from pathlib import Path


SOURCE = Path("ml/data/processed/dataset.csv")
OUTPUT = Path("ml/data/processed/ml_dataset.csv")


def main():
    print("Chargement du dataset...")
    df = pd.read_csv(SOURCE)

    print(f"Dataset source : {len(df)} lignes")

    # Colonne utilisée uniquement pour le découpage
    # Train/Test par groupe.
    # Elle ne sera PAS utilisée comme feature ML.
    group_column = "test_name"

    # Features retenues pour la première expérimentation ML
    features = [
        "vuln_type",
        "cwe",
        "line",
    ]

    # Variable cible
    target = "real_vulnerability"

    # Vérification des colonnes
    required_columns = [group_column] + features + [target]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Colonnes manquantes : {missing}"
        )

    # Sélection des colonnes
    ml_df = df[required_columns].copy()

    # Conversion de la cible en 0/1
    ml_df[target] = ml_df[target].astype(int)

    # Suppression des lignes incomplètes
    before = len(ml_df)

    ml_df = ml_df.dropna()

    after = len(ml_df)

    print(f"Lignes supprimées : {before - after}")

    # Création du dossier de sortie
    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True
    )

    # Sauvegarde
    ml_df.to_csv(
        OUTPUT,
        index=False
    )

    print()
    print("Dataset ML créé avec succès.")
    print(f"Fichier : {OUTPUT}")
    print(f"Nombre de lignes : {len(ml_df)}")
    print(f"Nombre de colonnes : {len(ml_df.columns)}")

    print("\nColonnes :")
    for column in ml_df.columns:
        print(f" - {column}")

    print("\nNombre de groupes uniques :")
    print(f" - {group_column} : {ml_df[group_column].nunique()}")

    print("\nDistribution de la cible :")
    print(
        ml_df[target]
        .value_counts()
        .sort_index()
        .rename(
            index={
                0: "False",
                1: "True"
            }
        )
    )


if __name__ == "__main__":
    main()

