import pandas as pd
from pathlib import Path

OWASP_FILE = Path("ml/data/processed/ml_dataset_enriched.csv")
PYTHON_FILE = Path("ml/data/raw/python_security_dataset.csv")
OUTPUT_FILE = Path("ml/data/processed/ml_dataset_combined.csv")


def main():
    print("=" * 70)
    print("FUSION DES DATASETS OWASP + PYTHON")
    print("=" * 70)

    # ---------------------------------------------------------
    # OWASP Benchmark
    # ---------------------------------------------------------
    print("\nChargement OWASP Benchmark...")

    owasp = pd.read_csv(OWASP_FILE)

    print(f"OWASP : {len(owasp)} lignes")

    owasp = owasp[
        [
            "test_name",
            "vuln_type",
            "cwe",
            "line",
            "title",
            "description",
            "code_line",
            "real_vulnerability",
        ]
    ].copy()

    owasp["language"] = "Java"

    # ---------------------------------------------------------
    # Dataset Python
    # ---------------------------------------------------------
    print("\nChargement dataset Python...")

    python = pd.read_csv(PYTHON_FILE)

    print(f"Python : {len(python)} lignes")

    python = python.rename(columns={"id": "test_name"})

    python["line"] = 1

    python = python[
        [
            "test_name",
            "vuln_type",
            "cwe",
            "line",
            "title",
            "description",
            "code_line",
            "real_vulnerability",
            "language",
        ]
    ].copy()

    # ---------------------------------------------------------
    # Harmonisation
    # ---------------------------------------------------------
    owasp["real_vulnerability"] = (
        owasp["real_vulnerability"].astype(int)
    )

    python["real_vulnerability"] = (
        python["real_vulnerability"].astype(int)
    )

    # ---------------------------------------------------------
    # Fusion
    # ---------------------------------------------------------
    combined = pd.concat(
        [owasp, python],
        ignore_index=True
    )

    # Vérification des doublons de groupe
    duplicate_groups = combined["test_name"].duplicated().sum()

    print("\nGroupes dupliqués :", duplicate_groups)

    # ---------------------------------------------------------
    # Sauvegarde
    # ---------------------------------------------------------
    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    combined.to_csv(
        OUTPUT_FILE,
        index=False
    )

    print("\n" + "=" * 70)
    print("DATASET FUSIONNE")
    print("=" * 70)

    print(f"Fichier : {OUTPUT_FILE}")
    print(f"Nombre total : {len(combined)}")
    print(
        f"OWASP : {len(owasp)}"
    )
    print(
        f"Python : {len(python)}"
    )

    print("\nLangages :")
    print(combined["language"].value_counts())

    print("\nDistribution cible :")
    print(
        combined["real_vulnerability"]
        .value_counts()
        .sort_index()
    )

    print("\nDistribution par type :")
    print(
        combined["vuln_type"]
        .value_counts()
    )

    print("\nColonnes :")
    print(list(combined.columns))


if __name__ == "__main__":
    main()
