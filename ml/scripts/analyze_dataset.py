import pandas as pd
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATASET = (
    PROJECT_ROOT
    / "ml"
    / "data"
    / "processed"
    / "dataset.csv"
)

df = pd.read_csv(DATASET)

print("=" * 70)
print("ANALYSE DU DATASET ML")
print("=" * 70)

print("\n1. Dimensions")
print(f"Lignes   : {len(df)}")
print(f"Colonnes : {len(df.columns)}")

print("\nColonnes :")
for column in df.columns:
    print(f" - {column}")

print("\n2. Valeurs manquantes")
print(df.isnull().sum())

print("\n3. Répartition Severity")
print(df["severity"].value_counts())

print("\n4. Répartition Severity (%)")
print(
    (df["severity"].value_counts(normalize=True) * 100)
    .round(2)
)

print("\n5. Severity × Type de vulnérabilité")
print(
    pd.crosstab(
        df["vuln_type"],
        df["severity"]
    )
)

print("\n6. Severity × CWE")
print(
    pd.crosstab(
        df["cwe"],
        df["severity"]
    )
)

print("\n7. Real vulnerability × Severity")
print(
    pd.crosstab(
        df["real_vulnerability"],
        df["severity"]
    )
)

print("\n8. Nombre de tests uniques")
print(df["test_name"].nunique())

print("\n9. Nombre de fichiers uniques")
print(df["file"].nunique())

print("\n10. Doublons exacts")
print(df.duplicated().sum())

print("\n11. Nombre moyen d'alertes par test")
print(
    round(
        len(df) / df["test_name"].nunique(),
        2
    )
)

print("\n" + "=" * 70)