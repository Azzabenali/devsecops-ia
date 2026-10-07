import csv
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import Counter

# ============================================================
# CONFIGURATION
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]

EXPECTED_RESULTS = (
    PROJECT_ROOT
    / "ml"
    / "data"
    / "raw"
    / "BenchmarkJava"
    / "expectedresults-1.2.csv"
)

VCG_RESULTS = (
    PROJECT_ROOT
    / "ml"
    / "data"
    / "raw"
    / "BenchmarkJava"
    / "results"
    / "Benchmark_1.2-visualcodegrepper-v2.2.0.xml"
)

OUTPUT_FILE = (
    PROJECT_ROOT
    / "ml"
    / "data"
    / "processed"
    / "dataset.csv"
)


# ============================================================
# 1. LECTURE DU CSV OWASP
# ============================================================

def load_expected_results():
    """
    Charge expectedresults-1.2.csv.

    Retourne un dictionnaire :
        BenchmarkTestXXXX -> informations OWASP
    """

    results = {}

    with open(EXPECTED_RESULTS, "r", encoding="utf-8") as file:
        reader = csv.reader(file)

        for row in reader:

            # Ignorer les lignes vides
            if not row:
                continue

            # Ignorer les commentaires
            if row[0].startswith("#"):
                continue

            if len(row) < 4:
                continue

            test_name = row[0].strip()
            category = row[1].strip()
            real_vulnerability = row[2].strip().lower()
            cwe = row[3].strip()

            results[test_name] = {
                "category": category,
                "real_vulnerability": real_vulnerability,
                "cwe": f"CWE-{cwe}",
            }

    return results


# ============================================================
# 2. EXTRACTION DES INFORMATIONS DU XML VCG
# ============================================================

def load_vcg_results():
    """
    Lit les résultats VisualCodeGrepper.

    Chaque <CodeIssue> devient une ligne.
    """

    tree = ET.parse(VCG_RESULTS)
    root = tree.getroot()

    results = []

    for issue in root.findall(".//CodeIssue"):

        priority = issue.findtext("Priority", default="").strip()
        severity = issue.findtext("Severity", default="").strip()
        title = issue.findtext("Title", default="").strip()
        description = issue.findtext("Description", default="").strip()
        filename = issue.findtext("FileName", default="").strip()
        line = issue.findtext("Line", default="").strip()
        code_line = issue.findtext("CodeLine", default="").strip()

        # ----------------------------------------------------
        # Extraire BenchmarkTestXXXX depuis le chemin Windows
        # ----------------------------------------------------

        match = re.search(r"(BenchmarkTest\d+)\.java", filename)

        if not match:
            continue

        test_name = match.group(1)

        # ----------------------------------------------------
        # Garder uniquement les classes de sévérité voulues
        # ----------------------------------------------------

        if severity not in {"Critical", "High", "Medium", "Low"}:
            continue

        results.append({
            "test_name": test_name,
            "priority": priority,
            "severity": severity,
            "title": title,
            "description": description,
            "file": filename,
            "line": line,
            "code_line": code_line,
        })

    return results


# ============================================================
# 3. JOINTURE OWASP + VCG
# ============================================================

def build_dataset(expected_results, vcg_results):

    dataset = []

    for result in vcg_results:

        test_name = result["test_name"]

        # Vérifier que le test existe dans expectedresults
        if test_name not in expected_results:
            continue

        expected = expected_results[test_name]

        row = {
            "test_name": test_name,

            # Source OWASP Benchmark
            "vuln_type": expected["category"],
            "cwe": expected["cwe"],
            "real_vulnerability": expected["real_vulnerability"],

            # Source VisualCodeGrepper
            "priority": result["priority"],
            "severity": result["severity"],
            "title": result["title"],
            "description": result["description"],
            "file": result["file"],
            "line": result["line"],
            "code_line": result["code_line"],

            # BenchmarkJava = Java
            "language": "Java",

            # Extension
            "file_type": ".java",
        }

        dataset.append(row)

    return dataset


# ============================================================
# 4. SAUVEGARDE
# ============================================================

def save_dataset(dataset):

    OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

    if not dataset:
        print("ERREUR : aucun exemple dans le dataset.")
        return

    fieldnames = list(dataset[0].keys())

    with open(
        OUTPUT_FILE,
        "w",
        encoding="utf-8",
        newline=""
    ) as file:

        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames
        )

        writer.writeheader()
        writer.writerows(dataset)


# ============================================================
# 5. RAPPORT
# ============================================================

def print_report(dataset):

    print()
    print("=" * 60)
    print("RAPPORT DE PREPARATION DU DATASET")
    print("=" * 60)

    print()
    print(f"Nombre total de lignes : {len(dataset)}")

    print()
    print("Répartition par sévérité :")

    severity_counter = Counter(
        row["severity"]
        for row in dataset
    )

    for severity, count in severity_counter.most_common():
        print(f"  {severity:10} : {count}")

    print()
    print("Répartition par type de vulnérabilité :")

    vuln_counter = Counter(
        row["vuln_type"]
        for row in dataset
    )

    for vuln_type, count in vuln_counter.most_common():
        print(f"  {vuln_type:15} : {count}")

    print()
    print("Répartition par CWE :")

    cwe_counter = Counter(
        row["cwe"]
        for row in dataset
    )

    for cwe, count in cwe_counter.most_common():
        print(f"  {cwe:10} : {count}")

    print()
    print("Répartition real_vulnerability :")

    real_counter = Counter(
        row["real_vulnerability"]
        for row in dataset
    )

    for value, count in real_counter.items():
        print(f"  {value:5} : {count}")

    print()
    print(f"Dataset sauvegardé dans :")
    print(OUTPUT_FILE)

    print("=" * 60)


# ============================================================
# MAIN
# ============================================================

def main():

    print("Chargement OWASP Benchmark...")
    expected_results = load_expected_results()

    print(
        f"  -> {len(expected_results)} tests OWASP chargés"
    )

    print()
    print("Chargement VisualCodeGrepper...")
    vcg_results = load_vcg_results()

    print(
        f"  -> {len(vcg_results)} résultats VCG exploitables"
    )

    print()
    print("Construction du dataset...")

    dataset = build_dataset(
        expected_results,
        vcg_results
    )

    save_dataset(dataset)

    print_report(dataset)


if __name__ == "__main__":
    main()