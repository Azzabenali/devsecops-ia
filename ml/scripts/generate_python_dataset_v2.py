from pathlib import Path
import csv
import random

# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]
OUTPUT_FILE = BASE_DIR / "ml" / "data" / "raw" / "python_security_dataset_v2.csv"

RANDOM_SEED = 42
random.seed(RANDOM_SEED)


# ============================================================
# OUTILS
# ============================================================

def add_example(
    rows,
    group_id,
    vuln_type,
    cwe,
    title,
    description,
    code_line,
    real_vulnerability,
):
    rows.append({
        "group_id": group_id,
        "vuln_type": vuln_type,
        "cwe": cwe,
        "title": title,
        "description": description,
        "code_line": code_line,
        "real_vulnerability": real_vulnerability,
        "language": "python",
        "file_type": ".py",
    })


# ============================================================
# DATASET
# ============================================================

rows = []


# ============================================================
# 1. SQL INJECTION — CWE-89
# ============================================================

sqli_cases = [
    (
        "concat",
        "Construction SQL par concaténation",
        "Une entrée utilisateur est concaténée directement dans une requête SQL.",
        'query = "SELECT * FROM users WHERE name = \'" + username + "\'"',
        1,
    ),
    (
        "fstring",
        "SQL construit avec une f-string",
        "Une donnée contrôlée par l'utilisateur est directement incorporée dans une requête SQL.",
        'query = f"SELECT * FROM users WHERE id = {user_id}"',
        1,
    ),
    (
        "format",
        "SQL construit avec format",
        "La requête SQL utilise une valeur utilisateur sans paramétrage.",
        'query = "SELECT * FROM products WHERE name = \'{}\'".format(product)',
        1,
    ),
    (
        "percent",
        "SQL avec formatage percent",
        "Une valeur utilisateur est injectée dans une chaîne SQL.",
        'query = "SELECT * FROM accounts WHERE email = \'%s\'" % email',
        1,
    ),
    (
        "safe_parameter",
        "Requête SQL paramétrée",
        "La valeur utilisateur est transmise comme paramètre séparé.",
        'cursor.execute("SELECT * FROM users WHERE name = ?", (username,))',
        0,
    ),
    (
        "safe_named",
        "Requête SQL avec paramètres nommés",
        "La requête utilise des paramètres nommés au lieu de concaténer les entrées.",
        'cursor.execute("SELECT * FROM users WHERE id = :id", {"id": user_id})',
        0,
    ),
    (
        "safe_orm",
        "Utilisation sécurisée d'un ORM",
        "La recherche est effectuée via une API ORM sans construction manuelle de SQL.",
        'user = User.query.filter_by(name=username).first()',
        0,
    ),
    (
        "safe_constant",
        "Requête SQL avec valeur constante",
        "La requête ne contient aucune donnée contrôlée par l'utilisateur.",
        'cursor.execute("SELECT * FROM users WHERE active = 1")',
        0,
    ),
]


# ============================================================
# 2. XSS — CWE-79
# ============================================================

xss_cases = [
    (
        "html_concat",
        "HTML construit avec une entrée utilisateur",
        "Une entrée utilisateur est directement insérée dans une réponse HTML.",
        'return "<h1>Bonjour " + username + "</h1>"',
        1,
    ),
    (
        "html_fstring",
        "HTML construit avec une f-string",
        "Une donnée externe est directement incorporée dans du HTML.",
        'html = f"<div>{comment}</div>"',
        1,
    ),
    (
        "template_raw",
        "Contenu utilisateur rendu sans échappement",
        "Le contenu utilisateur est marqué comme HTML sûr sans échappement.",
        'return render_template_string("<p>{{ content|safe }}</p>", content=comment)',
        1,
    ),
    (
        "response_raw",
        "Réponse HTML non échappée",
        "La réponse contient directement une donnée provenant de la requête.",
        'return "<script>" + value + "</script>"',
        1,
    ),
    (
        "safe_escape",
        "Échappement explicite du contenu",
        "Le contenu utilisateur est échappé avant son insertion dans la réponse.",
        'return "<h1>" + html.escape(username) + "</h1>"',
        0,
    ),
    (
        "safe_template",
        "Template avec échappement automatique",
        "Le moteur de template effectue l'échappement de la variable.",
        'return render_template("profile.html", username=username)',
        0,
    ),
    (
        "safe_markupsafe",
        "Contenu traité avant rendu",
        "La donnée est nettoyée avant son utilisation dans la réponse.",
        'safe_name = escape(username)',
        0,
    ),
    (
        "safe_json",
        "Donnée retournée en JSON",
        "La donnée n'est pas interprétée comme du HTML.",
        'return jsonify({"username": username})',
        0,
    ),
]


# ============================================================
# 3. COMMAND INJECTION — CWE-78
# ============================================================

cmdi_cases = [
    (
        "shell_true",
        "Commande système avec shell=True",
        "Une entrée utilisateur influence une commande exécutée par le shell.",
        'subprocess.check_output("ping " + host, shell=True)',
        1,
    ),
    (
        "os_system",
        "Utilisation de os.system",
        "Une commande contenant une entrée externe est exécutée directement.",
        'os.system("ping " + hostname)',
        1,
    ),
    (
        "popen_concat",
        "Commande construite dynamiquement",
        "Une valeur utilisateur est concaténée à une commande système.",
        'subprocess.Popen("cat " + filename, shell=True)',
        1,
    ),
    (
        "eval_command",
        "Commande exécutée dynamiquement",
        "Une entrée externe est utilisée dans une opération d'exécution dynamique.",
        'eval(user_expression)',
        1,
    ),
    (
        "safe_list",
        "Commande exécutée avec une liste d'arguments",
        "Les arguments sont séparés et le shell n'est pas utilisé.",
        'subprocess.run(["ping", "-c", "1", host], shell=False)',
        0,
    ),
    (
        "safe_constant",
        "Commande système constante",
        "La commande ne dépend d'aucune entrée utilisateur.",
        'subprocess.run(["whoami"], check=True)',
        0,
    ),
    (
        "safe_allowlist",
        "Commande contrôlée par liste blanche",
        "Seules des valeurs autorisées peuvent être utilisées comme argument.",
        'if host in ALLOWED_HOSTS: subprocess.run(["ping", host])',
        0,
    ),
    (
        "safe_validation",
        "Validation avant exécution",
        "L'entrée est validée puis passée comme argument séparé.",
        'subprocess.run(["ping", validated_host], shell=False)',
        0,
    ),
]


# ============================================================
# 4. PATH TRAVERSAL — CWE-22
# ============================================================

path_cases = [
    (
        "open_user_file",
        "Fichier contrôlé par utilisateur",
        "Un nom de fichier fourni par l'utilisateur est utilisé directement.",
        'with open("/var/www/files/" + filename) as f:',
        1,
    ),
    (
        "join_user_path",
        "Chemin construit avec une entrée utilisateur",
        "Une entrée externe influence directement le chemin d'accès.",
        'path = os.path.join("/uploads", filename); open(path)',
        1,
    ),
    (
        "download_path",
        "Téléchargement contrôlé par utilisateur",
        "Le chemin demandé est utilisé sans vérification de confinement.",
        'return send_file("/data/" + requested_file)',
        1,
    ),
    (
        "archive_extract",
        "Extraction d'archive non contrôlée",
        "Les chemins contenus dans une archive sont extraits sans validation.",
        'archive.extractall("/tmp/uploads")',
        1,
    ),
    (
        "safe_realpath",
        "Vérification du chemin réel",
        "Le chemin est vérifié avant l'accès au fichier.",
        'path = os.path.realpath(os.path.join(BASE_DIR, filename))',
        0,
    ),
    (
        "safe_basename",
        "Utilisation du nom de base",
        "Le chemin fourni est réduit à un nom de fichier simple.",
        'filename = os.path.basename(user_filename)',
        0,
    ),
    (
        "safe_allowlist",
        "Fichier sélectionné depuis une liste autorisée",
        "Le fichier est choisi parmi des ressources connues.",
        'path = ALLOWED_FILES[file_id]',
        0,
    ),
    (
        "safe_storage",
        "Identifiant interne utilisé pour le fichier",
        "L'utilisateur fournit un identifiant et non un chemin arbitraire.",
        'path = storage.get_path(document_id)',
        0,
    ),
]


# ============================================================
# 5. HARDCODED SECRET — CWE-798
# ============================================================

secret_cases = [
    (
        "api_key",
        "Clé API codée en dur",
        "Une clé API est directement présente dans le code source.",
        'API_KEY = "sk_live_123456789"',
        1,
    ),
    (
        "password",
        "Mot de passe codé en dur",
        "Un mot de passe est stocké directement dans le code.",
        'DB_PASSWORD = "AdminPassword123"',
        1,
    ),
    (
        "token",
        "Token codé en dur",
        "Un token d'accès est présent dans le programme.",
        'TOKEN = "ghp_123456789abcdef"',
        1,
    ),
    (
        "secret_header",
        "Secret dans un en-tête",
        "Un secret d'authentification est écrit directement dans le code.",
        'headers = {"Authorization": "Bearer SECRET_TOKEN"}',
        1,
    ),
    (
        "env_api",
        "Clé API récupérée depuis l'environnement",
        "La clé est stockée hors du code source.",
        'API_KEY = os.getenv("API_KEY")',
        0,
    ),
    (
        "env_password",
        "Mot de passe récupéré depuis l'environnement",
        "Le mot de passe n'est pas stocké directement dans le programme.",
        'password = os.environ["DB_PASSWORD"]',
        0,
    ),
    (
        "secret_manager",
        "Secret récupéré depuis un gestionnaire",
        "L'application utilise un gestionnaire de secrets.",
        'password = secrets_manager.get("database/password")',
        0,
    ),
    (
        "config_external",
        "Configuration externe",
        "Les informations sensibles sont fournies par une configuration externe.",
        'token = config.get_secret("TOKEN")',
        0,
    ),
]


# ============================================================
# 6. WEAK CRYPTOGRAPHY — CWE-327
# ============================================================

crypto_cases = [
    (
        "md5",
        "Utilisation de MD5",
        "MD5 est utilisé pour une opération cryptographique sensible.",
        'digest = hashlib.md5(password.encode()).hexdigest()',
        1,
    ),
    (
        "sha1",
        "Utilisation de SHA-1",
        "SHA-1 est utilisé dans un contexte où une fonction moderne est nécessaire.",
        'digest = hashlib.sha1(data).hexdigest()',
        1,
    ),
    (
        "des",
        "Algorithme DES obsolète",
        "Un algorithme cryptographique ancien est utilisé.",
        'cipher = DES.new(key, DES.MODE_ECB)',
        1,
    ),
    (
        "ecb",
        "Mode ECB",
        "Le mode ECB ne protège pas correctement les motifs des données.",
        'cipher = AES.new(key, AES.MODE_ECB)',
        1,
    ),
    (
        "sha256",
        "SHA-256",
        "Une fonction de hachage moderne est utilisée.",
        'digest = hashlib.sha256(data).hexdigest()',
        0,
    ),
    (
        "bcrypt",
        "Bcrypt pour mot de passe",
        "Bcrypt est utilisé pour le stockage sécurisé des mots de passe.",
        'password_hash = bcrypt.hashpw(password, bcrypt.gensalt())',
        0,
    ),
    (
        "fernet",
        "Fernet",
        "Fernet fournit une primitive de chiffrement authentifié adaptée aux données.",
        'token = Fernet(key).encrypt(data)',
        0,
    ),
    (
        "aes_gcm",
        "AES-GCM",
        "AES-GCM est utilisé comme mode de chiffrement authentifié.",
        'cipher = AES.new(key, AES.MODE_GCM)',
        0,
    ),
]


# ============================================================
# 7. DEBUG / MISCONFIGURATION — CWE-489
# ============================================================

debug_cases = [
    (
        "flask_debug",
        "Flask en mode debug",
        "L'application Flask est exécutée avec le mode debug activé.",
        'app.run(debug=True)',
        1,
    ),
    (
        "debug_config",
        "Configuration debug activée",
        "Le mode debug est explicitement activé dans la configuration.",
        'DEBUG = True',
        1,
    ),
    (
        "django_debug",
        "Django DEBUG activé",
        "Le paramètre DEBUG est activé dans une configuration de production.",
        'DEBUG = True',
        1,
    ),
    (
        "debug_env",
        "Mode debug forcé",
        "Le programme force le mode debug au lieu d'utiliser une configuration sûre.",
        'app.config["DEBUG"] = True',
        1,
    ),
    (
        "production_config",
        "Configuration production",
        "Le mode debug est désactivé.",
        'app.run(debug=False)',
        0,
    ),
    (
        "env_debug",
        "Debug contrôlé par environnement",
        "Le mode debug est désactivé par défaut.",
        'DEBUG = os.getenv("DEBUG", "false").lower() == "true"',
        0,
    ),
    (
        "secure_config",
        "Configuration sécurisée",
        "La configuration de production désactive les informations de debug.",
        'app.config.update(DEBUG=False)',
        0,
    ),
    (
        "no_debug",
        "Application sans debug",
        "L'application est démarrée sans mode debug.",
        'app.run()',
        0,
    ),
]


# ============================================================
# 8. INSECURE DESERIALIZATION — CWE-502
# ============================================================

deserialize_cases = [
    (
        "pickle_load",
        "Désérialisation Pickle",
        "Des données non fiables sont désérialisées avec pickle.",
        'obj = pickle.loads(user_data)',
        1,
    ),
    (
        "pickle_file",
        "Pickle depuis un fichier",
        "Un fichier potentiellement non fiable est chargé avec pickle.",
        'obj = pickle.load(open(filename, "rb"))',
        1,
    ),
    (
        "yaml_unsafe",
        "YAML non sécurisé",
        "yaml.load est utilisé sans chargeur sécurisé.",
        'data = yaml.load(user_input)',
        1,
    ),
    (
        "marshal_external",
        "Données externes désérialisées",
        "Des données externes sont chargées avec un mécanisme dangereux.",
        'obj = marshal.loads(request.data)',
        1,
    ),
    (
        "json_load",
        "Désérialisation JSON",
        "JSON est utilisé pour traiter des données structurées sans exécution de code.",
        'data = json.loads(request.data)',
        0,
    ),
    (
        "yaml_safe",
        "YAML sécurisé",
        "SafeLoader empêche l'utilisation de constructions dangereuses.",
        'data = yaml.safe_load(user_input)',
        0,
    ),
    (
        "validated_schema",
        "Validation de schéma",
        "Les données sont validées selon un schéma avant utilisation.",
        'data = UserSchema.model_validate(request.json)',
        0,
    ),
    (
        "primitive_data",
        "Données primitives",
        "L'application utilise uniquement des données primitives validées.",
        'value = int(request.args["id"])',
        0,
    ),
]


# ============================================================
# GÉNÉRATION DES GROUPES
# ============================================================

categories = {
    "sqli": ("CWE-89", sqli_cases),
    "xss": ("CWE-79", xss_cases),
    "cmdi": ("CWE-78", cmdi_cases),
    "pathtraver": ("CWE-22", path_cases),
    "secret": ("CWE-798", secret_cases),
    "crypto": ("CWE-327", crypto_cases),
    "debug": ("CWE-489", debug_cases),
    "deserialize": ("CWE-502", deserialize_cases),
}


# Chaque catégorie possède 10 groupes.
# Chaque groupe reprend les 8 scénarios mais avec un identifiant
# différent afin de pouvoir faire un GroupShuffleSplit.
for vuln_type, (cwe, cases) in categories.items():

    for group_number in range(1, 11):

        group_id = f"{vuln_type}_scenario_{group_number:02d}"

        # Mélange léger des scénarios pour éviter un ordre fixe.
        shuffled_cases = cases.copy()
        random.shuffle(shuffled_cases)

        for case in shuffled_cases:

            case_id, title, description, code_line, label = case

            add_example(
                rows=rows,
                group_id=group_id,
                vuln_type=vuln_type,
                cwe=cwe,
                title=title,
                description=description,
                code_line=code_line,
                real_vulnerability=label,
            )


# ============================================================
# MÉLANGE FINAL
# ============================================================

random.shuffle(rows)


# ============================================================
# ÉCRITURE CSV
# ============================================================

OUTPUT_FILE.parent.mkdir(parents=True, exist_ok=True)

fieldnames = [
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

with open(
    OUTPUT_FILE,
    "w",
    newline="",
    encoding="utf-8",
) as f:

    writer = csv.DictWriter(
        f,
        fieldnames=fieldnames,
        quoting=csv.QUOTE_ALL,
    )

    writer.writeheader()
    writer.writerows(rows)


# ============================================================
# STATISTIQUES
# ============================================================

total = len(rows)
vulnerable = sum(
    row["real_vulnerability"] == 1
    for row in rows
)
secure = total - vulnerable

print("=" * 70)
print("DATASET PYTHON V2")
print("=" * 70)

print(f"Fichier : {OUTPUT_FILE}")
print(f"Nombre total : {total}")
print(f"Vulnérables : {vulnerable}")
print(f"Non vulnérables : {secure}")

print()
print("Distribution par type :")

for vuln_type in categories:
    count = sum(
        row["vuln_type"] == vuln_type
        for row in rows
    )

    print(f"  {vuln_type:15} : {count}")

print()
print("Nombre de groupes :", len({
    row["group_id"]
    for row in rows
}))

print()
print("Distribution par CWE :")

cwe_counts = {}

for row in rows:
    cwe = row["cwe"]
    cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

for cwe, count in sorted(cwe_counts.items()):
    print(f"  {cwe:10} : {count}")

print()
print("Dataset créé avec succès.")