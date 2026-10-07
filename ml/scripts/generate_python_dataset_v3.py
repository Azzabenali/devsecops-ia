from pathlib import Path
import pandas as pd


# ============================================================
# CONFIGURATION
# ============================================================

BASE_DIR = Path(__file__).resolve().parents[2]

OUTPUT = (
    BASE_DIR
    / "ml"
    / "data"
    / "raw"
    / "python_security_dataset_v3.csv"
)


# ============================================================
# DONNÉES
# ============================================================

rows = []

counter = 1


def add_group(
    vuln_type,
    cwe,
    scenarios,
):
    """
    Chaque scénario constitue un groupe indépendant.
    Pour chaque scénario :
      - 1 exemple vulnérable
      - 1 exemple sécurisé
    """

    global counter

    for scenario_id, vulnerable_code, secure_code, title, description in scenarios:

        group_id = f"{vuln_type}_{scenario_id}"

        # -------------------------
        # Exemple vulnérable
        # -------------------------

        rows.append({
            "id": counter,
            "group_id": group_id,
            "vuln_type": vuln_type,
            "cwe": cwe,
            "title": title,
            "description": description,
            "code_line": vulnerable_code,
            "real_vulnerability": 1,
            "language": "python",
            "file_type": ".py",
        })

        counter += 1

        # -------------------------
        # Exemple sécurisé
        # -------------------------

        rows.append({
            "id": counter,
            "group_id": group_id,
            "vuln_type": vuln_type,
            "cwe": cwe,
            "title": f"{title} - secure",
            "description": (
                "Version sécurisée du même scénario avec une "
                "mesure de protection appropriée."
            ),
            "code_line": secure_code,
            "real_vulnerability": 0,
            "language": "python",
            "file_type": ".py",
        })

        counter += 1


# ============================================================
# SQL INJECTION — CWE-89
# ============================================================

add_group(
    "sqli",
    "CWE-89",
    [
        (
            "001",
            'query = "SELECT * FROM users WHERE id = " + user_id',
            'query = "SELECT * FROM users WHERE id = ?"',

            "SQL Injection - string concatenation",
            "Construction dynamique d'une requête SQL avec une entrée utilisateur.",
        ),
        (
            "002",
            'sql = f"SELECT * FROM products WHERE name = \'{name}\'"',
            'sql = "SELECT * FROM products WHERE name = ?"',

            "SQL Injection - f-string",
            "Une f-string incorpore directement une donnée contrôlée par l'utilisateur.",
        ),
        (
            "003",
            'cursor.execute("DELETE FROM users WHERE id=" + uid)',
            'cursor.execute("DELETE FROM users WHERE id=?", (uid,))',

            "SQL Injection - DELETE",
            "Une commande DELETE est construite avec une entrée non paramétrée.",
        ),
        (
            "004",
            'statement = "SELECT balance FROM accounts WHERE id=" + account_id',
            'statement = "SELECT balance FROM accounts WHERE id=?"',

            "SQL Injection - account query",
            "Une requête sur un compte utilise directement une valeur externe.",
        ),
        (
            "005",
            'query = "UPDATE users SET role=\'" + role + "\' WHERE id=" + uid',
            'query = "UPDATE users SET role=? WHERE id=?"',

            "SQL Injection - UPDATE",
            "Des paramètres utilisateur sont concaténés dans une requête UPDATE.",
        ),
        (
            "006",
            'sql = "SELECT * FROM orders WHERE status=\'" + status + "\'"',
            'sql = "SELECT * FROM orders WHERE status=?"',

            "SQL Injection - status filter",
            "Une valeur de filtre est directement ajoutée à la requête SQL.",
        ),
        (
            "007",
            'query = "SELECT email FROM clients WHERE city=\'" + city + "\'"',
            'query = "SELECT email FROM clients WHERE city=?"',

            "SQL Injection - city filter",
            "Une donnée externe est utilisée dans une clause WHERE sans paramètre.",
        ),
        (
            "008",
            'sql = "SELECT * FROM logs WHERE user=\'" + username + "\'"',
            'sql = "SELECT * FROM logs WHERE user=?"',

            "SQL Injection - log query",
            "Le nom utilisateur est directement concaténé à une requête SQL.",
        ),
    ],
)


# ============================================================
# XSS — CWE-79
# ============================================================

add_group(
    "xss",
    "CWE-79",
    [
        (
            "001",
            'return "<h1>Hello " + username + "</h1>"',
            'return "<h1>Hello " + html.escape(username) + "</h1>"',

            "XSS - HTML concatenation",
            "Une donnée utilisateur est injectée directement dans une réponse HTML.",
        ),
        (
            "002",
            'html = "<div>" + comment + "</div>"',
            'html = "<div>" + html.escape(comment) + "</div>"',

            "XSS - comment",
            "Un commentaire contrôlé par l'utilisateur est inséré dans du HTML.",
        ),
        (
            "003",
            'page = f"<p>{message}</p>"',
            'page = f"<p>{html.escape(message)}</p>"',

            "XSS - f-string HTML",
            "Une f-string incorpore directement une donnée dans du HTML.",
        ),
        (
            "004",
            'return "<span>" + search_term + "</span>"',
            'return "<span>" + html.escape(search_term) + "</span>"',

            "XSS - search",
            "Le terme de recherche est renvoyé sans échappement HTML.",
        ),
        (
            "005",
            'response = "<h2>" + title + "</h2>"',
            'response = "<h2>" + html.escape(title) + "</h2>"',

            "XSS - title",
            "Le titre fourni par l'utilisateur est placé directement dans HTML.",
        ),
        (
            "006",
            'body = "<li>" + item + "</li>"',
            'body = "<li>" + html.escape(item) + "</li>"',

            "XSS - list item",
            "Une valeur externe est insérée directement dans une liste HTML.",
        ),
        (
            "007",
            'result = "<strong>" + value + "</strong>"',
            'result = "<strong>" + html.escape(value) + "</strong>"',

            "XSS - formatted value",
            "Une donnée externe est affichée sans encodage HTML.",
        ),
        (
            "008",
            'return "<div class=\'user\'>" + name + "</div>"',
            'return "<div class=\'user\'>" + html.escape(name) + "</div>"',

            "XSS - user profile",
            "Le nom d'un utilisateur est intégré directement dans une page HTML.",
        ),
    ],
)


# ============================================================
# COMMAND INJECTION — CWE-78
# ============================================================

add_group(
    "cmdi",
    "CWE-78",
    [
        (
            "001",
            'subprocess.run("ping " + host, shell=True)',
            'subprocess.run(["ping", host], shell=False)',

            "Command Injection - ping",
            "Une commande système est construite à partir d'une entrée externe.",
        ),
        (
            "002",
            'os.system("nslookup " + domain)',
            'subprocess.run(["nslookup", domain], check=True)',

            "Command Injection - nslookup",
            "Une entrée utilisateur est ajoutée à une commande système.",
        ),
        (
            "003",
            'os.popen("grep " + pattern + " file.txt")',
            'subprocess.run(["grep", pattern, "file.txt"], check=True)',

            "Command Injection - grep",
            "Une commande shell est construite avec une valeur contrôlée.",
        ),
        (
            "004",
            'subprocess.check_output("curl " + url, shell=True)',
            'subprocess.check_output(["curl", url], shell=False)',

            "Command Injection - curl",
            "Une URL externe est directement utilisée dans une commande shell.",
        ),
        (
            "005",
            'os.system("mkdir " + directory)',
            'subprocess.run(["mkdir", directory], check=True)',

            "Command Injection - mkdir",
            "Un nom de répertoire externe est utilisé dans une commande système.",
        ),
        (
            "006",
            'os.system("tar -xf " + archive)',
            'subprocess.run(["tar", "-xf", archive], check=True)',

            "Command Injection - tar",
            "Le nom d'une archive est intégré dans une commande shell.",
        ),
        (
            "007",
            'subprocess.call("chmod " + mode + " " + filename, shell=True)',
            'subprocess.call(["chmod", mode, filename], shell=False)',

            "Command Injection - chmod",
            "Des paramètres externes contrôlent une commande système.",
        ),
        (
            "008",
            'os.system("python " + script)',
            'subprocess.run(["python", script], check=True)',

            "Command Injection - python command",
            "Le chemin du script est directement ajouté à une commande système.",
        ),
    ],
)


# ============================================================
# PATH TRAVERSAL — CWE-22
# ============================================================

add_group(
    "pathtraver",
    "CWE-22",
    [
        (
            "001",
            'open("/var/www/files/" + filename)',
            'open(os.path.join("/var/www/files", os.path.basename(filename)))',

            "Path Traversal - file read",
            "Un chemin contrôlé par l'utilisateur est utilisé pour ouvrir un fichier.",
        ),
        (
            "002",
            'path = "/uploads/" + requested_file',
            'path = safe_join("/uploads", requested_file)',

            "Path Traversal - uploads",
            "Le nom de fichier externe est ajouté directement au chemin.",
        ),
        (
            "003",
            'with open("/tmp/reports/" + report_name) as f:',
            'with open(safe_join("/tmp/reports", report_name)) as f:',

            "Path Traversal - report",
            "Le nom du rapport influence directement le chemin du fichier.",
        ),
        (
            "004",
            'filename = "/data/" + user_file',
            'filename = safe_join("/data", user_file)',

            "Path Traversal - data",
            "Un fichier fourni par l'utilisateur peut modifier le chemin cible.",
        ),
        (
            "005",
            'config = open("/configs/" + config_name)',
            'config = open(safe_join("/configs", config_name))',

            "Path Traversal - config",
            "Un nom de configuration externe est utilisé sans validation.",
        ),
        (
            "006",
            'backup = "/backup/" + backup_name',
            'backup = safe_join("/backup", backup_name)',

            "Path Traversal - backup",
            "Le chemin d'une sauvegarde est contrôlé par une entrée externe.",
        ),
        (
            "007",
            'image = open("/images/" + image_name, "rb")',
            'image = open(safe_join("/images", image_name), "rb")',

            "Path Traversal - image",
            "Le nom d'image externe peut influencer le chemin du fichier.",
        ),
        (
            "008",
            'template = open("/templates/" + template_name).read()',
            'template = open(safe_join("/templates", template_name)).read()',

            "Path Traversal - template",
            "Le nom du template est utilisé directement pour construire un chemin.",
        ),
    ],
)


# ============================================================
# HARDCODED SECRET — CWE-798
# ============================================================

add_group(
    "secret",
    "CWE-798",
    [
        (
            "001",
            'API_KEY = "sk_live_123456789"',
            'API_KEY = os.environ["API_KEY"]',

            "Hardcoded API key",
            "Une clé API est stockée directement dans le code source.",
        ),
        (
            "002",
            'PASSWORD = "Admin@123"',
            'PASSWORD = os.environ["APP_PASSWORD"]',

            "Hardcoded password",
            "Un mot de passe est écrit en clair dans le code.",
        ),
        (
            "003",
            'TOKEN = "ghp_example_secret_token"',
            'TOKEN = os.getenv("GITHUB_TOKEN")',

            "Hardcoded token",
            "Un token d'accès est intégré directement dans le programme.",
        ),
        (
            "004",
            'SECRET_KEY = "django-secret-123"',
            'SECRET_KEY = os.environ["SECRET_KEY"]',

            "Hardcoded secret key",
            "Une clé secrète d'application est codée en dur.",
        ),
        (
            "005",
            'DB_PASSWORD = "database_password"',
            'DB_PASSWORD = os.environ["DB_PASSWORD"]',

            "Hardcoded database password",
            "Le mot de passe de base de données apparaît dans le code source.",
        ),
        (
            "006",
            'AWS_SECRET = "very-secret-value"',
            'AWS_SECRET = os.getenv("AWS_SECRET")',

            "Hardcoded cloud secret",
            "Un secret cloud est stocké directement dans le programme.",
        ),
        (
            "007",
            'PRIVATE_TOKEN = "token-value-123"',
            'PRIVATE_TOKEN = os.environ.get("PRIVATE_TOKEN")',

            "Hardcoded private token",
            "Un token privé est intégré dans le code.",
        ),
        (
            "008",
            'SMTP_PASSWORD = "mail-password"',
            'SMTP_PASSWORD = os.environ["SMTP_PASSWORD"]',

            "Hardcoded SMTP password",
            "Un mot de passe SMTP est présent en clair dans le code.",
        ),
    ],
)


# ============================================================
# WEAK CRYPTOGRAPHY — CWE-327
# ============================================================

add_group(
    "crypto",
    "CWE-327",
    [
        (
            "001",
            'cipher = DES.new(key, DES.MODE_ECB)',
            'cipher = AES.new(key, AES.MODE_GCM)',

            "Weak cryptography - DES",
            "L'algorithme DES est considéré comme cryptographiquement faible.",
        ),
        (
            "002",
            'cipher = ARC2.new(key)',
            'cipher = AES.new(key, AES.MODE_GCM)',

            "Weak cryptography - ARC2",
            "Un ancien algorithme cryptographique est utilisé.",
        ),
        (
            "003",
            'cipher = Blowfish.new(key)',
            'cipher = AES.new(key, AES.MODE_GCM)',

            "Weak cryptography - Blowfish",
            "Un algorithme ancien est utilisé pour protéger les données.",
        ),
        (
            "004",
            'cipher = DES3.new(key)',
            'cipher = AES.new(key, AES.MODE_GCM)',

            "Weak cryptography - 3DES",
            "Triple DES est utilisé au lieu d'un algorithme moderne.",
        ),
        (
            "005",
            'encrypted = legacy_encrypt(data)',
            'encrypted = modern_encrypt(data)',

            "Weak cryptography - legacy",
            "Une fonction cryptographique ancienne protège les données.",
        ),
        (
            "006",
            'algorithm = "RC4"',
            'algorithm = "AES-256-GCM"',

            "Weak cryptography - RC4",
            "RC4 est un algorithme obsolète et vulnérable.",
        ),
        (
            "007",
            'cipher_name = "DES"',
            'cipher_name = "AES-256-GCM"',

            "Weak cryptography - cipher selection",
            "Un algorithme faible est sélectionné pour le chiffrement.",
        ),
        (
            "008",
            'encryptor = LegacyCipher(key)',
            'encryptor = AESGCM(key)',

            "Weak cryptography - legacy cipher",
            "Une implémentation cryptographique ancienne est utilisée.",
        ),
    ],
)


# ============================================================
# DEBUG / MISCONFIGURATION — CWE-489
# ============================================================

add_group(
    "debug",
    "CWE-489",
    [
        (
            "001",
            'app.run(debug=True)',
            'app.run(debug=False)',

            "Debug mode enabled",
            "Le mode debug est activé dans une application déployée.",
        ),
        (
            "002",
            'DEBUG = True',
            'DEBUG = False',

            "Debug configuration",
            "Une configuration de production active le mode debug.",
        ),
        (
            "003",
            'flask_app.debug = True',
            'flask_app.debug = False',

            "Flask debug mode",
            "Le mode debug de Flask est explicitement activé.",
        ),
        (
            "004",
            'server_config["debug"] = True',
            'server_config["debug"] = False',

            "Server debug setting",
            "Le paramètre debug du serveur est activé.",
        ),
        (
            "005",
            'settings.DEBUG = True',
            'settings.DEBUG = False',

            "Application debug setting",
            "Le mode debug applicatif est activé.",
        ),
        (
            "006",
            'development_mode = True',
            'development_mode = False',

            "Development mode",
            "Le mode développement est laissé actif.",
        ),
        (
            "007",
            'config["DEBUG_MODE"] = True',
            'config["DEBUG_MODE"] = False',

            "Debug mode configuration",
            "Une option de debug est activée dans la configuration.",
        ),
        (
            "008",
            'DEBUG_ENABLED = True',
            'DEBUG_ENABLED = False',

            "Debug flag",
            "Un indicateur active le mode debug.",
        ),
    ],
)


# ============================================================
# UNSAFE DESERIALIZATION — CWE-502
# ============================================================

add_group(
    "deserialize",
    "CWE-502",
    [
        (
            "001",
            'obj = pickle.loads(user_data)',
            'obj = json.loads(user_data)',

            "Unsafe deserialization - pickle",
            "Des données externes sont désérialisées avec pickle.",
        ),
        (
            "002",
            'data = pickle.load(uploaded_file)',
            'data = json.load(uploaded_file)',

            "Unsafe deserialization - file",
            "Un fichier externe est chargé directement avec pickle.",
        ),
        (
            "003",
            'session = pickle.loads(request.data)',
            'session = json.loads(request.data)',

            "Unsafe deserialization - request",
            "Les données d'une requête sont désérialisées avec pickle.",
        ),
        (
            "004",
            'payload = dill.loads(raw_payload)',
            'payload = json.loads(raw_payload)',

            "Unsafe deserialization - dill",
            "Un payload externe est désérialisé avec une bibliothèque dangereuse.",
        ),
        (
            "005",
            'value = pickle.loads(message)',
            'value = json.loads(message)',

            "Unsafe deserialization - message",
            "Un message externe est désérialisé avec pickle.",
        ),
        (
            "006",
            'obj = yaml.load(data, Loader=yaml.Loader)',
            'obj = yaml.safe_load(data)',

            "Unsafe YAML deserialization",
            "YAML est chargé avec un loader non sécurisé.",
        ),
        (
            "007",
            'config = pickle.loads(config_data)',
            'config = json.loads(config_data)',

            "Unsafe config deserialization",
            "Une configuration externe est désérialisée avec pickle.",
        ),
        (
            "008",
            'result = pickle.loads(serialized)',
            'result = json.loads(serialized)',

            "Unsafe object deserialization",
            "Un objet provenant d'une source externe est désérialisé dangereusement.",
        ),
    ],
)


# ============================================================
# CRÉATION DU DATAFRAME
# ============================================================

df = pd.DataFrame(rows)


# ============================================================
# VÉRIFICATIONS
# ============================================================

print("=" * 70)
print("GÉNÉRATION DU DATASET PYTHON V3")
print("=" * 70)

print("\nNombre total :", len(df))

print("\nDistribution cible :")
print(df["real_vulnerability"].value_counts())

print("\nDistribution par type :")
print(df["vuln_type"].value_counts().sort_index())

print("\nNombre de groupes :", df["group_id"].nunique())

print("\nExemples par groupe :")
print(df.groupby("group_id").size().value_counts().sort_index())

print("\nValeurs manquantes :")
print(df.isnull().sum())

print("\nLangages :")
print(df["language"].value_counts())


# ============================================================
# SAUVEGARDE
# ============================================================

OUTPUT.parent.mkdir(parents=True, exist_ok=True)

df.to_csv(
    OUTPUT,
    index=False,
    encoding="utf-8",
)

print("\nDataset sauvegardé :")
print(OUTPUT)

print("\nGénération terminée.")
