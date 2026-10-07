import pandas as pd
from pathlib import Path

OUTPUT = Path("ml/data/raw/python_security_dataset.csv")


def add(rows, vuln_type, cwe, title, description, code, label):
    rows.append({
        "vuln_type": vuln_type,
        "cwe": cwe,
        "title": title,
        "description": description,
        "code_line": code,
        "real_vulnerability": label,
        "language": "Python",
    })


def main():
    rows = []

    # ==========================================================
    # SQL INJECTION
    # ==========================================================

    sqli_vulnerable = [
        'query = "SELECT * FROM users WHERE id = " + user_id',
        'query = "SELECT * FROM users WHERE name = \'" + name + "\'"',
        'sql = "DELETE FROM users WHERE id = " + user_id',
        'sql = "UPDATE users SET name = \'" + name + "\'"',
        'cursor.execute("SELECT * FROM users WHERE id = " + user_id)',
        'db.execute("SELECT * FROM products WHERE name = \'" + product + "\'")',
        'query = f"SELECT * FROM users WHERE id = {user_id}"',
        'sql = f"SELECT * FROM accounts WHERE name = \'{name}\'"',
        'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        'query = "SELECT password FROM users WHERE login = \'" + login + "\'"',
    ]

    sqli_safe = [
        'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))',
        'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))',
        'db.execute("DELETE FROM users WHERE id = ?", (user_id,))',
        'cursor.execute("UPDATE users SET name = ? WHERE id = ?", (name, user_id))',
        'cursor.execute("SELECT * FROM products WHERE name = ?", (product,))',
        'query = "SELECT * FROM users WHERE id = %s"',
        'cursor.execute(query, (user_id,))',
        'User.query.filter_by(id=user_id).first()',
        'User.query.filter_by(name=name).first()',
        'session.execute(text("SELECT * FROM users WHERE id=:id"), {"id": user_id})',
    ]

    for code in sqli_vulnerable:
        add(rows, "sqli", "CWE-89", "SQL Injection",
            "User-controlled data is directly incorporated into an SQL statement.",
            code, 1)

    for code in sqli_safe:
        add(rows, "sqli", "CWE-89", "SQL Injection",
            "User input is passed through a parameterized database query.",
            code, 0)

    # ==========================================================
    # XSS
    # ==========================================================

    xss_vulnerable = [
        'return "<h1>" + name + "</h1>"',
        'return "<div>" + username + "</div>"',
        'html = "<p>" + comment + "</p>"',
        'response = "<script>" + value + "</script>"',
        'return render_template_string("<h1>" + name + "</h1>")',
        'message = "<div>" + message + "</div>"',
        'return "<span>" + request.args["name"] + "</span>"',
        'html = f"<h1>{name}</h1>"',
        'return f"<p>{comment}</p>"',
        'content = "<body>" + user_input + "</body>"',
    ]

    xss_safe = [
        'return escape(name)',
        'return render_template("index.html", name=name)',
        'return render_template("profile.html", username=username)',
        'html = escape(comment)',
        'return jsonify({"message": message})',
        'response = escape(value)',
        'safe_name = html.escape(name)',
        'return render_template("page.html", value=value)',
        'content = html.escape(user_input)',
        'return jsonify({"content": user_input})',
    ]

    for code in xss_vulnerable:
        add(rows, "xss", "CWE-79", "Cross-Site-Scripting",
            "User-controlled data is inserted into an HTML response without proper escaping.",
            code, 1)

    for code in xss_safe:
        add(rows, "xss", "CWE-79", "Cross-Site-Scripting",
            "User-controlled data is safely encoded or rendered using a template.",
            code, 0)

    # ==========================================================
    # COMMAND INJECTION
    # ==========================================================

    cmdi_vulnerable = [
        'os.system("ping " + host)',
        'os.system("ls " + directory)',
        'subprocess.call("ping " + host, shell=True)',
        'subprocess.check_output(command, shell=True)',
        'subprocess.Popen("cat " + filename, shell=True)',
        'subprocess.run("nslookup " + domain, shell=True)',
        'os.popen("grep " + pattern + " file.txt")',
        'command = "ping " + host; os.system(command)',
        'subprocess.call("curl " + url, shell=True)',
        'subprocess.run(command, shell=True)',
    ]

    cmdi_safe = [
        'subprocess.run(["ping", "-c", "1", host], shell=False)',
        'subprocess.run(["ls", directory], shell=False)',
        'subprocess.check_output(["ping", "-c", "1", host])',
        'subprocess.run(["nslookup", domain], shell=False)',
        'subprocess.run(["cat", filename], shell=False)',
        'subprocess.Popen(["grep", pattern, "file.txt"])',
        'subprocess.run(["curl", url], shell=False)',
        'subprocess.check_call(["ping", "-c", "1", host])',
        'subprocess.run(["python", script], shell=False)',
        'subprocess.run(["git", "status"], shell=False)',
    ]

    for code in cmdi_vulnerable:
        add(rows, "cmdi", "CWE-78", "Command Injection",
            "User-controlled input can influence an operating system command.",
            code, 1)

    for code in cmdi_safe:
        add(rows, "cmdi", "CWE-78", "Command Injection",
            "Command execution uses a fixed argument list without shell interpretation.",
            code, 0)

    # ==========================================================
    # PATH TRAVERSAL
    # ==========================================================

    path_vulnerable = [
        'open("/var/www/" + filename).read()',
        'open(base_dir + request.args["file"]).read()',
        'path = "/tmp/" + filename',
        'with open(user_path) as f:',
        'file_path = directory + "/" + filename',
        'send_file("/uploads/" + filename)',
        'open(request.args["path"]).read()',
        'data = open("../files/" + filename).read()',
        'path = os.path.join("/var/www", filename)',
        'return send_file(user_input)',
    ]

    path_safe = [
        'path = os.path.join(SAFE_DIR, secure_filename(filename))',
        'filename = secure_filename(request.args["file"])',
        'path = Path(SAFE_DIR) / safe_name',
        'if filename not in allowed_files: abort(404)',
        'path = safe_join(SAFE_DIR, filename)',
        'safe_name = os.path.basename(filename)',
        'if ".." in filename: abort(400)',
        'path = Path(SAFE_DIR).resolve() / Path(filename).name',
        'filename = werkzeug.utils.secure_filename(filename)',
        'return send_file(os.path.join(SAFE_DIR, filename))',
    ]

    for code in path_vulnerable:
        add(rows, "pathtraver", "CWE-22", "Path Traversal",
            "User-controlled input is used to access a filesystem path without sufficient validation.",
            code, 1)

    for code in path_safe:
        add(rows, "pathtraver", "CWE-22", "Path Traversal",
            "The requested file is restricted using path validation or filename sanitization.",
            code, 0)

    # ==========================================================
    # DEBUG
    # ==========================================================

    debug_vulnerable = [
        "app.run(debug=True)",
        "Flask(__name__, debug=True)",
        "app.config['DEBUG'] = True",
        "app.debug = True",
        "application.run(debug=True)",
        "DEBUG = True",
        "config['DEBUG'] = True",
        "app.run(host='0.0.0.0', debug=True)",
        "flask_app.run(debug=True)",
        "server.start(debug=True)",
    ]

    debug_safe = [
        "app.run(debug=False)",
        "Flask(__name__, debug=False)",
        "app.config['DEBUG'] = False",
        "app.debug = False",
        "application.run(debug=False)",
        "DEBUG = False",
        "config['DEBUG'] = False",
        "app.run(host='0.0.0.0', debug=False)",
        "flask_app.run(debug=False)",
        "server.start(debug=False)",
    ]

    for code in debug_vulnerable:
        add(rows, "debug", "CWE-489", "Active Debug Code",
            "Debug mode is enabled and should not be active in production.",
            code, 1)

    for code in debug_safe:
        add(rows, "debug", "CWE-489", "Active Debug Code",
            "Debug mode is disabled.",
            code, 0)

    # ==========================================================
    # HARDcoded SECRET
    # ==========================================================

    secret_vulnerable = [
        'API_KEY = "sk_live_123456"',
        'PASSWORD = "admin123"',
        'SECRET_KEY = "super-secret-key"',
        'TOKEN = "ghp_123456789"',
        'AWS_SECRET = "AKIA123456SECRET"',
        'DB_PASSWORD = "root123"',
        'JWT_SECRET = "my-secret"',
        'API_TOKEN = "token123"',
        'PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----"',
        'password = "P@ssw0rd123"',
    ]

    secret_safe = [
        'API_KEY = os.getenv("API_KEY")',
        'PASSWORD = os.getenv("DB_PASSWORD")',
        'SECRET_KEY = os.environ["SECRET_KEY"]',
        'TOKEN = os.getenv("API_TOKEN")',
        'AWS_SECRET = os.environ.get("AWS_SECRET")',
        'DB_PASSWORD = os.getenv("DB_PASSWORD")',
        'JWT_SECRET = os.getenv("JWT_SECRET")',
        'API_TOKEN = config["API_TOKEN"]',
        'PRIVATE_KEY = os.environ.get("PRIVATE_KEY")',
        'password = get_secret("DB_PASSWORD")',
    ]

    for code in secret_vulnerable:
        add(rows, "secret", "CWE-798", "Hardcoded Secret",
            "A sensitive credential or secret is embedded directly in source code.",
            code, 1)

    for code in secret_safe:
        add(rows, "secret", "CWE-798", "Hardcoded Secret",
            "The sensitive value is loaded from an external configuration or secret store.",
            code, 0)

    # ==========================================================
    # WEAK CRYPTOGRAPHY
    # ==========================================================

    crypto_vulnerable = [
        "hashlib.md5(password.encode()).hexdigest()",
        "hashlib.sha1(data).hexdigest()",
        "md5(data)",
        "sha1(password)",
        "hashlib.md5(token.encode())",
        "hashlib.sha1(secret.encode())",
        "Crypto.Hash.MD5.new(data)",
        "Crypto.Hash.SHA1.new(data)",
        "hashlib.new('md5', data)",
        "hashlib.new('sha1', data)",
    ]

    crypto_safe = [
        "bcrypt.hashpw(password.encode(), bcrypt.gensalt())",
        "argon2.PasswordHasher().hash(password)",
        "hashlib.sha256(data).hexdigest()",
        "hashlib.sha512(data).hexdigest()",
        "hmac.new(key, data, hashlib.sha256)",
        "hmac.new(key, data, hashlib.sha512)",
        "secrets.token_hex(32)",
        "secrets.token_urlsafe(32)",
        "cryptography.fernet.Fernet(key)",
        "bcrypt.checkpw(password.encode(), hashed)",
    ]

    for code in crypto_vulnerable:
        add(rows, "crypto", "CWE-327", "Weak Cryptography",
            "A weak or outdated cryptographic algorithm is used.",
            code, 1)

    for code in crypto_safe:
        add(rows, "crypto", "CWE-327", "Weak Cryptography",
            "A modern or appropriate cryptographic mechanism is used.",
            code, 0)

    # ==========================================================
    # INSECURE DESERIALIZATION
    # ==========================================================

    deserialize_vulnerable = [
        "pickle.loads(user_data)",
        "pickle.load(file)",
        "yaml.load(data)",
        "yaml.load(stream)",
        "dill.loads(data)",
        "marshal.loads(data)",
        "joblib.load(user_file)",
        "torch.load(user_file)",
        "pickle.Unpickler(file).load()",
        "pickle.loads(request.data)",
    ]

    deserialize_safe = [
        "json.loads(user_data)",
        "json.load(file)",
        "yaml.safe_load(data)",
        "yaml.safe_load(stream)",
        "json.loads(request.data)",
        "json.load(request.files['file'])",
        "ast.literal_eval(data)",
        "json.loads(response.text)",
        "safe_data = json.loads(data)",
        "payload = yaml.safe_load(request.data)",
    ]

    for code in deserialize_vulnerable:
        add(rows, "deserialize", "CWE-502", "Insecure Deserialization",
            "Untrusted data is deserialized using a potentially unsafe mechanism.",
            code, 1)

    for code in deserialize_safe:
        add(rows, "deserialize", "CWE-502", "Insecure Deserialization",
            "Input is parsed using a safer data serialization format.",
            code, 0)

    # ==========================================================
    # DATASET FINAL
    # ==========================================================

    df = pd.DataFrame(rows)

    df.insert(0, "id", [f"PY{i:04d}" for i in range(1, len(df) + 1)])

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUTPUT, index=False)

    print("=" * 60)
    print("DATASET PYTHON CREE")
    print("=" * 60)
    print(f"Fichier : {OUTPUT}")
    print(f"Nombre total : {len(df)}")
    print(f"Vulnerables : {(df.real_vulnerability == 1).sum()}")
    print(f"Non vulnerables : {(df.real_vulnerability == 0).sum()}")
    print("\nDistribution par type :")
    print(df["vuln_type"].value_counts())
    print("\nDistribution cible :")
    print(df["real_vulnerability"].value_counts())


if __name__ == "__main__":
    main()
