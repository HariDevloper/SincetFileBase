from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
import os, json, base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import gspread
from oauth2client.service_account import ServiceAccountCredentials
from werkzeug.utils import secure_filename
from io import BytesIO

app = Flask(__name__)
app.secret_key = "9597937366"

# Folders
UPLOAD_FOLDER = "uploads"
PUBLIC_FOLDER = os.path.join(UPLOAD_FOLDER, "public")
PRIVATE_FOLDER = os.path.join(UPLOAD_FOLDER, "private")
os.makedirs(PUBLIC_FOLDER, exist_ok=True)
os.makedirs(PRIVATE_FOLDER, exist_ok=True)

META_FILE = os.path.join(UPLOAD_FOLDER, "file_meta.json")

# Load metadata
if os.path.exists(META_FILE):
    with open(META_FILE, "r") as f:
        file_meta = json.load(f)
else:
    file_meta = {}

# Define the Google Sheets API scope
scope = ["https://spreadsheets.google.com/feeds",
         "https://www.googleapis.com/auth/drive"]

# Load JSON key from environment variable
key_dict = json.loads(os.environ.get("GOOGLE_CREDENTIALS"))

# Authorize and connect to the sheet
creds = ServiceAccountCredentials.from_json_keyfile_dict(key_dict, scope)
client = gspread.authorize(creds)
sheet = client.open("students_login").sheet1


# --- helper functions ----------------
def meta_key(type_, user, filename):
    return f"public/{filename}" if type_ == "public" else f"private/{user}/{filename}"

def save_meta(key, meta_dict):
    file_meta[key] = meta_dict
    with open(META_FILE, "w") as meta:
        json.dump(file_meta, meta)

def validate_login(username, password):
    for row in sheet.get_all_records():
        if row["username"] == username and row["password"] == password:
            return True
    return False

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_file(file_data: bytes, password: str = None) -> tuple[bytes, str]:
    if password:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        encrypted = fernet.encrypt(file_data)
        return salt + encrypted, None
    else:
        key = Fernet.generate_key()
        fernet = Fernet(key)
        encrypted = fernet.encrypt(file_data)
        return encrypted, key.decode()

def decrypt_file(file_data: bytes, password: str = None, key_info: str = None) -> bytes:
    if password:
        if not file_data or len(file_data) <= 16:
            raise InvalidToken("Corrupt or too-short encrypted blob")
        salt = file_data[:16]
        encrypted = file_data[16:]
        key = derive_key(password, salt)
        fernet = Fernet(key)
        return fernet.decrypt(encrypted)
    elif key_info:
        fernet = Fernet(key_info.encode())
        return fernet.decrypt(file_data)
    else:
        raise ValueError("No password or key info provided for decryption")

# ✅ Routes
@app.route("/")
def index():
    return redirect(url_for("public"))

@app.route("/public", methods=["GET", "POST"])
def public():
    if request.method == "POST":
        f = request.files["file"]
        filename = secure_filename(f.filename)
        uploader = request.form.get("uploader", "Anonymous")
        description = request.form.get("description", "")
        password = request.form.get("password", "")
        file_path = os.path.join(PUBLIC_FOLDER, filename)
        data = f.read()
        encrypted_data, key_info = encrypt_file(data, password if password else None)
        with open(file_path, "wb") as out:
            out.write(encrypted_data)

        meta = {
            "type": "public",
            "uploader": uploader,
            "description": description,
            "size": round(len(data)/1024, 2),
            "filename": filename,
            "protected": bool(password),
            "key_info": key_info
        }
        save_meta(meta_key("public", "", filename), meta)
        flash("✅ File uploaded successfully", "success")
        return redirect(url_for("public"))

    public_files = {}
    for fn in os.listdir(PUBLIC_FOLDER):
        meta = file_meta.get(
            meta_key("public", "", fn),
            {"protected": False, "uploader": "-", "description": "-", "size": 0}
        )
        public_files[fn] = meta
    return render_template("public.html", files=public_files)


@app.route("/download/<filename>", methods=["GET", "POST"])
def download(filename):
    # Find candidates in metadata
    candidates = [k for k in file_meta.keys() if k.endswith("/" + filename)]
    if not candidates:
        flash("❌ File not found", "danger")
        return redirect(url_for("public"))

    # Prefer public file, else private of current user
    meta_key_chosen = None
    for k in candidates:
        if file_meta[k].get("type") == "public":
            meta_key_chosen = k
            break
    if not meta_key_chosen:
        user = session.get("user")
        for k in candidates:
            if file_meta[k].get("type") == "private" and file_meta[k].get("uploader") == user:
                meta_key_chosen = k
                break
    if not meta_key_chosen:
        flash("❌ Unauthorized or file not found", "danger")
        return redirect(url_for("login") if "user" not in session else url_for("public"))

    meta = file_meta[meta_key_chosen]
    folder = PUBLIC_FOLDER if meta.get("type") == "public" else os.path.join(PRIVATE_FOLDER, meta.get("uploader"))
    file_path = os.path.join(folder, filename)

    if request.method == "POST":
        password = request.form.get("password", None)  # None if empty
        try:
            with open(file_path, "rb") as f:
                raw = f.read()
            # Use password if protected, else key_info
            if meta.get("protected"):
                decrypted = decrypt_file(raw, password=password)
            else:
                decrypted = decrypt_file(raw, key_info=meta.get("key_info"))
        except InvalidToken:
            flash("❌ Invalid password or corrupted file", "danger")
            return redirect(url_for("download", filename=filename))
        except Exception:
            flash("❌ Error reading file", "danger")
            return redirect(url_for("public"))

        return send_file(BytesIO(decrypted), as_attachment=True, download_name=filename)

    back_url = url_for('public') if meta.get("type") == "public" else url_for('private')
    return render_template("download.html", filename=filename, meta=meta, back_url=back_url)

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if validate_login(username, password):
            session["user"] = username
            return redirect(url_for("private"))
        flash("❌ Invalid login", "danger")
    return render_template("login.html")


@app.route("/private", methods=["GET", "POST"])
def private():
    if "user" not in session:
        return redirect(url_for("login"))
    user = session["user"]
    user_folder = os.path.join(PRIVATE_FOLDER, user)
    os.makedirs(user_folder, exist_ok=True)

    if request.method == "POST":
        f = request.files["file"]
        filename = secure_filename(f.filename)
        password = request.form.get("password", "")
        description = request.form.get("description", "")
        file_path = os.path.join(user_folder, filename)

        # Encrypt file
        data = f.read()
        encrypted_data, key_info = encrypt_file(data, password if password else None)
        with open(file_path, "wb") as out:
            out.write(encrypted_data)

        # Save metadata exactly like public
        meta = {
            "type": "private",
            "uploader": user,
            "description": description,
            "size": round(len(data)/1024, 2),
            "filename": filename,
            "protected": bool(password),
            "key_info": key_info
        }
        key = meta_key("private", user, filename)
        save_meta(key, meta)

        flash("✅ Private file uploaded", "success")
        return redirect(url_for("private"))

    # Show all private files for current user
    user_meta = {}
    for fn in os.listdir(user_folder):
        key = meta_key("private", user, fn)
        meta = file_meta.get(key, {"filename": fn, "protected": False, "uploader": user, "description": "-", "size": 0})
        user_meta[fn] = meta

    return render_template("private.html", file_meta=user_meta, user=user)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("public"))

if __name__ == "__main__":
    app.run(debug=True)


