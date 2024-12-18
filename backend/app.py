import smtplib
from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
from datetime import datetime, timedelta
from functools import wraps
import bcrypt
import secrets
import psycopg2
from email.mime.text import MIMEText
from Crypto.Cipher import AES, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
from Crypto.Util.Padding import pad, unpad

# PostgreSQL Bağlantısı
conn = psycopg2.connect(
    dbname="smart_email",
    user="postgres",
    password="12345",
    host="localhost",
    port="5432"
)
cursor = conn.cursor()

app = Flask(__name__)
CORS(app)

# SMTP Ayarları
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "metehaanguveen@gmail.com"
EMAIL_PASSWORD = "nlko anht xxtt rrtl"

# JWT Ayarları
SECRET_KEY = "my_secret_key"


# JWT Token Doğrulama
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-access-token")
        if not token:
            return jsonify({"error": "Token eksik."}), 403
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data["email"]
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token süresi dolmuş."}), 403
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token geçersiz."}), 403
        return f(current_user, *args, **kwargs)
    return decorated

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt_aes(message, key):
    key = key.ljust(16)[:16].encode('utf-8')
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode('utf-8'))
    encrypted_data = cipher.nonce + tag + ciphertext
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_aes(encrypted_message, key):
    key = key.ljust(16)[:16].encode('utf-8')
    encrypted_data = base64.b64decode(encrypted_message)
    nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    message = cipher.decrypt_and_verify(ciphertext, tag)
    return message.decode('utf-8')

# Blowfish Şifreleme ve Çözme
def encrypt_blowfish(message, key):
    key = key.ljust(16)[:16].encode('utf-8')
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    padded_message = message.encode('utf-8') + (b"\x00" * (8 - len(message.encode('utf-8')) % 8))
    ciphertext = cipher.encrypt(padded_message)
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_blowfish(encrypted_message, key):
    key = key.ljust(16)[:16].encode('utf-8')
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    ciphertext = base64.b64decode(encrypted_message)
    decrypted_message = cipher.decrypt(ciphertext).rstrip(b'\x00')
    return decrypted_message.decode('utf-8')

# RSA Şifreleme ve Çözme
def encrypt_rsa(message, public_key_str):
    public_key = RSA.import_key(public_key_str.encode('utf-8'))
    cipher = PKCS1_OAEP.new(public_key)
    ciphertext = cipher.encrypt(message.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_rsa(encrypted_message, private_key_str):
    private_key = RSA.import_key(private_key_str.encode('utf-8'))
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(base64.b64decode(encrypted_message))
    return decrypted_message.decode('utf-8')


# Kayıt Rotası
@app.route('/register', methods=['POST'])
def register_user():
    try:
        data = request.json
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        if not username or not email or not password:
            return jsonify({"error": "Tüm alanlar gereklidir."}), 400

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        verification_code = secrets.token_hex(3)

        cursor.execute(
            "INSERT INTO users (username, email, password, verification_code, is_verified) VALUES (%s, %s, %s, %s, %s)",
            (username, email, hashed_password.decode('utf-8'), verification_code, False)
        )
        conn.commit()

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            email_message = MIMEText(
                f"Kayıt işleminizi tamamlamak için doğrulama kodu:\n{verification_code}",
                "plain",
                "utf-8"
            )
            email_message["From"] = EMAIL_ADDRESS
            email_message["To"] = email
            email_message["Subject"] = "Kayıt Doğrulama Kodu"
            server.sendmail(EMAIL_ADDRESS, email, email_message.as_string())

        return jsonify({"message": "Kayıt başarılı. Doğrulama kodu e-posta adresinize gönderildi."}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

# Doğrulama Rotası
@app.route('/verify', methods=['POST'])
def verify_user():
    try:
        data = request.json
        email = data['email']
        verification_code = data['verification_code']

        cursor.execute("SELECT verification_code FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()

        if not result:
            return jsonify({"error": "Kullanıcı bulunamadı."}), 404

        stored_code = result[0]
        if stored_code != verification_code:
            return jsonify({"error": "Doğrulama kodu geçersiz."}), 400

        cursor.execute("UPDATE users SET is_verified = TRUE WHERE email = %s", (email,))
        conn.commit()

        return jsonify({"message": "Kullanıcı başarıyla doğrulandı."})
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500

# Giriş Rotası
@app.route('/login', methods=['POST'])
def login_user():
    try:
        data = request.json
        username = data['username']
        password = data['password']

        cursor.execute("SELECT password, is_verified, email FROM users WHERE username = %s", (username,))
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "Kullanıcı bulunamadı."}), 404

        hashed_password, is_verified, email = user
        if not is_verified:
            return jsonify({"error": "Kullanıcı henüz doğrulanmamış."}), 403

        if not bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
            return jsonify({"error": "Yanlış şifre."}), 401

        token = jwt.encode({"username": username, "email": email, "exp": datetime.utcnow() + timedelta(hours=1)}, SECRET_KEY, algorithm="HS256")
        return jsonify({"message": "Giriş başarılı.", "token": token}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# Şifre Çözme Rotası
@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        encrypted_message = data.get('encrypted_message')
        algorithm = data.get('algorithm')
        key = data.get('key')

        if algorithm == "AES":
            decrypted_message = decrypt_aes(encrypted_message, key)
        elif algorithm == "Blowfish":
            decrypted_message = decrypt_blowfish(encrypted_message, key)
        elif algorithm == "RSA":
            if not key:
                return jsonify({"error": "RSA anahtarı gereklidir."}), 400
            decrypted_message = decrypt_rsa(encrypted_message, key)
        else:
            return jsonify({"error": "Geçersiz algoritma türü."}), 400

        return jsonify({
            "message": "Şifre çözme işlemi başarılı.",
            "decrypted_message": decrypted_message
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Şifreleme Rotası
@app.route('/encrypt', methods=['POST'])
@token_required
def encrypt_message(current_user):
    try:
        data = request.json
        recipient_email = data.get('recipient_email')
        message = data['message']
        sensitivity = data['sensitivity']
        key = data.get('key', None)

        if not recipient_email:
            return jsonify({"error": "Alıcı e-posta gereklidir."}), 400

        if sensitivity == "Low":
            algorithm = "AES"
            key = key or "defaultaeskey1234"
            encrypted_message = encrypt_aes(message, key)
        elif sensitivity == "Medium":
            algorithm = "Blowfish"
            key = key or "defaultblowfish"
            encrypted_message = encrypt_blowfish(message, key)
        elif sensitivity == "High":
            algorithm = "RSA"
            if not key:
                return jsonify({"error": "RSA anahtarı gereklidir."}), 400
            try:
                encrypted_message = encrypt_rsa(message, key)
            except Exception as e:
                logging.error(f"RSA şifreleme hatası: {str(e)}")
                return jsonify({"error": f"RSA şifreleme hatası: {str(e)}"}), 500
        else:
            return jsonify({"error": "Geçersiz hassasiyet seviyesi."}), 400

        # E-posta gönderimi
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            email_message = MIMEText(
                f"Şifrelenmiş Mesaj:\n{encrypted_message}\n\n"
                f"Kullanılan Algoritma: {algorithm}\n"
                f"Anahtar: {key if algorithm != 'RSA' else 'RSA özel anahtar gerekli'}",
                "plain",
                "utf-8"
            )
            email_message["From"] = EMAIL_ADDRESS
            email_message["To"] = recipient_email
            email_message["Subject"] = "Şifrelenmiş Mesaj Gönderimi"
            server.sendmail(EMAIL_ADDRESS, recipient_email, email_message.as_string())

        return jsonify({
            "message": "Mesaj başarıyla şifrelendi ve gönderildi.",
            "encrypted_message": encrypted_message,
            "algorithm": algorithm
        }), 200
    except Exception as e:
        logging.error(f"Genel şifreleme hatası: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
