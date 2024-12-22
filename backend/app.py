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
from ecies.utils import generate_eth_key
from ecies import encrypt as ecies_encrypt, decrypt as ecies_decrypt
from Crypto.Cipher import ChaCha20_Poly1305


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
EMAIL_ADDRESS = "metehantest1010@gmail.com"
EMAIL_PASSWORD = "zuud paya hnzd zpju"

# JWT Ayarları
SECRET_KEY = "my_secret_key"


# JWT Token Doğrulama
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("x-access-token")
        if not token:
            print("Token eksik!")
            return jsonify({"error": "Token eksik."}), 403
        try:
            data = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
            current_user = data["email"]
        except jwt.ExpiredSignatureError:
            print("Token süresi dolmuş!")
            return jsonify({"error": "Token süresi dolmuş."}), 403
        except jwt.InvalidTokenError:
            print("Geçersiz token!")
            return jsonify({"error": "Token geçersiz."}), 403
        return f(current_user, *args, **kwargs)
    return decorated

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os

def format_key(key, length):
    return key.encode('utf-8')[:length].ljust(length, b'\0')

def encrypt_aes(plaintext, key):
    key = key.encode('utf-8')
    if len(key) not in [16, 24, 32]:
        raise ValueError("Anahtar uzunluğu 16, 24 veya 32 bayt olmalıdır.")

    iv = os.urandom(16)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))

    encrypted_data = base64.b64encode(iv + ciphertext).decode('utf-8')
    return encrypted_data

def decrypt_aes(encrypted_data, key):
    key = key.encode('utf-8')
    if len(key) not in [16, 24, 32]:
        raise ValueError("Anahtar uzunluğu 16, 24 veya 32 bayt olmalıdır.")
    
    encrypted_data = base64.b64decode(encrypted_data)
    
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
  
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size).decode('utf-8')
    return plaintext

from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import os

def encrypt_blowfish(plaintext, key):
    key = key.encode('utf-8')[:56]  # Max 56 byte
    iv = os.urandom(8)  # 8 byte IV
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext.encode('utf-8'), Blowfish.block_size))
    return base64.b64encode(iv + ciphertext).decode('utf-8')

def decrypt_blowfish(ciphertext_b64, key):
    key = key.encode('utf-8')[:56]
    ciphertext = base64.b64decode(ciphertext_b64)
    iv, ct = ciphertext[:8], ciphertext[8:]
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ct), Blowfish.block_size)
    return plaintext.decode('utf-8')

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
import os
import base64

def encrypt_chacha20_poly1305(plaintext, key):
    """
    ChaCha20-Poly1305 şifreleme fonksiyonu.
    Args:
        plaintext (str): Şifrelenecek metin.
        key (str): 32 byte uzunluğunda şifreleme anahtarı.
    Returns:
        str: Base64 ile kodlanmış şifreli metin.
    """
    if len(key) != 32:
        raise ValueError("Key 32 byte (256 bit) uzunluğunda olmalıdır.")
    
    key_bytes = key.encode('utf-8') 
    nonce = os.urandom(12)  
    chacha = ChaCha20Poly1305(key_bytes)
    ciphertext = chacha.encrypt(nonce, plaintext.encode('utf-8'), None)
    return base64.b64encode(nonce + ciphertext).decode('utf-8')

def decrypt_chacha20_poly1305(ciphertext_b64, key):
    """
    ChaCha20-Poly1305 çözme fonksiyonu.
    Args:
        ciphertext_b64 (str): Base64 ile kodlanmış şifreli metin.
        key (str): 32 byte uzunluğunda şifreleme anahtarı.
    Returns:
        str: Çözülen düz metin.
    """
    if len(key) != 32:
        raise ValueError("Key 32 byte (256 bit) uzunluğunda olmalıdır.")
    
    key_bytes = key.encode('utf-8')  
    ciphertext = base64.b64decode(ciphertext_b64)
    nonce = ciphertext[:12]  
    ct = ciphertext[12:]  
    chacha = ChaCha20Poly1305(key_bytes)
    plaintext = chacha.decrypt(nonce, ct, None)
    return plaintext.decode('utf-8')


from ecies.utils import generate_eth_key
from ecies import encrypt, decrypt

def generate_ecc_keypair():
    eth_key = generate_eth_key()
    private_key_hex = eth_key.to_hex()
    public_key_hex = eth_key.public_key.to_hex()
    return private_key_hex, public_key_hex

def encrypt_ecies(plaintext, public_key_hex):
    ciphertext = ecies_encrypt(public_key_hex, plaintext.encode('utf-8'))
    return base64.b64encode(ciphertext).decode('utf-8')

def decrypt_ecies(ciphertext_b64, private_key_hex):
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = ecies_decrypt(private_key_hex, ciphertext)
    return plaintext.decode('utf-8')


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

        token = jwt.encode({"username": username, "email": email, "exp": datetime.utcnow() + timedelta(hours=3)}, SECRET_KEY, algorithm="HS256")
        return jsonify({"message": "Giriş başarılı.", "token": token}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/encrypt', methods=['POST'])
@token_required
def encrypt_message(current_user):
    try:
        print(f"İstek JSON Verisi: {request.json}")
        data = request.json

        recipient_email = data.get('recipient_email')
        message = data.get('message')
        sensitivity = data.get('sensitivity')

        print(f"Recipient: {recipient_email}, Sensitivity: {sensitivity}")

        if not recipient_email:
            return jsonify({"error": "Alıcı e-posta gereklidir."}), 400

        if not message or not message.strip():
            return jsonify({"error": "Mesaj boş olamaz."}), 400

        if sensitivity == "Low":
            algorithm = "AES"
            key = "defaultaeskey123"
            encrypted_message = encrypt_aes(message, key)
            private_key = key
            print(f"AES Encrypted Message: {encrypted_message}")

        elif sensitivity == "Medium":
            algorithm = "Blowfish"
            key = "defaultblowfish"
            encrypted_message = encrypt_blowfish(message, key)
            private_key = key
            print(f"Blowfish Encrypted Message: {encrypted_message}")

        elif sensitivity == "High":
            algorithm = "ChaCha20-Poly1305"
            key = "12345678901234567890123456789012"
            encrypted_message = encrypt_chacha20_poly1305(message, key)
            private_key = key
            print(f"ChaCha20-Poly1305 Encrypted Message: {encrypted_message}")

        elif sensitivity == "Asymmetric":
            algorithm = "ECIES-secp256k1"
            priv_hex, pub_hex = generate_ecc_keypair()
            encrypted_message = encrypt_ecies(message, pub_hex)
            private_key = priv_hex
            print(f"ECIES Encrypted Message: {encrypted_message}")

        else:
            return jsonify({"error": "Geçersiz hassasiyet seviyesi."}), 400

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            email_body = f"Şifrelenmiş Mesaj:\n{encrypted_message}"
            email_message = MIMEText(email_body, "plain", "utf-8")
            email_message["From"] = EMAIL_ADDRESS
            email_message["To"] = recipient_email
            email_message["Subject"] = "Şifrelenmiş Mesaj Gönderimi"
            server.sendmail(EMAIL_ADDRESS, recipient_email, email_message.as_string())
            print("E-posta başarıyla gönderildi.")

        return jsonify({
            "message": "Mesaj başarıyla şifrelendi ve gönderildi.",
            "encrypted_message": encrypted_message,
            "algorithm": algorithm,
            "private_key": private_key
        }), 200

    except Exception as e:
        print(f"Hata: {e}")  
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt_message():
    try:
        data = request.json
        encrypted_message = data.get('encrypted_message')
        algorithm = data.get('algorithm')
        key = data.get('key', None)            
        private_key = data.get('private_key', None)

        if algorithm == "AES":
            decrypted_message = decrypt_aes(encrypted_message, key)

        elif algorithm == "Blowfish":
            decrypted_message = decrypt_blowfish(encrypted_message, key)

        elif algorithm == "ChaCha20-Poly1305":
            if not private_key:
                return jsonify({"error": "ChaCha20 key gereklidir."}), 400
            decrypted_message = decrypt_chacha20_poly1305(encrypted_message, private_key)

        elif algorithm == "ECIES-secp256k1":

            if not private_key:
                return jsonify({"error": "ECIES private key gereklidir."}), 400

            decrypted_message = decrypt_ecies(encrypted_message, private_key)

        else:
            return jsonify({"error": "Geçersiz algoritma."}), 400

        return jsonify({
            "message": "Şifre çözme başarılı.",
            "decrypted_message": decrypted_message
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)

