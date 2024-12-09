from Crypto.Cipher import AES, Blowfish, PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# AES Şifre Çözme Fonksiyonu
def decrypt_aes(encrypted_message, key):
    try:
        key = key.ljust(16)[:16]  # 16 byte uzunluk
        decoded_message = base64.b64decode(encrypted_message)
        nonce = decoded_message[:16]
        tag = decoded_message[16:32]
        ciphertext = decoded_message[32:]

        cipher = AES.new(key.encode("utf-8"), AES.MODE_EAX, nonce=nonce)
        decrypted_message = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_message.decode("utf-8")
    except Exception as e:
        return f"Hata oluştu (AES): {e}"


# Blowfish Şifre Çözme Fonksiyonu
def decrypt_blowfish(encrypted_message, key):
    try:
        key = key.ljust(16)[:16]  # Blowfish anahtar uzunluğunu 16 byte'a ayarla
        decoded_message = base64.b64decode(encrypted_message)
        
        cipher = Blowfish.new(key.encode("utf-8"), Blowfish.MODE_ECB)
        decrypted_message = cipher.decrypt(decoded_message)
        
        # Padding kaldırma
        last_byte = decrypted_message[-1]
        decrypted_message = decrypted_message[:-last_byte]
        
        return decrypted_message.decode("utf-8")
    except Exception as e:
        return f"Hata oluştu (Blowfish): {e}"


# RSA Şifre Çözme Fonksiyonu
def decrypt_rsa(encrypted_message, private_key_pem):
    try:
        private_key = RSA.import_key(private_key_pem.encode("utf-8"))
        cipher = PKCS1_OAEP.new(private_key)
        decoded_message = base64.b64decode(encrypted_message)
        decrypted_message = cipher.decrypt(decoded_message)
        return decrypted_message.decode("utf-8")
    except Exception as e:
        return f"Hata oluştu (RSA): {e}"


# Kullanıcıdan Girdi Al
encrypted_message = input("Şifrelenmiş mesajı girin: ").strip()
encryption_type = input("Şifreleme türünü girin (AES/RSA/Blowfish): ").strip().upper()

if encryption_type == "AES":
    key = input("Anahtarı girin: ").strip() or "defaultaeskey1234"
    decrypted_message = decrypt_aes(encrypted_message, key)
elif encryption_type == "BLOWFISH":
    key = input("Anahtarı girin: ").strip() or "defaultblowfishkey"
    decrypted_message = decrypt_blowfish(encrypted_message, key)
elif encryption_type == "RSA":
    private_key = input("Özel RSA anahtarını girin: ").strip()
    decrypted_message = decrypt_rsa(encrypted_message, private_key)
else:
    decrypted_message = "Geçersiz şifreleme türü!"

# Sonucu Yazdır
print(f"Çözülen Mesaj: {decrypted_message}")
