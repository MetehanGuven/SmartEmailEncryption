from locust import HttpUser, task, between
import random

class EncryptionTestUser(HttpUser):
    wait_time = between(1, 2)

    def on_start(self):
        self.token = None
        self.encrypted_message = None
        self.algorithm = None
        self.key_or_private_key = None

        self.login()

    def login(self):
        payload = {
            "username": "Metehan",
            "password": "mete123"
        }
        response = self.client.post("/login", json=payload)
        if response.status_code == 200:
            self.token = response.json().get("token")
            print("Login başarılı. Token alındı.")
        else:
            print(f"Login başarısız: {response.status_code} - {response.text}")

    def refresh_token(self):
        if not self.token:
            print("Token eksik, yenileme atlanıyor.")
            return

        headers = {"x-access-token": self.token}
        response = self.client.post("/refresh-token", headers=headers)
        if response.status_code == 200:
            self.token = response.json().get("token")
            print("Token başarıyla yenilendi.")
        else:
            print(f"Token yenileme hatası: {response.status_code} - {response.text}")
            self.login()  

    @task(3)
    def encrypt_test(self):
        if not self.token:
            print("Token eksik, encrypt_test atlanıyor.")
            return

        payload = {
            "recipient_email": "recipient@test.com",
            "message": "Bu bir test mesajıdır.",
            "sensitivity": random.choice(["Low", "Medium", "High", "Asymmetric"])
        }
        headers = {"x-access-token": self.token}
        response = self.client.post("/encrypt", json=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()
            self.encrypted_message = data.get("encrypted_message")
            self.algorithm = data.get("algorithm")
            self.key_or_private_key = data.get("private_key") or data.get("key")
            print("Encrypt başarılı.")
        elif response.status_code == 403:
            print("Token süresi dolmuş, yenileme yapılıyor.")
            self.refresh_token()
        else:
            print(f"Encrypt başarısız: {response.status_code} - {response.text}")

    @task(2)
    def decrypt_test(self):
        if not self.encrypted_message or not self.algorithm or not self.key_or_private_key:
            print("Şifrelenmiş mesaj bulunamadı, decrypt_test atlanıyor.")
            return

        payload = {
            "encrypted_message": self.encrypted_message,
            "algorithm": self.algorithm
        }

        if self.algorithm in ["AES", "Blowfish"]:
            payload["key"] = self.key_or_private_key
        elif self.algorithm in ["ChaCha20-Poly1305", "ECIES-secp256k1"]:
            payload["private_key"] = self.key_or_private_key

        headers = {"x-access-token": self.token}
        response = self.client.post("/decrypt", json=payload, headers=headers)
        if response.status_code == 200:
            print("Decrypt başarılı.")
        elif response.status_code == 403:
            print("Token süresi dolmuş, yenileme yapılıyor.")
            self.refresh_token()
        else:
            print(f"Decrypt başarısız: {response.status_code} - {response.text}")

    @task(1)
    def invalid_encrypt_test(self):
        payload = {
            "recipient_email": "",
            "message": None,
            "sensitivity": "Invalid"
        }
        headers = {"x-access-token": self.token}
        response = self.client.post("/encrypt", json=payload, headers=headers)
        if response.status_code == 400:
            print("Beklenen hata alındı: Geçersiz veri.")
        elif response.status_code == 403:
            print("Token süresi dolmuş, yenileme yapılıyor.")
            self.refresh_token()
        else:
            print(f"Beklenmeyen yanıt: {response.status_code} - {response.text}")
