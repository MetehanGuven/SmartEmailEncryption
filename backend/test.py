import requests
import time
import base64
import random
import string

TEST_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Ik1ldEciLCJlbWFpbCI6ImFiY2RAaG90bWFpbC5jb20iLCJleHAiOjE3MzQ4OTY0MTV9.3RM7HypC79lifnSz2mDtu5mXZSbRICrQ4PGf5FRFPRE"

BASE_URL = "http://127.0.0.1:5000"

def generate_test_data():
    """Farklı senaryolar için metinler döndürür."""
    data_small = "Hello Test!"
    data_utf8 = "Merhaba Dünya! 😊🚀"  
    data_empty = ""                   
    data_medium = "A" * 10_000       
    data_large = "B" * 1_000_000      
    data_xlarge = "C" * 5_000_000    

    return [
        ("SMALL (12 bytes)", data_small),
        ("UTF8 (emoji)", data_utf8),
        ("EMPTY (0 byte)", data_empty),
        ("MEDIUM (10 KB)", data_medium),
        ("LARGE (1 MB)", data_large),
        ("XLARGE (5 MB)", data_xlarge), 
    ]

ALGORITHMS = [
    ("Low", "AES"),
    ("Medium", "Blowfish"),
    ("High", "ChaCha20"),
    ("Asymmetric", "ECIES"),
]

def test_encrypt_decrypt(algorithm_key, plaintext):
    """
    1) /encrypt ile mesaj şifrelenir (plaintext, sensitivity)
    2) Dönen ciphertext + key/private_key ile /decrypt edilir
    3) Decrypted sonucu orijinal plaintext ile karşılaştırılır => correctness
    4) Süreler ölçülür
    """
    start_enc = time.perf_counter()
    resp_enc = requests.post(
        f"{BASE_URL}/encrypt",
        json={
            "recipient_email": "dummy@test.com",
            "message": plaintext,
            "sensitivity": algorithm_key
        },
        headers={"x-access-token": TEST_TOKEN},
        timeout=60
    )
    end_enc = time.perf_counter()

    if resp_enc.status_code != 200:
        return {
            "status": f"Encrypt Error {resp_enc.status_code}",
            "encrypt_time_ms": round((end_enc - start_enc)*1000, 2),
            "decrypt_time_ms": None,
            "correctness": False,
            "wrong_key_test": "SKIP"
        }

    enc_data = resp_enc.json()
    encrypted_message = enc_data.get("encrypted_message")
    algo = enc_data.get("algorithm")
    private_key = enc_data.get("private_key", None)
    req_decrypt_data = {
        "encrypted_message": encrypted_message,
        "algorithm": algo,
    }
    if algo in ["AES", "Blowfish"]:
        req_decrypt_data["key"] = private_key
    elif algo == "ChaCha20-Poly1305" or algo.startswith("ECIES"):
        req_decrypt_data["private_key"] = private_key

    start_dec = time.perf_counter()
    resp_dec = requests.post(f"{BASE_URL}/decrypt", json=req_decrypt_data, timeout=60)
    end_dec = time.perf_counter()

    if resp_dec.status_code != 200:
        return {
            "status": f"Decrypt Error {resp_dec.status_code}",
            "encrypt_time_ms": round((end_enc - start_enc)*1000, 2),
            "decrypt_time_ms": round((end_dec - start_dec)*1000, 2),
            "correctness": False,
            "wrong_key_test": "SKIP"
        }

    dec_data = resp_dec.json()
    decrypted_message = dec_data.get("decrypted_message", "")
    correctness = (decrypted_message == plaintext)

    wrong_key_result = test_wrong_key(algo, encrypted_message, private_key)

    return {
        "status": "OK" if correctness else "WRONG",
        "encrypt_time_ms": round((end_enc - start_enc)*1000, 2),
        "decrypt_time_ms": round((end_dec - start_dec)*1000, 2),
        "correctness": correctness,
        "wrong_key_test": wrong_key_result
    }

def test_wrong_key(algo, encrypted_message, correct_key):
    if correct_key is None:
        return "NO_KEY"

    if len(correct_key) >= 1:
        last_char = correct_key[-1]
        new_last_char = chr(ord(last_char) ^ 1) if last_char.isprintable() else "X"
        wrong_key = correct_key[:-1] + new_last_char
    else:
        wrong_key = "WRONGKEY"

    req_data = {
        "encrypted_message": encrypted_message,
        "algorithm": algo
    }
    if algo in ["AES", "Blowfish"]:
        req_data["key"] = wrong_key
    elif algo == "ChaCha20-Poly1305" or algo.startswith("ECIES"):
        req_data["private_key"] = wrong_key

    try:
        resp = requests.post(f"{BASE_URL}/decrypt", json=req_data, timeout=30)
        if resp.status_code == 200:
            return "DECRYPT_200_BUT_WRONG"
        else:
            return f"{resp.status_code}_ERROR_OK"
    except Exception as e:
        return f"EXCEPTION_{str(e)}"

def test_random_message_encryption():
    random_message = generate_random_message()
    res = test_encrypt_decrypt("Low", random_message)
    print(f"Rastgele mesaj sonucu: {res}")

def generate_random_message(length=256):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

def test_algorithm_support():
    unsupported_algorithms = ["FakeAlgo", "UnsupportedAlgorithm"]
    results = []

    for alg in unsupported_algorithms:
        resp = requests.post(
            f"{BASE_URL}/encrypt",
            json={"recipient_email": "dummy@test.com", "message": "Test", "sensitivity": alg},
            headers={"x-access-token": TEST_TOKEN},
            timeout=30
        )
        if resp.status_code in [400, 500]:
            results.append((alg, "SUPPORTED_ERROR"))
        else:
            results.append((alg, "UNEXPECTED_BEHAVIOR"))

    print("\n=== Algorithm Support Test ===")
    for alg, status in results:
        print(f"Algorithm: {alg}, Status: {status}")

def test_empty_message():
    resp = requests.post(
        f"{BASE_URL}/encrypt",
        json={"recipient_email": "dummy@test.com", "message": "", "sensitivity": "Low"},
        headers={"x-access-token": TEST_TOKEN},
        timeout=30
    )
    print("\n=== Empty Message Test ===")
    if resp.status_code == 400:
        print("Boş mesaj için beklenen hata döndü: 400")
    else:
        print(f"Beklenmeyen cevap kodu: {resp.status_code}, Mesaj: {resp.text}")

def test_scenarios():
    test_data = generate_test_data()
    results = []
    for (data_label, plaintext) in test_data:
        for (alg_key, alg_label) in ALGORITHMS:
            res = test_encrypt_decrypt(alg_key, plaintext)
            results.append((data_label, alg_label, len(plaintext), res))
    return results

def print_report(results):
    print("\n=== EXTENDED TEST RESULTS ===")
    print(f"{'Data Label':<15} | {'Alg':<10} | {'Size':>7} | {'Enc(ms)':>8} | {'Dec(ms)':>8} | {'Status':<6} | {'WrongKey':<16}")
    print("-"*100)
    for (data_label, alg_label, size, r) in results:
        print(f"{data_label:<15} | {alg_label:<10} | {size:>7} | {r['encrypt_time_ms']:>8} | {r['decrypt_time_ms'] if r['decrypt_time_ms'] else '-':>8} | {r['status']:<6} | {r['wrong_key_test']:<16}")

    print("\nAçıklama:")
    print("- 'Status' = 'OK' => Doğru encrypt/decrypt (plaintext eşleşti). 'WRONG' => Eşleşmedi.")
    print("- 'WrongKey' => Yanlış key senaryosu sonucu. 200 dönerse şaibeli, 4xx/5xx hata veya bozuk plaintext bekleniyor.")
    print("Test tamamlandı.\n")

def main():
    results = test_scenarios()
    print_report(results)
    test_random_message_encryption()
    test_algorithm_support()
    test_empty_message()

if __name__ == "__main__":
    main()