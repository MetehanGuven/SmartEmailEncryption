from Crypto.PublicKey import RSA

# RSA Anahtarlarını Üret
key = RSA.generate(2048)

# Özel Anahtarı Kaydet
private_key = key.export_key()
with open("private.pem", "wb") as f:
    f.write(private_key)

# Genel Anahtarı Kaydet
public_key = key.publickey().export_key()
with open("public.pem", "wb") as f:
    f.write(public_key)

print("Anahtarlar başarıyla oluşturuldu.")
