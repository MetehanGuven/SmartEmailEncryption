import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import "./Decrypt.css";

function Decrypt() {
  const [encryptedMessage, setEncryptedMessage] = useState("");
  const [decryptionKey, setDecryptionKey] = useState("");
  const [decryptedMessage, setDecryptedMessage] = useState("");
  const [selectedAlgorithm, setSelectedAlgorithm] = useState("AES");
  const navigate = useNavigate();

  const handleDecrypt = async () => {
    try {
      // Hazırlıyoruz:
      const requestData = {
        encrypted_message: encryptedMessage,
        algorithm: selectedAlgorithm,
      };

      // ECIES-secp256k1 özel anahtar "private_key" parametresiyle gönderilir
      if (selectedAlgorithm === "ChaCha20-Poly1305") {
        requestData.private_key = decryptionKey;
      } else if (selectedAlgorithm === "ECIES-secp256k1") {
        requestData.private_key = decryptionKey;
      } else {
        // AES / Blowfish => "key"
        requestData.key = decryptionKey;
      }

      const response = await axios.post(
        "http://127.0.0.1:5000/decrypt",
        requestData
      );
      setDecryptedMessage(response.data.decrypted_message);
    } catch (error) {
      console.error(
        "Şifre çözme hatası:",
        error.response ? error.response.data.error : error.message
      );
      alert("Şifre çözme sırasında hata oluştu.");
    }
  };

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/");
  };

  return (
    <div className="decrypt-container">
      <div className="text-section">
        <h1>Şifre Çözme</h1>
        <p>Şifrelenmiş mesajınızı çözmek için aşağıdaki formu doldurun.</p>
      </div>

      <div className="form-section">
        <div className="input-group">
          <label>Şifrelenmiş Mesaj</label>
          <textarea
            value={encryptedMessage}
            onChange={(e) => setEncryptedMessage(e.target.value)}
            rows="4"
            required
          />
        </div>

        <div className="input-group">
          <label>Anahtar / Key / PrivateKey</label>
          <input
            type="text"
            placeholder="Şifreleme anahtarını (veya ECC private) girin"
            value={decryptionKey}
            onChange={(e) => setDecryptionKey(e.target.value)}
            required
          />
        </div>

        <div className="input-group">
          <label>Algoritma Seçimi</label>
          <select
            value={selectedAlgorithm}
            onChange={(e) => setSelectedAlgorithm(e.target.value)}
          >
            <option value="AES">AES</option>
            <option value="Blowfish">Blowfish</option>
            <option value="ChaCha20-Poly1305">ChaCha20-Poly1305</option>
            {/* Yeni */}
            <option value="ECIES-secp256k1">ECIES (Asymmetric ECC)</option>
          </select>
        </div>

        <button className="btn-primary" onClick={handleDecrypt}>
          Şifreyi Çöz
        </button>

        {decryptedMessage && (
          <div className="result-box">
            <h4>Çözülen Mesaj:</h4>
            <p>{decryptedMessage}</p>
          </div>
        )}

        <button className="logout-button" onClick={handleLogout}>
          Çıkış Yap
        </button>
      </div>
    </div>
  );
}

export default Decrypt;
