import React, { useState } from "react";
import axios from "axios";
import "./Decrypt.css";

function Decrypt() {
  const [encryptedMessage, setEncryptedMessage] = useState("");
  const [decryptionKey, setDecryptionKey] = useState("");
  const [decryptedMessage, setDecryptedMessage] = useState("");
  const [selectedAlgorithm, setSelectedAlgorithm] = useState("AES");

  const handleDecrypt = async () => {
    try {
      const response = await axios.post("http://127.0.0.1:5000/decrypt", {
        encrypted_message: encryptedMessage,
        algorithm: selectedAlgorithm,
        key: decryptionKey,
      });
      setDecryptedMessage(response.data.decrypted_message);
    } catch (error) {
      console.error(
        "Şifre çözme hatası:",
        error.response ? error.response.data.error : error.message
      );
    }
  };

  return (
    <div className="decrypt-container">
      <div className="text-section">
        <h1>Şifre Çözme</h1>
        <p>
          Şifrelenmiş mesajınızı çözmek için aşağıdaki formu doldurun ve çözme
          işlemini başlatın.
        </p>
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
          <label>Şifreleme Anahtarı</label>
          <input
            type="text"
            placeholder="Şifreleme anahtarını girin"
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
            <option value="RSA">RSA</option>
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
      </div>
    </div>
  );
}

export default Decrypt;
