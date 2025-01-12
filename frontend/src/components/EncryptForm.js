import React, { useState, useEffect } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
// Eğer jwt-decode paketi 3.x sürümüyse named export: { jwtDecode }
// Daha eskiyse default export: jwt_decode
import { jwtDecode } from "jwt-decode";
import "./EncryptForm.css";

function EncryptForm() {
  const [recipientEmail, setRecipientEmail] = useState("");
  const [message, setMessage] = useState("");
  const [sensitivity, setSensitivity] = useState("Low");
  const [result, setResult] = useState(null);
  const [username, setUsername] = useState("");
  const navigate = useNavigate();

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (token) {
      const decodedToken = jwtDecode(token);
      setUsername(decodedToken.username);
    }
  }, []);

  const handleLogout = () => {
    localStorage.removeItem("token");
    navigate("/");
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    try {
      const token = localStorage.getItem("token");
      const requestData = {
        recipient_email: recipientEmail,
        message: message,
        sensitivity: sensitivity, // Low / Medium / High / Asymmetric
      };

      const response = await axios.post(
        "http://127.0.0.1:5000/encrypt",
        requestData,
        {
          headers: {
            "x-access-token": token,
          },
        }
      );
      setResult(response.data);
    } catch (error) {
      alert("Mesaj şifreleme sırasında bir hata oluştu.");
      console.error(error);
    }
  };

  return (
    <div className="encrypt-page">
      <div className="encrypt-card">
        <h2>Mesaj Şifreleme</h2>
        <p>Mesajınızı şifrelemek için aşağıdaki formu doldurun.</p>
        <form onSubmit={handleSubmit}>
          <div className="input-group">
            <label>Alıcı E-Posta</label>
            <input
              type="email"
              value={recipientEmail}
              onChange={(e) => setRecipientEmail(e.target.value)}
              required
            />
          </div>

          <div className="input-group">
            <label>Mesaj</label>
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              rows="4"
              required
            />
          </div>

          <div className="input-group">
            <label>Hassasiyet Seviyesi</label>
            <select
              value={sensitivity}
              onChange={(e) => setSensitivity(e.target.value)}
            >
              <option value="Low">Düşük (AES)</option>
              <option value="Medium">Orta (Blowfish)</option>
              <option value="High">Yüksek (ChaCha20)</option>
              {/* Yeni eklediğimiz seçenek */}
              <option value="Asymmetric">Asimetrik (ECIES)</option>
            </select>
          </div>

          <button type="submit" className="btn-primary">
            Şifrele ve Gönder
          </button>
        </form>

        {result && (
          <div className="result-box">
            <h4>Sonuç:</h4>
            <p>
              <b>Şifrelenmiş Mesaj:</b> {result.encrypted_message}
            </p>
            <p>
              <b>Kullanılan Algoritma:</b> {result.algorithm}
            </p>
            {result.private_key && (
              <p>
                <b>Key (private_key):</b> {result.private_key}
              </p>
            )}
          </div>
        )}

        <div className="username-display">Kullanıcı: {username}</div>
        <button onClick={handleLogout} className="logout-button">
          Çıkış Yap
        </button>
      </div>
    </div>
  );
}

export default EncryptForm;
