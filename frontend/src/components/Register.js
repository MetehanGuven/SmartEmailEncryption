import React, { useState } from "react";
import axios from "axios";
import { useNavigate } from "react-router-dom";
import "./Register.css";

function Register() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [verificationCode, setVerificationCode] = useState("");
  const [showVerification, setShowVerification] = useState(false);
  const [message, setMessage] = useState("");
  const navigate = useNavigate();

  const handleRegister = async (e) => {
    e.preventDefault();
    try {
      const response = await axios.post("http://127.0.0.1:5000/register", {
        email,
        password,
      });
      setMessage(response.data.message);
      setShowVerification(true); // Doğrulama penceresini göster
    } catch (error) {
      setMessage(error.response ? error.response.data.error : error.message);
    }
  };

  const handleVerify = async () => {
    try {
      const response = await axios.post("http://127.0.0.1:5000/verify", {
        email,
        verification_code: verificationCode,
      });
      setMessage(response.data.message);
      setShowVerification(false);
      navigate("/"); // Doğrulama başarılı, pencereyi kapat
    } catch (error) {
      setMessage(error.response ? error.response.data.error : error.message);
    }
  };

  return (
    <div className="register-page">
      <div className="register-card">
        <h2>Kayıt Ol</h2>
        {!showVerification ? (
          <form onSubmit={handleRegister}>
            <div className="input-group">
              <label>E-Posta</label>
              <input
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
              />
            </div>
            <div className="input-group">
              <label>Şifre</label>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
            <button type="submit" className="btn-primary">
              Kayıt Ol
            </button>
            <p className="login-link">
              Hesabınız var mı? <a href="/login">Giriş Yap</a>
            </p>
          </form>
        ) : (
          <div>
            <h5>Doğrulama Kodunu Girin</h5>
            <div className="input-group">
              <label>Doğrulama Kodu</label>
              <input
                type="text"
                value={verificationCode}
                onChange={(e) => setVerificationCode(e.target.value)}
                required
              />
            </div>
            <button className="btn-primary" onClick={handleVerify}>
              Doğrula
            </button>
          </div>
        )}
        {message && <div className="message-box">{message}</div>}
      </div>
    </div>
  );
}

export default Register;
