import React from "react";
import mailImage from "../assets/mail.webp";
import "./HomePage.css";

function HomePage() {
  return (
    <div className="homepage">
      <div className="homepage-header">
        <h1>Smart Email Encryption</h1>
        <p>Güvenli, hızlı ve şifreli iletişim için buradayız!</p>
        <div className="homepage-buttons">
          <a href="/register" className="btn-homepage">
            Kayıt Ol
          </a>
          <a href="/login" className="btn-homepage">
            Giriş Yap
          </a>
          <a href="/decrypt" className="btn-homepage btn-decrypt">
            Şifreli Mesajını Çöz
          </a>
        </div>
      </div>
      <div className="image-container">
        <img src={mailImage} alt="Secure Email" />
      </div>
    </div>
  );
}

export default HomePage;
