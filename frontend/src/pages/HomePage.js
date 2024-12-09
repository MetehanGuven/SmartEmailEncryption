import React from "react";
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
          <a href="/login" className="btn-homepage btn-secondary">
            Giriş Yap
          </a>
        </div>
      </div>
    </div>
  );
}

export default HomePage;
