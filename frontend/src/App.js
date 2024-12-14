import React from "react";
import { ThemeProvider } from "@mui/material/styles";
import { CssBaseline } from "@mui/material";
import { BrowserRouter as Router, Routes, Route } from "react-router-dom";
import theme from "./theme";
import HomePage from "./pages/HomePage";
import RegisterForm from "./components/Register";
import EncryptForm from "./components/EncryptForm";
import LoginForm from "./components/Login";
import Decrypt from "./components/Decrypt";

function App() {
  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <Router>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/register" element={<RegisterForm />} />
          <Route path="/login" element={<LoginForm />} />
          <Route path="/encrypt" element={<EncryptForm />} />
          <Route path="/decrypt" element={<Decrypt />} />
        </Routes>
      </Router>
    </ThemeProvider>
  );
}

export default App;
