import { createTheme } from "@mui/material/styles";

const theme = createTheme({
  palette: {
    primary: {
      main: "#1976d2", // Ana renk (mavi)
    },
    secondary: {
      main: "#dc004e", // İkincil renk (kırmızı)
    },
  },
  typography: {
    fontFamily: "Roboto, Arial, sans-serif",
  },
});

export default theme;
