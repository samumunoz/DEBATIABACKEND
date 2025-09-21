const express = require("express");
const cors = require("cors");
const { OAuth2Client } = require("google-auth-library");
const dotenv = require("dotenv");
const cookieSession = require("cookie-session");

dotenv.config();

// LOG de variables de entorno para depuración
console.log("GOOGLE_CLIENT_ID:", process.env.GOOGLE_CLIENT_ID);
console.log("GOOGLE_CLIENT_SECRET:", process.env.GOOGLE_CLIENT_SECRET);
console.log("GOOGLE_REDIRECT_URI:", process.env.GOOGLE_REDIRECT_URI);
console.log("SESSION_SECRET:", process.env.SESSION_SECRET);

const app = express();

// Configuración de CORS (acepta todo para pruebas)
app.use(
  cors({
    origin: true, // permite cualquier origen
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"],
    allowedHeaders: [
      "Content-Type",
      "Authorization",
      "X-Requested-With",
      "Accept",
    ],
    credentials: true,
  })
);

// Configuración de sesión en cookies
app.use(
  cookieSession({
    name: "session",
    keys: [process.env.SESSION_SECRET],
    maxAge: 24 * 60 * 60 * 1000, // 1 día
  })
);

// Inicializa cliente OAuth2 de Google
const client = new OAuth2Client(
  process.env.GOOGLE_CLIENT_ID,
  process.env.GOOGLE_CLIENT_SECRET,
  process.env.GOOGLE_REDIRECT_URI
);

// ENDPOINT: Redirigir al login de Google
app.get("/auth/google", (req, res) => {
  console.log("Iniciando autenticación con Google");
  const url = client.generateAuthUrl({
    access_type: "offline",
    scope: ["email", "profile"],
    prompt: "select_account", // fuerza selección de cuenta
  });
  res.redirect(url);
});

// ENDPOINT: Callback de Google (intercambia code por token)
app.get("/auth/google/callback", async (req, res) => {
  try {
    const code = req.query.code;

    const { tokens } = await client.getToken(code);
    client.setCredentials(tokens);

    // Obtener info del usuario
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    // Guardar en sesión
    req.session.user = {
      email: payload.email,
      name: payload.name,
      picture: payload.picture,
    };

    res.redirect("http://localhost:3000/profile");
  } catch (err) {
    console.error("Error en login:", err);
    res.status(500).send("Error al autenticar con Google" + err.message);
  }
});

// ENDPOINT: Perfil del usuario logueado
app.get("/profile", (req, res) => {
  if (!req.session.user) {
    return res.redirect("/auth/google");
  }

  const userData = req.session.user;
  res.json(userData);
});

// ENDPOINT: Logout
app.get("/logout", (req, res) => {
  req.session = null;
  res.send("Sesión cerrada <a href='/auth/google'>Login</a>");
});

app.listen(3000, () => {
  console.log("Servidor corriendo en http://localhost:3000");
});
