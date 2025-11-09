// =========================
// 📦 DEPENDENCIAS
// =========================
import express from 'express';
import cors from 'cors';
import multer from 'multer';
import { google } from 'googleapis';
import stream from 'stream';
import fs from 'fs';
import path from 'path';
import axios from 'axios';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

// =========================
// ⚙️ CONFIGURACIÓN BASE
// =========================
const app = express();
const upload = multer();
const PORT = process.env.PORT || 3000;

// ✅ CORS (para local y producción)
app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (/vercel\.app$/.test(origin) || origin.includes('localhost:4200')) {
        return callback(null, true);
      }
      callback(new Error('No autorizado por CORS'));
    },
    credentials: true,
  })
);

app.use(express.json());
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

// =========================
// 🩺 ENDPOINT DE SALUD
// =========================
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Backend funcionando ✅' });
});

// =========================
// 🔐 CONFIG GOOGLE OAUTH2
// =========================
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

const TOKEN_PATH = path.join(process.cwd(), 'tokens.json');
const UPLOADS_PATH = path.join(process.cwd(), 'uploads.json');

const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

// Si ya hay tokens guardados, los usa
if (fs.existsSync(TOKEN_PATH)) {
  const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
  oAuth2Client.setCredentials(tokens);
  console.log('🔑 Tokens de Google cargados correctamente');
}

// =========================
// 🔐 CONFIG KEYCLOAK JWT (seguro y recomendado)
// =========================
const KEYCLOAK_JWKS_URI =
  process.env.KEYCLOAK_JWKS_URI ||
  'https://keycloak-cloud.onrender.com/realms/postulaciones/protocol/openid-connect/certs';

const client = jwksClient({ jwksUri: KEYCLOAK_JWKS_URI });

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      console.error('❌ Error obteniendo clave pública:', err);
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

function verifyKeycloakToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Falta token' });

  const token = authHeader.split(' ')[1];

  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) {
      console.error('❌ Token inválido o expirado:', err.message);
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }

    req.user = decoded;
    next();
  });
}

// =========================
// 🌐 AUTORIZACIÓN GOOGLE
// =========================
app.get('/auth', (req, res) => {
  const authUrl = oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: ['https://www.googleapis.com/auth/drive.file'],
  });
  res.redirect(authUrl);
});

app.get('/oauth2callback', async (req, res) => {
  const code = req.query.code;
  if (!code) return res.status(400).send('No se recibió ningún código');

  try {
    const { tokens } = await oAuth2Client.getToken(code);
    oAuth2Client.setCredentials(tokens);
    fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens));
    res.send('✅ Autorización completada. Ya puedes subir archivos.');
  } catch (err) {
    console.error('❌ Error al obtener tokens:', err);
    res.status(500).send('Error al obtener tokens');
  }
});

// =========================
// 📤 SUBIR ARCHIVO
// =========================
app.post('/subir-archivo', verifyKeycloakToken, upload.single('file'), async (req, res) => {
  if (!fs.existsSync(TOKEN_PATH)) {
    return res.status(401).json({ error: 'No autorizado. Visita /auth primero.' });
  }

  const userName = req.user?.name || req.user?.preferred_username || req.user?.email || 'Usuario desconocido';
  console.log('👤 Usuario autenticado:', userName);

  const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
  oAuth2Client.setCredentials(tokens);
  const drive = google.drive({ version: 'v3', auth: oAuth2Client });

  const { tipo, folderId } = req.body;
  const file = req.file;
  if (!file) return res.status(400).json({ error: 'No se recibió ningún archivo' });

  try {
    const bufferStream = new stream.PassThrough();
    bufferStream.end(file.buffer);

    const driveRes = await drive.files.create({
      requestBody: { name: file.originalname, parents: [folderId] },
      media: { mimeType: file.mimetype, body: bufferStream },
      fields: 'id, name, webViewLink, webContentLink',
    });

    let uploads = {};
    if (fs.existsSync(UPLOADS_PATH)) {
      uploads = JSON.parse(fs.readFileSync(UPLOADS_PATH));
    }
    if (!uploads[userName]) uploads[userName] = {};

    uploads[userName][tipo] = {
      name: file.originalname,
      id: driveRes.data.id,
      url: driveRes.data.webViewLink,
      date: new Date().toISOString(),
    };

    fs.writeFileSync(UPLOADS_PATH, JSON.stringify(uploads, null, 2));
    res.json({ message: `✅ Archivo subido con éxito por ${userName}`, file: uploads[userName][tipo] });
  } catch (err) {
    console.error('❌ Error al subir a Drive:', err);
    res.status(500).json({ error: err.message });
  }
});

// =========================
// 📁 LISTAR ARCHIVOS
// =========================
app.get('/archivos', verifyKeycloakToken, (req, res) => {
  try {
    if (!fs.existsSync(UPLOADS_PATH)) return res.json({});
    const data = JSON.parse(fs.readFileSync(UPLOADS_PATH, 'utf8'));
    const userEmail = req.user.email || req.user.preferred_username;
    res.json(data[userEmail] || {});
  } catch (err) {
    console.error('Error leyendo uploads.json', err);
    res.status(500).json({ error: 'Error al leer los archivos guardados' });
  }
});

// =========================
// 🗑️ ELIMINAR ARCHIVO
// =========================
app.delete('/archivo/:tipo', verifyKeycloakToken, async (req, res) => {
  const tipo = req.params.tipo;
  const userEmail = req.user.email || req.user.preferred_username;

  if (!fs.existsSync(UPLOADS_PATH)) {
    return res.status(404).json({ error: 'No hay registros' });
  }

  const uploads = JSON.parse(fs.readFileSync(UPLOADS_PATH));
  const userFiles = uploads[userEmail];
  if (!userFiles || !userFiles[tipo]) {
    return res.status(404).json({ error: 'Archivo no encontrado' });
  }

  const fileId = userFiles[tipo].id;
  try {
    const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
    oAuth2Client.setCredentials(tokens);
    const drive = google.drive({ version: 'v3', auth: oAuth2Client });
    await drive.files.delete({ fileId });

    delete uploads[userEmail][tipo];
    fs.writeFileSync(UPLOADS_PATH, JSON.stringify(uploads, null, 2));
    res.json({ message: '🗑️ Archivo eliminado correctamente' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Error al eliminar en Drive' });
  }
});

// =========================
// 🌍 RAÍZ DEL SERVICIO (Render check)
// =========================
app.get('/', (req, res) => {
  res.send('✅ Backend activo en Render (raíz /)');
});

// =========================
// 🌐 SERVIR FRONTEND (Angular build)
// =========================
const frontendPath = path.join(process.cwd(), '../frontend/dist/frontend');
if (fs.existsSync(frontendPath)) {
  app.use(express.static(frontendPath));
  app.get('*', (req, res) => {
    res.sendFile(path.join(frontendPath, 'index.html'));
  });
}

// =========================
// 🚀 INICIAR SERVIDOR
// =========================
app.listen(PORT, () => {
  console.log(`🚀 Servidor en el puerto ${PORT}`);
});
