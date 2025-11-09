// =========================
// 📦 DEPENDENCIAS
// =========================
const express = require('express');
const cors = require('cors');
const multer = require('multer');
const { google } = require('googleapis');
const stream = require('stream');
const fs = require('fs');
const path = require('path');
const axios = require('axios');
const bodyParser = require('body-parser');
const { expressjwt: checkJwtMiddleware } = require('express-jwt');
const jwksRsa = require('jwks-rsa');

// =========================
// ⚙️ CONFIGURACIÓN BASE
// =========================
const app = express();
const upload = multer();
app.use(cors({
  origin: '*',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());

app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Backend funcionando ✅' });
});


app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));

const PORT = process.env.PORT || 3000;

// =========================
// 🔐 CONFIG GOOGLE OAUTH2
// =========================
const CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const REDIRECT_URI = process.env.GOOGLE_REDIRECT_URI;

const TOKEN_PATH = path.join(__dirname, 'tokens.json');
const UPLOADS_PATH = path.join(__dirname, 'uploads.json');

const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

// Si ya hay tokens guardados, los usa
if (fs.existsSync(TOKEN_PATH)) {
  const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
  oAuth2Client.setCredentials(tokens);
  console.log('🔑 Tokens de Google cargados correctamente');
}

// =========================
// 🔐 CONFIG KEYCLOAK
// =========================
const KEYCLOAK_URL = process.env.KEYCLOAK_URL || 'http://localhost:8080';
const REALM = process.env.KEYCLOAK_REALM || 'postulaciones';

async function verificarTokenKeycloak(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader?.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Falta el token de autenticación' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const response = await axios.get(
      `${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/userinfo`,
      { headers: { Authorization: `Bearer ${token}` } }
    );
    req.user = response.data;
    next();
  } catch (error) {
    console.error('❌ Token inválido o expirado:', error.message);
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
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
app.post('/subir-archivo', verificarTokenKeycloak, upload.single('file'), async (req, res) => {
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
app.get('/archivos', verificarTokenKeycloak, (req, res) => {
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
app.delete('/archivo/:tipo', verificarTokenKeycloak, async (req, res) => {
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
// 🚀 INICIAR SERVIDOR

// =========================

app.listen(PORT, () => {
  console.log(`🚀 Servidor en el puerto ${PORT}`);
});

// // =========================
// // 📦 DEPENDENCIAS
// // =========================
// const express = require('express');
// const cors = require('cors');
// const multer = require('multer');
// const { google } = require('googleapis');
// const stream = require('stream');
// const fs = require('fs');
// const path = require('path');
// const axios = require('axios');
// const bodyParser = require('body-parser');
// const jwtLib = require('jsonwebtoken'); // para generar/verificar tokens
// const { expressjwt: checkJwtMiddleware } = require('express-jwt'); // middleware Keycloak
// const jwksRsa = require('jwks-rsa'); // 🔑 JWKS para Keycloak
// const PORT = process.env.PORT || 3000;

// // =========================
// // ⚙️ CONFIGURACIÓN BASE
// // =========================
// const app = express();
// const upload = multer();
// app.use(cors());
// app.use(bodyParser.json());
// app.use(express.urlencoded({ extended: true }));

// // =========================
// // 🔐 CONFIG GOOGLE OAUTH2
// // =========================
// const CLIENT_ID = '105526235933-u4jif1ptcpcgtggb0am94s7a298qlt4k.apps.googleusercontent.com';
// const CLIENT_SECRET = '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';
// const REDIRECT_URI = 'http://localhost:3000/oauth2callback';

// const TOKEN_PATH = path.join(__dirname, 'tokens.json');
// const UPLOADS_PATH = path.join(__dirname, 'uploads.json');

// const oAuth2Client = new google.auth.OAuth2(CLIENT_ID, CLIENT_SECRET, REDIRECT_URI);

// if (fs.existsSync(TOKEN_PATH)) {
//   const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
//   oAuth2Client.setCredentials(tokens);
//   console.log('🔑 Tokens cargados correctamente');
// }

// // =========================
// // 🔐 MIDDLEWARE: VALIDAR TOKEN DE KEYCLOAK
// // =========================
// const checkJwt = checkJwtMiddleware({
//   secret: jwksRsa.expressJwtSecret({
//     jwksUri: 'http://localhost:8080/realms/postulaciones/protocol/openid-connect/certs',
//     cache: true,
//     rateLimit: true,
//     jwksRequestsPerMinute: 5,
//   }),
//   audience: 'account', // Client ID si aplica
//   issuer: 'http://localhost:8080/realms/postulaciones',
//   algorithms: ['RS256'],
// });

// async function verificarTokenKeycloak(req, res, next) {
//   const authHeader = req.headers.authorization;

//   if (!authHeader || !authHeader.startsWith('Bearer ')) {
//     return res.status(401).json({ error: 'Falta el token de autenticación' });
//   }

//   const token = authHeader.split(' ')[1];

//   try {
//     const response = await axios.get(
//       'http://localhost:8080/realms/postulaciones/protocol/openid-connect/userinfo',
//       { headers: { Authorization: `Bearer ${token}` } }
//     );
//     req.user = response.data; // contiene: sub, name, preferred_username, email...
//     next();
//   } catch (error) {
//     console.error('❌ Token inválido o expirado:', error.message);
//     return res.status(401).json({ error: 'Token inválido o expirado' });
//   }
// }

// // =========================
// // 🌐 AUTORIZACIÓN GOOGLE
// // =========================
// app.get('/auth', (req, res) => {
//   const authUrl = oAuth2Client.generateAuthUrl({
//     access_type: 'offline',
//     scope: ['https://www.googleapis.com/auth/drive.file'],
//   });
//   res.redirect(authUrl);
// });

// app.get('/oauth2callback', async (req, res) => {
//   const code = req.query.code;
//   if (!code) return res.status(400).send('No code received');

//   try {
//     const { tokens } = await oAuth2Client.getToken(code);
//     oAuth2Client.setCredentials(tokens);
//     fs.writeFileSync(TOKEN_PATH, JSON.stringify(tokens));
//     res.send('✅ Autorización completada. Ya puedes subir archivos.');
//   } catch (err) {
//     console.error('❌ Error obteniendo tokens:', err);
//     res.status(500).send('Error al obtener tokens');
//   }
// });

// // =========================
// // 📤 SUBIR ARCHIVO
// // =========================
// app.post('/subir-archivo', verificarTokenKeycloak, upload.single('file'), async (req, res) => {
//   if (!fs.existsSync(TOKEN_PATH)) {
//     return res.status(401).json({ error: 'No autorizado. Visita /auth primero.' });
//   }

//   // ✅ Obtener nombre de usuario de Keycloak
//   const userName = req.user?.name || req.user?.preferred_username || req.user?.email || 'Usuario desconocido';

//   console.log('👤 Usuario autenticado:', userName);

//   const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
//   oAuth2Client.setCredentials(tokens);
//   const drive = google.drive({ version: 'v3', auth: oAuth2Client });

//   const { tipo, folderId } = req.body;
//   const file = req.file;
//   if (!file) return res.status(400).json({ error: 'No se recibió ningún archivo' });

//   try {
//     const bufferStream = new stream.PassThrough();
//     bufferStream.end(file.buffer);

//     const driveRes = await drive.files.create({
//       requestBody: { name: file.originalname, parents: [folderId] },
//       media: { mimeType: file.mimetype, body: bufferStream },
//       fields: 'id, name, webViewLink, webContentLink',
//     });

//     let uploads = {};
//     if (fs.existsSync(UPLOADS_PATH)) {
//       uploads = JSON.parse(fs.readFileSync(UPLOADS_PATH));
//     }
//     if (!uploads[userName]) uploads[userName] = {};

//     uploads[userName][tipo] = {
//       name: file.originalname,
//       id: driveRes.data.id,
//       url: driveRes.data.webViewLink,
//       date: new Date().toISOString(),
//     };

//     fs.writeFileSync(UPLOADS_PATH, JSON.stringify(uploads, null, 2));
//     res.json({ message: `✅ Archivo subido con éxito por ${userName}`, file: uploads[userName][tipo] });
//   } catch (err) {
//     console.error('❌ Error al subir a Drive:', err);
//     res.status(500).json({ error: err.message });
//   }
// });

// // =========================
// // 📁 LISTAR ARCHIVOS
// // =========================
// app.get('/archivos', verificarTokenKeycloak, (req, res) => {
//   try {
//     if (!fs.existsSync(UPLOADS_PATH)) return res.json({});
//     const data = JSON.parse(fs.readFileSync(UPLOADS_PATH, 'utf8'));

//     const userEmail = req.user.email || req.user.preferred_username;
//     res.json(data[userEmail] || {});
//   } catch (err) {
//     console.error('Error leyendo uploads.json', err);
//     res.status(500).json({ error: 'Error al leer los archivos guardados' });
//   }
// });

// // =========================
// // 🗑️ ELIMINAR ARCHIVO
// // =========================
// app.delete('/archivo/:tipo', verificarTokenKeycloak, async (req, res) => {
//   const tipo = req.params.tipo;
//   const userEmail = req.user.email || req.user.preferred_username;

//   if (!fs.existsSync(UPLOADS_PATH)) {
//     return res.status(404).json({ error: 'No hay registros' });
//   }

//   const uploads = JSON.parse(fs.readFileSync(UPLOADS_PATH));
//   const userFiles = uploads[userEmail];
//   if (!userFiles || !userFiles[tipo]) {
//     return res.status(404).json({ error: 'Archivo no encontrado' });
//   }

//   const fileId = userFiles[tipo].id;
//   try {
//     const tokens = JSON.parse(fs.readFileSync(TOKEN_PATH));
//     oAuth2Client.setCredentials(tokens);
//     const drive = google.drive({ version: 'v3', auth: oAuth2Client });
//     await drive.files.delete({ fileId });

//     delete uploads[userEmail][tipo];
//     fs.writeFileSync(UPLOADS_PATH, JSON.stringify(uploads, null, 2));
//     res.json({ message: '🗑️ Archivo eliminado correctamente' });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: 'Error al eliminar en Drive' });
//   }
// });

// // =========================
// // 🚀 INICIAR SERVIDOR
// // =========================

// app.listen(PORT, () => console.log(`Server on port ${PORT}`));