import jwt from 'jsonwebtoken';
import jwksClient from 'jwks-rsa';

/**
 * Cliente para obtener las claves públicas (JWKS) del realm de Keycloak
 * Estas claves se usan para verificar la firma del token JWT
 */
const client = jwksClient({
  jwksUri: 'https://keycloak-cloud.onrender.com/realms/postulaciones/protocol/openid-connect/certs'
});

/**
 * Obtiene la clave pública según el `kid` del header del token
 */
function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    if (err) {
      console.error('❌ Error obteniendo clave pública de Keycloak:', err);
      return callback(err);
    }
    const signingKey = key.getPublicKey();
    callback(null, signingKey);
  });
}

/**
 * Middleware de Express para validar tokens JWT emitidos por Keycloak
 */
export function verifyKeycloakToken(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: 'Falta token' });

  const token = authHeader.split(' ')[1];

  jwt.verify(token, getKey, { algorithms: ['RS256'] }, (err, decoded) => {
    if (err) {
      console.error('❌ Token inválido o expirado:', err.message);
      return res.status(403).json({ error: 'Token inválido o expirado' });
    }

    // Guardamos los datos del usuario decodificado para las rutas
    req.user = decoded;
    next();
  });
}
