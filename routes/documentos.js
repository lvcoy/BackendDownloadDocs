import express from 'express';
const router = express.Router();

router.get('/', (req, res) => {
  res.json({
    mensaje: `Hola ${req.user.preferred_username}, tus documentos están seguros.`,
  });
});

export default router;
