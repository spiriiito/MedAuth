const express = require('express');
const helmet = require('helmet');
const { errorHandler } = require('./middleware/errorHandler');
const secureDoctorRoutes = require('./routes/secureDoctorRoutes');
const { mtlsRequired, requireActiveTlsCertificate } = require('./middleware/mtls');

const app = express();
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '2mb' }));

app.get('/health', mtlsRequired, requireActiveTlsCertificate, (req, res) => res.json({
  ok: true,
  service: 'medauth-doctor-mtls-api',
  tlsAuthorized: req.socket.authorized === true,
  doctor: req.tlsIdentity.username,
  certificateSerial: req.tlsIdentity.serialNumber,
  timestamp: new Date().toISOString(),
}));

app.use('/api/secure', secureDoctorRoutes);

app.use((_req, res) => res.status(404).json({ error: 'Secure doctor API route not found' }));
app.use(errorHandler);

module.exports = app;
