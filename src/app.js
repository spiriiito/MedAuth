const express = require('express');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const authRoutes = require('./routes/authRoutes');
const uploadRoutes = require('./routes/uploadRoutes');
const adminRoutes = require('./routes/adminRoutes');
const auditLogsRoutes = require('./routes/auditLogsRoutes');
const ledgerRoutes = require('./routes/ledgerRoutes');
const blockchainRoutes = require('./routes/blockchainRoutes');
const { errorHandler } = require('./middleware/errorHandler');

require('./db/database');

const app = express();

app.use(helmet({
  contentSecurityPolicy: false,
}));
app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(morgan('combined'));
app.use(express.static(path.resolve(__dirname, '..', 'public')));

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'secure-med-upload', timestamp: new Date().toISOString() });
});

app.get('/', (_req, res) => {
  res.sendFile(path.resolve(__dirname, '..', 'public', 'index.html'));
});

app.use('/api/auth', authRoutes);
app.use('/api/uploads', uploadRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/audit-logs', auditLogsRoutes);
app.use('/api/audit', auditLogsRoutes);
app.use('/api/ledger', ledgerRoutes);
app.use('/api/blockchain', blockchainRoutes);

app.use(errorHandler);

module.exports = app;
