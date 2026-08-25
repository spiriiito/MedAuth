const { logAudit } = require('../services/auditService');

function errorHandler(err, req, res, _next) {
  const status = err.status || 500;
  const message = status === 500 ? 'Internal server error' : err.message;

  try {
    logAudit({
      userId: req.user?.id ?? null,
      action: 'request_error',
      status: 'failure',
      ipAddress: req.ip,
      userAgent: req.get('user-agent'),
      details: {
        path: req.originalUrl,
        method: req.method,
        error: err.message,
      },
    });
  } catch {
    // Avoid breaking response if audit logging fails.
  }

  res.status(status).json({ error: message });
}

module.exports = {
  errorHandler,
};