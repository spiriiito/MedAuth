const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

function prepareMedicalUpload({ username, file, patientId, reportType, reportDate, hospitalCode, department }) {
  const filePath = path.resolve(file || '');
  if (!file || !fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) throw new Error(`Medical report file not found: ${filePath}`);
  const fileBuffer = fs.readFileSync(filePath);
  const nonce = crypto.randomUUID();
  const timestamp = String(Math.floor(Date.now() / 1000));
  const metadata = {
    patientId,
    doctorId: username,
    reportType,
    reportDate,
    hospitalCode,
    department,
  };
  return {
    filePath,
    fileBuffer,
    originalName: path.basename(filePath),
    hash: crypto.createHash('sha256').update(fileBuffer).digest('hex'),
    nonce,
    timestamp,
    metadata,
  };
}

function multipartBody(fields, file) {
  const boundary = `----MedAuthDoctorClient${crypto.randomBytes(18).toString('hex')}`;
  const chunks = [];
  for (const [name, value] of Object.entries(fields)) {
    chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${String(value)}\r\n`));
  }
  chunks.push(Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${String(file.name).replace(/["\r\n]/g, '_')}"\r\nContent-Type: ${file.contentType || 'application/octet-stream'}\r\n\r\n`));
  chunks.push(file.buffer);
  chunks.push(Buffer.from(`\r\n--${boundary}--\r\n`));
  return { boundary, body: Buffer.concat(chunks) };
}

module.exports = { prepareMedicalUpload, multipartBody };
