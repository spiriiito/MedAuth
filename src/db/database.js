const fs = require('fs');
const path = require('path');
const Database = require('better-sqlite3');
const config = require('../config/env');

const dbDir = path.dirname(config.dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

const db = new Database(config.dbPath);
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  password_algorithm TEXT NOT NULL DEFAULT 'bcrypt',
  password_version INTEGER NOT NULL DEFAULT 2,
  requires_password_upgrade INTEGER NOT NULL DEFAULT 0,
  password_changed_at TEXT,
  role TEXT NOT NULL DEFAULT 'doctor',
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS used_nonces (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nonce TEXT NOT NULL,
  user_id INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(nonce, user_id),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  original_name TEXT NOT NULL,
  mime_type TEXT,
  size_bytes INTEGER NOT NULL,
  file_path TEXT NOT NULL,
  sha256_hash TEXT NOT NULL,
  aes_iv_b64 TEXT NOT NULL,
  aes_tag_b64 TEXT NOT NULL,
  signer_subject TEXT,
  signer_serial TEXT,
  signature_valid INTEGER NOT NULL DEFAULT 0,
  patient_id TEXT,
  doctor_id TEXT,
  report_type TEXT,
  report_date TEXT,
  hospital_code TEXT,
  department TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  action TEXT NOT NULL,
  status TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  details_json TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_used_nonces_created_at ON used_nonces(created_at);
CREATE INDEX IF NOT EXISTS idx_uploads_user_id ON uploads(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
`);

function ensureColumn(tableName, columnName, definition) {
  const columns = db.prepare(`PRAGMA table_info(${tableName})`).all();
  const exists = columns.some((column) => column.name === columnName);
  if (!exists) {
    try {
      db.exec(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`);
    } catch (err) {
      if (!/duplicate column name/i.test(err.message)) {
        throw err;
      }
    }
    return true;
  }
  return false;
}

ensureColumn('users', 'password_algorithm', "TEXT NOT NULL DEFAULT 'legacy'");
ensureColumn('users', 'password_version', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('users', 'requires_password_upgrade', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('users', 'password_changed_at', 'TEXT');

ensureColumn('uploads', 'patient_id', 'TEXT');
ensureColumn('uploads', 'doctor_id', 'TEXT');
ensureColumn('uploads', 'report_type', 'TEXT');
ensureColumn('uploads', 'report_date', 'TEXT');
ensureColumn('uploads', 'hospital_code', 'TEXT');
ensureColumn('uploads', 'department', 'TEXT');
ensureColumn('uploads', 'encrypted_file_key_b64', 'TEXT');
ensureColumn('uploads', 'file_iv_b64', 'TEXT');
ensureColumn('uploads', 'file_auth_tag_b64', 'TEXT');
ensureColumn('uploads', 'key_wrap_iv_b64', 'TEXT');
ensureColumn('uploads', 'key_wrap_tag_b64', 'TEXT');
ensureColumn('uploads', 'kdf_salt_b64', 'TEXT');
ensureColumn('uploads', 'kdf_algorithm', 'TEXT');
ensureColumn('uploads', 'kdf_iterations', 'INTEGER');
ensureColumn('uploads', 'fabric_record_id', 'TEXT');
ensureColumn('uploads', 'fabric_transaction_id', 'TEXT');
ensureColumn('uploads', 'fabric_block_number', 'TEXT');
ensureColumn('uploads', 'fabric_validation_code', 'TEXT');
ensureColumn('uploads', 'fabric_channel_name', 'TEXT');
ensureColumn('uploads', 'fabric_chaincode_name', 'TEXT');
ensureColumn('uploads', 'fabric_status', 'TEXT');
ensureColumn('uploads', 'fabric_committed_at', 'TEXT');
ensureColumn('uploads', 'fabric_error', 'TEXT');
ensureColumn('uploads', 'record_version', 'INTEGER NOT NULL DEFAULT 1');
ensureColumn('uploads', 'previous_fabric_record_id', 'TEXT');
ensureColumn('uploads', 'doctor_certificate_fingerprint', 'TEXT');
ensureColumn('uploads', 'doctor_signature_hash', 'TEXT');

ensureColumn('audit_logs', 'previous_audit_hash', "TEXT");
ensureColumn('audit_logs', 'current_audit_hash', "TEXT");

db.exec(`
CREATE TABLE IF NOT EXISTS verification_votes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id TEXT NOT NULL,
  upload_id INTEGER,
  node_name TEXT NOT NULL,
  vote TEXT NOT NULL CHECK(vote IN ('APPROVE', 'REJECT')),
  reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(upload_id) REFERENCES uploads(id)
);

CREATE TABLE IF NOT EXISTS rejected_uploads (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  attempt_id TEXT NOT NULL,
  user_id INTEGER,
  username TEXT,
  file_hash TEXT,
  reason TEXT NOT NULL,
  failed_stage TEXT NOT NULL,
  metadata_json TEXT,
  ip_address TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS hash_ledger (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  upload_id INTEGER NOT NULL UNIQUE,
  file_hash TEXT NOT NULL,
  metadata_hash TEXT NOT NULL,
  previous_ledger_hash TEXT NOT NULL,
  ledger_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(upload_id) REFERENCES uploads(id)
);

CREATE TABLE IF NOT EXISTS revoked_certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  serial_number TEXT NOT NULL UNIQUE,
  reason TEXT,
  revoked_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS doctor_certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  username TEXT,
  subject TEXT NOT NULL,
  serial_number TEXT NOT NULL UNIQUE,
  certificate_pem TEXT NOT NULL,
  public_key_fingerprint TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('active','revoked','expired','rotated')),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revocation_reason TEXT,
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS doctor_tls_certificates (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  username TEXT NOT NULL,
  subject TEXT NOT NULL,
  serial_number TEXT NOT NULL UNIQUE,
  fingerprint_sha256 TEXT NOT NULL UNIQUE,
  certificate_pem TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('PENDING','ACTIVE','REVOKED','EXPIRED','ROTATED')),
  issued_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  revocation_reason TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS doctor_patient_assignments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  doctor_user_id INTEGER NOT NULL,
  patient_id TEXT NOT NULL,
  assigned_by INTEGER NOT NULL,
  assigned_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(doctor_user_id, patient_id),
  FOREIGN KEY(doctor_user_id) REFERENCES users(id),
  FOREIGN KEY(assigned_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS blocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  block_index INTEGER NOT NULL UNIQUE,
  previous_block_hash TEXT NOT NULL,
  merkle_root TEXT NOT NULL,
  timestamp TEXT NOT NULL,
  block_hash TEXT NOT NULL UNIQUE,
  validator_signature TEXT NOT NULL,
  validator_certificate_serial TEXT NOT NULL,
  created_by INTEGER,
  FOREIGN KEY(created_by) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS block_transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  block_id INTEGER NOT NULL,
  upload_id INTEGER NOT NULL,
  transaction_hash TEXT NOT NULL,
  action_type TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(block_id) REFERENCES blocks(id),
  FOREIGN KEY(upload_id) REFERENCES uploads(id)
);

CREATE TABLE IF NOT EXISTS audit_chain_state (
  id INTEGER PRIMARY KEY CHECK(id = 1),
  tail_log_id INTEGER,
  tail_hash TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_uploads_medical_lookup ON uploads(patient_id, report_type, sha256_hash);
CREATE INDEX IF NOT EXISTS idx_verification_votes_attempt_id ON verification_votes(attempt_id);
CREATE INDEX IF NOT EXISTS idx_rejected_uploads_created_at ON rejected_uploads(created_at);
CREATE INDEX IF NOT EXISTS idx_hash_ledger_upload_id ON hash_ledger(upload_id);
CREATE INDEX IF NOT EXISTS idx_revoked_certificates_serial ON revoked_certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_doctor_certificates_user_status ON doctor_certificates(user_id, status);
CREATE INDEX IF NOT EXISTS idx_tls_certificates_user_id ON doctor_tls_certificates(user_id);
CREATE INDEX IF NOT EXISTS idx_tls_certificates_username ON doctor_tls_certificates(username);
CREATE INDEX IF NOT EXISTS idx_tls_certificates_serial ON doctor_tls_certificates(serial_number);
CREATE INDEX IF NOT EXISTS idx_tls_certificates_fingerprint ON doctor_tls_certificates(fingerprint_sha256);
CREATE INDEX IF NOT EXISTS idx_tls_certificates_status ON doctor_tls_certificates(status);
CREATE INDEX IF NOT EXISTS idx_assignments_doctor_patient ON doctor_patient_assignments(doctor_user_id, patient_id);
CREATE INDEX IF NOT EXISTS idx_block_transactions_block ON block_transactions(block_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_uploads_fabric_record_id ON uploads(fabric_record_id) WHERE fabric_record_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_uploads_fabric_transaction_id ON uploads(fabric_transaction_id);
CREATE INDEX IF NOT EXISTS idx_uploads_fabric_status ON uploads(fabric_status);
`);

ensureColumn('doctor_certificates', 'username', 'TEXT');
db.exec(`UPDATE doctor_certificates
         SET username = (SELECT username FROM users WHERE users.id = doctor_certificates.user_id)
         WHERE username IS NULL OR username = ''`);
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_certificate_per_doctor
         ON doctor_certificates(user_id) WHERE status = 'active'`);
db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_one_active_tls_certificate_per_doctor
         ON doctor_tls_certificates(user_id) WHERE status = 'ACTIVE'`);

module.exports = db;
