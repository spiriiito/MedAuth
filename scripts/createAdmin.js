const db = require('../src/db/database');
const {
  PASSWORD_ALGORITHM,
  PASSWORD_VERSION,
  hashPassword,
  validatePasswordPolicy,
} = require('../src/utils/password');

function usage() {
  return [
    'Usage:',
    '  npm run create-admin -- <username> <password>',
    '  npm run create-admin -- --username <username> --password <password>',
    '  ADMIN_USERNAME=<username> ADMIN_PASSWORD=<password> npm run create-admin',
    '',
    'Options:',
    '  --update-existing   Promote/update an existing user instead of failing',
  ].join('\n');
}

function normalizeUsername(value) {
  return String(value || '').trim().toLowerCase();
}

function validateUsername(username) {
  if (!username) {
    return 'Username is required';
  }
  if (username.length < 3 || username.length > 64) {
    return 'Username must be between 3 and 64 characters';
  }
  if (!/^[a-z0-9._-]+$/.test(username)) {
    return 'Username may only contain letters, numbers, dots, underscores, and hyphens';
  }
  return null;
}

function readArgValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) {
    return null;
  }
  return args[index + 1] || '';
}

async function main() {
  const args = process.argv.slice(2);
  const positional = args.filter((arg) => !arg.startsWith('--'));
  const username = normalizeUsername(
    readArgValue(args, '--username')
      || readArgValue(args, '-u')
      || process.env.ADMIN_USERNAME
      || positional[0]
  );
  const password = String(
    readArgValue(args, '--password')
      || readArgValue(args, '-p')
      || process.env.ADMIN_PASSWORD
      || positional[1]
      || ''
  );
  const updateExisting = args.includes('--update-existing') || process.env.ADMIN_UPDATE_EXISTING === '1';

  if (!username || !password) {
    throw new Error(usage());
  }

  const usernameError = validateUsername(username);
  if (usernameError) {
    throw new Error(usernameError);
  }

  const policyError = validatePasswordPolicy(password);
  if (policyError) {
    throw new Error(policyError);
  }

  const passwordHash = await hashPassword(password);
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);

  if (existing) {
    if (!updateExisting) {
      throw new Error(
        `User "${username}" already exists. Use --update-existing to promote/update this account as admin.`
      );
    }

    db.prepare(`
      UPDATE users
      SET password_hash = ?,
          password_algorithm = ?,
          password_version = ?,
          requires_password_upgrade = 0,
          password_changed_at = datetime('now'),
          role = 'admin'
      WHERE id = ?
    `).run(passwordHash, PASSWORD_ALGORITHM, PASSWORD_VERSION, existing.id);
    // eslint-disable-next-line no-console
    console.log(`Admin user "${username}" updated successfully.`);
    return;
  }

  db.prepare(`
    INSERT INTO users (
      username, password_hash, password_algorithm, password_version,
      requires_password_upgrade, password_changed_at, role
    )
    VALUES (?, ?, ?, ?, 0, datetime('now'), 'admin')
  `).run(username, passwordHash, PASSWORD_ALGORITHM, PASSWORD_VERSION);

  // eslint-disable-next-line no-console
  console.log(`Admin user "${username}" created successfully.`);
}

main()
  .catch((err) => {
    // eslint-disable-next-line no-console
    console.error(err.message);
    process.exitCode = 1;
  })
  .finally(() => {
    db.close();
  });
