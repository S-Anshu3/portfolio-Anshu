const crypto = require('crypto');
const pool = require('../db/pool');

const OTP_LENGTH = 6;
const OTP_TTL_MINUTES = 5;
const MAX_ATTEMPTS = 5;

/** Generates a numeric OTP, e.g. "482913" */
function generateOtp() {
  const min = 10 ** (OTP_LENGTH - 1);
  const max = 10 ** OTP_LENGTH - 1;
  return String(crypto.randomInt(min, max + 1));
}

/** One-way hash so raw OTPs are never stored in the database */
function hashOtp(otp) {
  return crypto.createHash('sha256').update(otp).digest('hex');
}

/**
 * Creates and stores a new OTP for the given identifier (email or phone).
 * Any older, unconsumed OTPs for the same identifier+purpose are invalidated.
 */
async function issueOtp(identifier, channel, purpose) {
  const otp = generateOtp();
  const otpHash = hashOtp(otp);
  const expiresAt = new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000);

  await pool.query(
    `UPDATE otps SET consumed = 1
     WHERE identifier = ? AND purpose = ? AND consumed = 0`,
    [identifier, purpose]
  );

  await pool.query(
    `INSERT INTO otps (identifier, channel, purpose, otp_hash, expires_at)
     VALUES (?, ?, ?, ?, ?)`,
    [identifier, channel, purpose, otpHash, expiresAt]
  );

  return otp; // caller sends this via email/SMS; never returned to the client directly
}

/**
 * Verifies a submitted OTP. Returns { ok: true } or { ok: false, reason }.
 */
async function verifyOtp(identifier, purpose, submittedOtp) {
  const [rows] = await pool.query(
    `SELECT * FROM otps
     WHERE identifier = ? AND purpose = ? AND consumed = 0
     ORDER BY id DESC LIMIT 1`,
    [identifier, purpose]
  );

  if (rows.length === 0) {
    return { ok: false, reason: 'No OTP was requested for this identifier.' };
  }

  const record = rows[0];

  if (new Date(record.expires_at) < new Date()) {
    return { ok: false, reason: 'OTP has expired. Please request a new one.' };
  }

  if (record.attempts >= MAX_ATTEMPTS) {
    return { ok: false, reason: 'Too many incorrect attempts. Request a new OTP.' };
  }

  if (hashOtp(submittedOtp) !== record.otp_hash) {
    await pool.query('UPDATE otps SET attempts = attempts + 1 WHERE id = ?', [record.id]);
    return { ok: false, reason: 'Incorrect OTP.' };
  }

  await pool.query('UPDATE otps SET consumed = 1 WHERE id = ?', [record.id]);
  return { ok: true };
}

module.exports = { issueOtp, verifyOtp, OTP_TTL_MINUTES };