const express = require('express');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'ausdmusic_super_secret_jwt_key_2026';

app.use(cors());
app.use(express.json());

const otpStore = new Map();
const userStore = new Map();

function createTransporter() {
  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASSWORD,
    },
  });
}

function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function getEmailHtmlTemplate(otp) {
  return `+
    `+<div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 24px; background-color: #121212; color: #ffffff; border-radius: 12px; border: 1px solid #282828;">`+
    `+`+<div style="text-align: center; margin-bottom: 24px;"><h1 style="color: #ff3366; margin: 0; font-size: 26px; font-weight: 800;">AusDMusic</h1><p style="color: #a0a0a0; font-size: 14px; margin-top: 4px;">Kode Verifikasi Masuk Aplikasi</p></div>`+
    `+`+<div style="background-color: #1e1e1e; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px;"><p style="color: #e0e0e0; font-size: 15px; margin: 0 0 16px 0;">Gunakan kode berikut untuk memverifikasi akun Anda:</p><div style="font-size: 36px; font-weight: 900; letter-spacing: 8px; color: #ff4081; padding: 12px; background-color: #2a2a2a; border-radius: 8px; display: inline-block;"></div><p style="color: #888888; font-size: 13px; margin-top: 16px; margin-bottom: 0;">Kode ini berlaku selama <strong>5 menit</strong>.</p></div>`+
    `+`+<div style="text-align: center; font-size: 12px; color: #666666;"><p style="margin: 0;">Jika Anda tidak meminta kode ini, abaikan email ini.</p></div>`+
    `+</div>
    ;
}

function authenticateToken(req, res, next) {
  const token = (req.headers['authorization'] || '').split(' ')[1];
  if (!token) return res.status(401).json({ success: false, message: 'Token tidak ditemukan' });
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ success: false, message: 'Token tidak valid atau kadaluarsa' });
    req.user = user; next();
  });
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'AusDMusic Auth API', time: new Date().toISOString() });
});

app.post('/api/auth/send-otp', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes('@') || !email.includes('.'))
      return res.status(400).json({ success: false, message: 'Alamat email tidak valid' });
    const normalizedEmail = email.trim().toLowerCase();
    const existing = otpStore.get(normalizedEmail);
    const now = Date.now();
    if (existing && existing.lastSentAt && now - existing.lastSentAt < 60000) {
      const waitSeconds = Math.ceil((60000 - (now - existing.lastSentAt)) / 1000);
      return res.status(429).json({ success: false, message: Harap tunggu  detik sebelum meminta kode baru });
    }
    const otp = generateOtp();
    otpStore.set(normalizedEmail, { otp, expiresAt: now + 5 * 60 * 1000, attempts: 0, lastSentAt: now });
    if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
      const transporter = createTransporter();
      await transporter.sendMail({
        from: "AusDMusic" <>,
        to: normalizedEmail,
        subject: ${otp} adalah kode verifikasi AusDMusic Anda,
        text: Kode verifikasi Anda: . Berlaku 5 menit.,
        html: getEmailHtmlTemplate(otp),
      });
    }
    return res.json({
      success: true,
      message: 'Kode verifikasi telah dikirim ke email Anda',
      devOtp: !process.env.GMAIL_USER ? otp : undefined,
    });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Gagal mengirim email verifikasi.', error: error.message });
  }
});

app.post('/api/auth/verify-otp', async (req, res) => {
  try {
    const { email, otp, name } = req.body;
    if (!email || !otp) return res.status(400).json({ success: false, message: 'Email dan kode OTP wajib diisi' });
    const normalizedEmail = email.trim().toLowerCase();
    const record = otpStore.get(normalizedEmail);
    if (!record) return res.status(400).json({ success: false, message: 'Kode verifikasi belum diminta atau sudah kedaluwarsa' });
    if (Date.now() > record.expiresAt) { otpStore.delete(normalizedEmail); return res.status(400).json({ success: false, message: 'Kode verifikasi telah kadaluarsa. Silakan minta kode baru.' }); }
    if (record.attempts >= 5) { otpStore.delete(normalizedEmail); return res.status(429).json({ success: false, message: 'Terlalu banyak percobaan gagal. Silakan minta kode baru.' }); }
    if (record.otp !== otp.trim()) { record.attempts += 1; return res.status(400).json({ success: false, message: Kode verifikasi salah (Sisa percobaan: ) }); }
    otpStore.delete(normalizedEmail);
    let user = userStore.get(normalizedEmail);
    const now = new Date().toISOString();
    if (!user) {
      user = { id: 'usr_' + Math.random().toString(36).substr(2, 9), email: normalizedEmail, name: name || normalizedEmail.split('@')[0], createdAt: now, lastLoginAt: now };
      userStore.set(normalizedEmail, user);
    } else { user.lastLoginAt = now; if (name) user.name = name; }
    const token = jwt.sign({ id: user.id, email: user.email, name: user.name }, JWT_SECRET, { expiresIn: '30d' });
    return res.json({ success: true, message: 'Login berhasil!', token, user: { id: user.id, email: user.email, name: user.name, createdAt: user.createdAt } });
  } catch (error) {
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan saat memverifikasi OTP', error: error.message });
  }
});

app.get('/api/auth/me', authenticateToken, (req, res) => {
  const user = userStore.get(req.user.email) || req.user;
  res.json({ success: true, user: { id: user.id, email: user.email, name: user.name, createdAt: user.createdAt } });
});

app.post('/api/auth/logout', (req, res) => {
  res.json({ success: true, message: 'Logout berhasil' });
});

module.exports = app;
