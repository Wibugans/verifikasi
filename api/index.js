const express = require('express');
const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'ausdmusic_super_secret_jwt_key_2026';

app.use(cors());
app.use(express.json());

// In-Memory Storage for OTP & Registered Users
const otpStore = new Map();
const userStore = new Map();

// Nodemailer Transporter Configuration (Gmail SMTP)
function createTransporter() {
  const user = process.env.GMAIL_USER;
  const pass = process.env.GMAIL_APP_PASSWORD;

  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: user,
      pass: pass,
    },
  });
}

// Generate 6-digit random number
function generateOtp() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// HTML Template for Email
function getEmailHtmlTemplate(otp) {
  return `
    <div style="font-family: 'Segoe UI', Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 24px; background-color: #121212; color: #ffffff; border-radius: 12px; border: 1px solid #282828;">
      <div style="text-align: center; margin-bottom: 24px;">
        <h1 style="color: #ff3366; margin: 0; font-size: 26px; font-weight: 800; letter-spacing: 1px;">AusDMusic</h1>
        <p style="color: #a0a0a0; font-size: 14px; margin-top: 4px;">Kode Verifikasi Masuk Aplikasi</p>
      </div>
      
      <div style="background-color: #1e1e1e; padding: 20px; border-radius: 8px; text-align: center; margin-bottom: 20px;">
        <p style="color: #e0e0e0; font-size: 15px; margin: 0 0 16px 0;">Gunakan kode berikut untuk memverifikasi akun Anda:</p>
        <div style="font-size: 36px; font-weight: 900; letter-spacing: 8px; color: #ff4081; padding: 12px; background-color: #2a2a2a; border-radius: 8px; display: inline-block;">
          ${otp}
        </div>
        <p style="color: #888888; font-size: 13px; margin-top: 16px; margin-bottom: 0;">Kode ini berlaku selama <strong>5 menit</strong>. Jangan bagikan kode ini kepada siapapun.</p>
      </div>

      <div style="text-align: center; font-size: 12px; color: #666666;">
        <p style="margin: 0;">Jika Anda tidak meminta kode ini, silakan abaikan email ini.</p>
        <p style="margin-top: 6px;">&copy; ${new Date().getFullYear()} AusDMusic. All rights reserved.</p>
      </div>
    </div>
  `;
}

// Middleware to verify JWT Token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Token otentikasi tidak ditemukan' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Token tidak valid atau telah kadaluarsa' });
    }
    req.user = user;
    next();
  });
}

// --- HANDLERS ---

const handleRoot = (req, res) => {
  res.json({
    status: 'online',
    message: 'AusDMusic Auth API Server is running!',
    endpoints: {
      health: '/api/health',
      sendOtp: 'POST /api/auth/send-otp',
      verifyOtp: 'POST /api/auth/verify-otp',
      me: 'GET /api/auth/me',
      logout: 'POST /api/auth/logout'
    },
    time: new Date().toISOString()
  });
};

const handleHealth = (req, res) => {
  res.json({ status: 'ok', service: 'AusDMusic Auth API', time: new Date().toISOString() });
};

const handleSendOtp = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email || !email.includes('@') || !email.includes('.')) {
      return res.status(400).json({ success: false, message: 'Alamat email tidak valid' });
    }

    const normalizedEmail = email.trim().toLowerCase();

    // Check rate limit / cooldown (60 seconds)
    const existing = otpStore.get(normalizedEmail);
    const now = Date.now();
    if (existing && existing.lastSentAt && now - existing.lastSentAt < 60000) {
      const waitSeconds = Math.ceil((60000 - (now - existing.lastSentAt)) / 1000);
      return res.status(429).json({
        success: false,
        message: `Harap tunggu ${waitSeconds} detik sebelum meminta kode baru`,
      });
    }

    const otp = generateOtp();
    const expiresAt = now + 5 * 60 * 1000; // 5 minutes

    otpStore.set(normalizedEmail, {
      otp: otp,
      expiresAt: expiresAt,
      attempts: 0,
      lastSentAt: now,
    });

    console.log(`[AUTH] Generating OTP for ${normalizedEmail}: ${otp}`);

    // If Gmail credentials configured, send email via Nodemailer
    if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
      const transporter = createTransporter();
      await transporter.sendMail({
        from: `"AusDMusic" <${process.env.GMAIL_USER}>`,
        to: normalizedEmail,
        subject: `${otp} adalah kode verifikasi AusDMusic Anda`,
        text: `Kode verifikasi AusDMusic Anda adalah: ${otp}. Berlaku selama 5 menit.`,
        html: getEmailHtmlTemplate(otp),
      });
      console.log(`[AUTH] Email OTP successfully sent to ${normalizedEmail}`);
    } else {
      console.log(`[AUTH] [DEV MODE] SMTP not configured. OTP: ${otp}`);
    }

    return res.json({
      success: true,
      message: 'Kode verifikasi telah dikirim ke email Anda',
      devOtp: process.env.NODE_ENV === 'development' || !process.env.GMAIL_USER ? otp : undefined,
    });
  } catch (error) {
    console.error('[AUTH] Error sending OTP:', error);
    return res.status(500).json({
      success: false,
      message: 'Gagal mengirim email verifikasi. Pastikan konfigurasi email benar.',
      error: error.message,
    });
  }
};

const handleVerifyOtp = async (req, res) => {
  try {
    const { email, otp, name } = req.body;

    if (!email || !otp) {
      return res.status(400).json({ success: false, message: 'Email dan kode OTP wajib diisi' });
    }

    const normalizedEmail = email.trim().toLowerCase();
    const record = otpStore.get(normalizedEmail);

    if (!record) {
      return res.status(400).json({ success: false, message: 'Kode verifikasi belum diminta atau sudah kedaluwarsa' });
    }

    if (Date.now() > record.expiresAt) {
      otpStore.delete(normalizedEmail);
      return res.status(400).json({ success: false, message: 'Kode verifikasi telah kadaluarsa. Silakan minta kode baru.' });
    }

    if (record.attempts >= 5) {
      otpStore.delete(normalizedEmail);
      return res.status(429).json({ success: false, message: 'Terlalu banyak percobaan gagal. Silakan minta kode baru.' });
    }

    if (record.otp !== otp.trim()) {
      record.attempts += 1;
      return res.status(400).json({
        success: false,
        message: `Kode verifikasi salah (Sisa percobaan: ${5 - record.attempts})`,
      });
    }

    // OTP is valid! Remove OTP record
    otpStore.delete(normalizedEmail);

    // Find or create user
    let user = userStore.get(normalizedEmail);
    const now = new Date().toISOString();
    if (!user) {
      user = {
        id: 'usr_' + Math.random().toString(36).substr(2, 9),
        email: normalizedEmail,
        name: name || normalizedEmail.split('@')[0],
        createdAt: now,
        lastLoginAt: now,
      };
      userStore.set(normalizedEmail, user);
    } else {
      user.lastLoginAt = now;
      if (name) user.name = name;
    }

    // Generate JWT token (expires in 30 days)
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        name: user.name,
      },
      JWT_SECRET,
      { expiresIn: '30d' }
    );

    console.log(`[AUTH] User verified successfully: ${normalizedEmail}`);

    return res.json({
      success: true,
      message: 'Login berhasil!',
      token: token,
      user: {
        id: user.id,
        email: user.email,
        name: user.name,
        createdAt: user.createdAt,
      },
    });
  } catch (error) {
    console.error('[AUTH] Error verifying OTP:', error);
    return res.status(500).json({ success: false, message: 'Terjadi kesalahan saat memverifikasi OTP', error: error.message });
  }
};

const handleMe = (req, res) => {
  const user = userStore.get(req.user.email) || req.user;
  res.json({
    success: true,
    user: {
      id: user.id,
      email: user.email,
      name: user.name,
      createdAt: user.createdAt,
    },
  });
};

const handleLogout = (req, res) => {
  res.json({ success: true, message: 'Logout berhasil' });
};

// --- REGISTER ROUTES (BOTH WITH AND WITHOUT /api PREFIX) ---

app.get(['/', '/api'], handleRoot);
app.get(['/health', '/api/health'], handleHealth);
app.post(['/auth/send-otp', '/api/auth/send-otp'], handleSendOtp);
app.post(['/auth/verify-otp', '/api/auth/verify-otp'], handleVerifyOtp);
app.get(['/auth/me', '/api/auth/me'], authenticateToken, handleMe);
app.post(['/auth/logout', '/api/auth/logout'], handleLogout);

module.exports = app;

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
}
