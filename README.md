# 🚀 AusDMusic Auth Backend (Email OTP Verification)

Backend REST API untuk autentikasi pengguna menggunakan **Kode Verifikasi OTP yang dikirim langsung ke Gmail / Email pengguna**.

---

## 📋 Fitur Utama
1. **Send OTP (`POST /api/auth/send-otp`)**:
   - Generate kode verifikasi 6-digit acak.
   - Masa berlaku OTP: 5 menit.
   - Proteksi cooldown request: 60 detik per email.
   - Mengirim email dengan template HTML modern & elegan via **Gmail SMTP (Nodemailer)**.
2. **Verify OTP (`POST /api/auth/verify-otp`)**:
   - Validasi kode verifikasi.
   - Proteksi maksimal 5x percobaan salah.
   - Menerbitkan **JSON Web Token (JWT)** berlaku 30 hari.
   - Mengembalikan data pengguna (`id`, `email`, `name`, `createdAt`).
3. **Get Profile (`GET /api/auth/me`)**:
   - Cek keabsahan JWT token dan ambil profil user yang sedang login.

---

## 🛠️ Panduan Menjalankan di Komputer Lokal

### 1. Dapatkan App Password dari Google/Gmail (Gratis)
1. Buka akun Google pengirim di: [https://myaccount.google.com/apppasswords](https://myaccount.google.com/apppasswords)
   *(Pastikan Verifikasi 2 Langkah / 2FA sudah aktif di akun Google tersebut)*.
2. Beri nama aplikasi: `AusDMusic Auth`.
3. Klik **Create / Buat**. Google akan memberikan 16 digit password (contoh: `abcd efgh ijkl mnop`).
4. Salin password tersebut.

### 2. Konfigurasi `.env`
Duplikat file `.env.example` menjadi `.env`, lalu isi:
```env
PORT=3000
JWT_SECRET=rahasia_jwt_ausdmusic_kamu
GMAIL_USER=email.kamu@gmail.com
GMAIL_APP_PASSWORD=abcdefghijklmnop
NODE_ENV=development
```

### 3. Install Dependensi & Jalankan
```bash
cd server
npm install
npm start
```
Server akan berjalan di `http://localhost:3000`.

---

## 🌐 Panduan Deploy Gratis ke Internet

### Opsi A: Render.com (Gratis & Sangat Mudah)
1. Push folder `server` ke GitHub repository baru.
2. Buka [Render.com](https://render.com) -> New Web Service.
3. Hubungkan repo GitHub kamu.
4. Set **Build Command**: `npm install`
5. Set **Start Command**: `node server.js`
6. Tambahkan **Environment Variables**:
   - `GMAIL_USER` = email kamu
   - `GMAIL_APP_PASSWORD` = 16 digit app password
   - `JWT_SECRET` = rahasia acak
7. Klik Deploy. Kamu akan mendapatkan URL HTTPS seperti: `https://ausdmusic-auth.onrender.com`.

### Opsi B: Vercel Serverless
File `server.js` bisa langsung diexport untuk Vercel Serverless Function menggunakan adapter `vercel.json`.

---

## 🐘 Alternatif Backend: Laravel (PHP)

Jika kamu ingin menggunakan **Laravel**, buat controller `AuthController.php`:

```php
namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Cache;
use App\Models\User;

class AuthController extends Controller
{
    public function sendOtp(Request $request)
    {
        $request->validate(['email' => 'required|email']);
        $email = strtolower(trim($request->email));

        $otp = (string) rand(100000, 900000);
        Cache::put("otp_{$email}", $otp, now()->addMinutes(5));

        // Kirim email via Laravel Mail
        Mail::raw("Kode verifikasi AusDMusic Anda adalah: {$otp}", function ($message) use ($email) {
            $message->to($email)->subject("Kode Verifikasi AusDMusic");
        });

        return response()->json([
            'success' => true,
            'message' => 'Kode verifikasi telah dikirim ke email Anda'
        ]);
    }

    public function verifyOtp(Request $request)
    {
        $request->validate([
            'email' => 'required|email',
            'otp' => 'required|string'
        ]);

        $email = strtolower(trim($request->email));
        $cachedOtp = Cache::get("otp_{$email}");

        if (!$cachedOtp || $cachedOtp !== trim($request->otp)) {
            return response()->json([
                'success' => false,
                'message' => 'Kode OTP salah atau telah kadaluarsa'
            ], 400);
        }

        Cache::forget("otp_{$email}");

        $user = User::firstOrCreate(
            ['email' => $email],
            ['name' => explode('@', $email)[0]]
        );

        $token = $user->createToken('ausdmusic-token')->plainTextToken;

        return response()->json([
            'success' => true,
            'message' => 'Login berhasil!',
            'token' => $token,
            'user' => [
                'id' => (string) $user->id,
                'email' => $user->email,
                'name' => $user->name,
            ]
        ]);
    }
}
```
