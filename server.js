const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt"); // Pastikan bcrypt sudah terinstal: npm install bcrypt

// Pastikan path ke file-file ini benar dan file tersebut ada
const tamuRoutes = require("./routes/tamu");
const usersRoutes = require("./routes/users");
const db = require("./config/db"); // Pastikan konfigurasi database Anda benar (./config/db.js)

const app = express();
const port = process.env.PORT || 5000;

/* ======================= MIDDLEWARE ======================= */
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Logging setiap request
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} - ${req.method} ${req.originalUrl} - IP: ${req.ip}`);
  next();
});

// Middleware untuk mempercayai header proxy (penting agar req.ip benar jika di belakang proxy)
app.set('trust proxy', true);

// Error handling (pastikan ini adalah middleware terakhir sebelum app.listen)
app.use((err, req, res, next) => {
  console.error("❌ SERVER ERROR:", err.stack || err);
  res.status(500).json({ error: "Terjadi kesalahan fatal pada server." });
});

/* ======================= ENDPOINT UMUM ======================= */

app.get("/api/status", async (req, res) => {
  try {
    await db.query('SELECT 1 AS result');
    res.json({
      status: "online",
      server: "running",
      database: "connected",
      timestamp: new Date(),
    });
  } catch (err) {
    console.error("❌ Status check database error:", err);
    res.status(500).json({
      status: "degraded",
      server: "running",
      database: "disconnected",
      error_message: err.message,
      timestamp: new Date(),
    });
  }
});

app.get("/api/schema/tamu", (req, res) => {
  db.query("DESCRIBE tamu", (err, results) => {
    if (err) {
      console.error("❌ Gagal mendapatkan skema tabel 'tamu':", err);
      return res.status(500).json({ error: "Gagal mendapatkan skema tabel 'tamu'" });
    }
    const requiredColumns = [
      "id", "nama_lengkap", "jenis_kelamin", "email", "no_hp",
      "pekerjaan", "alamat", "keperluan", "staff", "dituju", "tanggal_kehadiran"
    ];
    const missingColumns = requiredColumns.filter(
      (col) => !results.some((r) => r.Field === col)
    );
    res.json({
      table: "tamu",
      schema: results,
      status: missingColumns.length === 0 ? "valid" : "invalid",
      missingColumns: missingColumns.length > 0 ? missingColumns : null,
    });
  });
});

/* ======================= LOGIN USER (Non-Admin) ======================= */
app.post("/api/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username dan password wajib diisi" });
  }

  db.query("SELECT * FROM users WHERE username = ?", [username], async (err, results) => {
    if (err) {
      console.error("❌ Gagal mengambil data user:", err);
      return res.status(500).json({ error: "Terjadi kesalahan server saat mengambil data user" });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: "Username tidak ditemukan" });
    }

    const user = results[0];
    const isMatch = password === user.password; // TIDAK AMAN jika password tidak di-hash

    if (!isMatch) {
      return res.status(401).json({ error: "Password salah" });
    }

    res.json({
      message: "Login user berhasil",
      user: { id: user.id, name: user.name, nip: user.nip, username: user.username },
    });
  });
});

/* ======================= LOGIN ADMIN ======================= */
app.post("/api/admin-login", (req, res) => {
  const { nama_pengguna, password } = req.body;
  console.log(`[ADMIN LOGIN ATTEMPT] User: ${nama_pengguna}`);

  if (!nama_pengguna || !password) {
    console.warn("[ADMIN LOGIN] Data tidak lengkap:", { nama_pengguna, password_exists: !!password });
    return res.status(400).json({ error: "Nama pengguna dan password admin wajib diisi" });
  }

  db.query("SELECT * FROM admins WHERE nama_pengguna = ?", [nama_pengguna], async (err, results) => {
    if (err) {
      console.error("❌ Gagal mengambil data admin dari DB:", err);
      return res.status(500).json({ error: "Kesalahan server saat mengambil data admin" });
    }

    if (results.length === 0) {
      console.warn(`[ADMIN LOGIN] Admin tidak ditemukan: ${nama_pengguna}`);
      return res.status(401).json({ error: "Admin tidak ditemukan" });
    }

    const admin = results[0];
    console.log("[ADMIN LOGIN] Data admin dari DB:", { id: admin.id, nama_pengguna: admin.nama_pengguna, password_stored: admin.password ? '***' : 'NOT_FOUND' });

    const isMatch = (password === admin.password); // SANGAT TIDAK AMAN. Segera ganti dengan bcrypt.

    if (!isMatch) {
      console.warn(`[ADMIN LOGIN] Password salah untuk admin: ${admin.nama_pengguna}`);
      return res.status(401).json({ error: "Password admin salah" });
    }

    console.log(`[ADMIN LOGIN] Login berhasil untuk admin: ${admin.nama_pengguna}`);

    // Simpan log aktivitas admin ke tabel baru yang disederhanakan
    if (admin.nama_pengguna) { // Hanya butuh nama_pengguna sekarang
      const usernameAdmin = admin.nama_pengguna;
      const waktuLogin = new Date(); // Mendapatkan waktu saat ini dari aplikasi

      // DEBUGGING LOG: Data yang akan dimasukkan ke tabel log
      console.log("ℹ️ [ADMIN LOGGING] Data untuk log admin (sederhana):", { usernameAdmin, waktuLogin });

      db.query(
        "INSERT INTO log_aktivitas_admin (username_admin, waktu_login) VALUES (?, ?)", // Query disederhanakan
        [usernameAdmin, waktuLogin], // Parameter disederhanakan
        (logErr, logResult) => {
          if (logErr) {
            console.error("❌ [ADMIN LOGGING] GAGAL menyimpan log aktivitas admin (sederhana):", logErr);
          } else {
            console.log("✅ [ADMIN LOGGING] Log aktivitas admin (sederhana) DISIMPAN, id:", logResult.insertId);
          }
        }
      );
    } else {
      console.warn("⚠️ [ADMIN LOGGING] Nama pengguna admin tidak ditemukan. Tidak bisa menyimpan log.", { admin_object: admin });
    }

    res.json({
      message: "Login admin berhasil",
      admin: { id: admin.id, nama_pengguna: admin.nama_pengguna }, // Respons ke klien tetap sama
    });
  });
});

/* ======================= TAMBAH DATA TAMU ======================= */
app.post("/api/tamu", (req, res) => {
  const {
    nama_lengkap, jenis_kelamin, email, no_hp, pekerjaan,
    alamat, keperluan, staff, dituju, tanggal_kehadiran,
  } = req.body;

  if (!nama_lengkap || !jenis_kelamin || !tanggal_kehadiran) {
    return res.status(400).json({ error: "Data tamu wajib (nama, jenis kelamin, tanggal hadir) tidak lengkap" });
  }

  const sql = `
    INSERT INTO tamu 
    (nama_lengkap, jenis_kelamin, email, no_hp, pekerjaan, alamat, keperluan, staff, dituju, tanggal_kehadiran)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  const values = [
    nama_lengkap, jenis_kelamin, email || null, no_hp || null, pekerjaan || null,
    alamat || null, keperluan || null, staff || null, dituju || null, tanggal_kehadiran,
  ];

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error("❌ Gagal menyimpan data tamu:", err);
      return res.status(500).json({ error: "Gagal menyimpan data tamu ke database" });
    }
    res.status(201).json({ message: "Data tamu berhasil disimpan", id: result.insertId });
  });
});

/* ======================= ROUTES TAMBAHAN ======================= */
app.use("/api/tamu", tamuRoutes);
app.use("/api/users", usersRoutes);

/* ======================= JALANKAN SERVER ======================= */
app.listen(port, () => {
  console.log(`✅ Server berjalan di http://localhost:${port}`);
  console.log(`ℹ️  Mode: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 Status endpoint: http://localhost:${port}/api/status`);
  console.log(`📋 Schema tamu endpoint: http://localhost:${port}/api/schema/tamu`);
});

/* ======================= HANDLE SIGINT (优雅关机) ======================= */
process.on("SIGINT", () => {
  console.log("🛑 Menghentikan server... Menutup koneksi database...");
  db.end((err) => {
    if (err) {
      console.error("❌ Error saat menutup koneksi database:", err);
      process.exit(1);
    } else {
      console.log("✅ Koneksi database ditutup dengan baik.");
      process.exit(0);
    }
  });
});