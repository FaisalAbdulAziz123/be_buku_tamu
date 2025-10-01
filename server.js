const express = require("express");
const cors = require("cors");
const bcrypt = require('bcryptjs'); // Pastikan Anda sudah menginstall bcryptjs

// Pastikan path ke file-file ini benar
const tamuRoutes = require("./routes/tamu");
const usersRoutes = require("./routes/users");
const db = require("./config/db"); // Pastikan konfigurasi database Anda sudah benar

const app = express();

/* ======================= MIDDLEWARE ======================= */
app.use(cors());
app.use(express.json({ limit: "1mb" }));
app.use(express.urlencoded({ extended: true, limit: "1mb" }));

// Logging setiap request
app.use((req, res, next) => {
  console.log(`[REQ] ${new Date().toISOString()} - ${req.method} ${req.originalUrl} - IP: ${req.ip}`);
  next();
});

// Middleware untuk mempercayai header proxy (penting agar req.ip benar di Vercel)
app.set('trust proxy', true);

/* ======================= ENDPOINT UMUM ======================= */

app.get("/api/status", async (req, res) => {
  try {
    // Gunakan promise wrapper jika db library Anda tidak mendukungnya secara native
    await db.promise().query('SELECT 1 AS result');
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

/* ======================= LOGIN USER (Diperbaiki dengan bcryptjs) ======================= */
app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username dan password wajib diisi" });
  }

  try {
    // Menggunakan db.promise() untuk async/await
    const [results] = await db.promise().query("SELECT * FROM users WHERE username = ?", [username]);

    if (results.length === 0) {
      return res.status(401).json({ error: "Username tidak ditemukan" });
    }

    const user = results[0];
    
    // PERBAIKAN PENTING: Gunakan bcrypt.compare untuk membandingkan password
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ error: "Password salah" });
    }

    res.json({
      message: "Login user berhasil",
      user: { id: user.id, name: user.name, nip: user.nip, username: user.username },
    });
  } catch (err) {
    console.error("❌ Gagal mengambil data user:", err);
    return res.status(500).json({ error: "Terjadi kesalahan server saat mengambil data user" });
  }
});

/* ======================= LOGIN ADMIN (Diperbaiki dengan bcryptjs) ======================= */
app.post("/api/admin-login", async (req, res) => {
    const { nama_pengguna, password } = req.body;
    console.log(`[ADMIN LOGIN ATTEMPT] User: ${nama_pengguna}`);

    if (!nama_pengguna || !password) {
        console.warn("[ADMIN LOGIN] Data tidak lengkap:", { nama_pengguna, password_exists: !!password });
        return res.status(400).json({ error: "Nama pengguna dan password admin wajib diisi" });
    }
    
    try {
        const [results] = await db.promise().query("SELECT * FROM admins WHERE nama_pengguna = ?", [nama_pengguna]);
        
        if (results.length === 0) {
            console.warn(`[ADMIN LOGIN] Admin tidak ditemukan: ${nama_pengguna}`);
            return res.status(401).json({ error: "Admin tidak ditemukan" });
        }

        const admin = results[0];
        
        // PERBAIKAN PENTING: Gunakan bcrypt.compare untuk membandingkan password dengan aman
        const isMatch = await bcrypt.compare(password, admin.password);

        if (!isMatch) {
            console.warn(`[ADMIN LOGIN] Password salah untuk admin: ${admin.nama_pengguna}`);
            return res.status(401).json({ error: "Password admin salah" });
        }

        console.log(`[ADMIN LOGIN] Login berhasil untuk admin: ${admin.nama_pengguna}`);
        
        // Logika untuk menyimpan log aktivitas
        try {
            const usernameAdmin = admin.nama_pengguna;
            const waktuLogin = new Date();
            await db.promise().query(
              "INSERT INTO log_aktivitas_admin (username_admin, waktu_login) VALUES (?, ?)",
              [usernameAdmin, waktuLogin]
            );
            console.log("✅ [ADMIN LOGGING] Log aktivitas admin DISIMPAN");
        } catch (logErr) {
            console.error("❌ [ADMIN LOGGING] GAGAL menyimpan log aktivitas admin:", logErr);
        }

        res.json({
            message: "Login admin berhasil",
            admin: { id: admin.id, nama_pengguna: admin.nama_pengguna },
        });

    } catch (err) {
        console.error("❌ Gagal mengambil data admin dari DB:", err);
        return res.status(500).json({ error: "Kesalahan server saat mengambil data admin" });
    }
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

/* ======================= ERROR HANDLING (Middleware terakhir) ======================= */
app.use((err, req, res, next) => {
  console.error("❌ SERVER ERROR:", err.stack || err);
  res.status(500).json({ error: "Terjadi kesalahan fatal pada server." });
});

/* ======================= UNTUK VERCEL ======================= */
// Baris app.listen() DIHAPUS karena Vercel yang akan menangani server.
// Sebagai gantinya, kita ekspor aplikasi 'app'
module.exports = app;
