const express = require("express");
const router = express.Router();
const db = require("../config/db");

// Helper function untuk handle database query dengan error handling yang lebih baik
const executeQuery = async (query, params = []) => {
  return new Promise((resolve, reject) => {
    // Cek apakah db.query adalah function
    if (typeof db.query !== "function") {
      reject(
        new Error(
          "Database connection tidak tersedia atau tidak memiliki method query"
        )
      );
      return;
    }

    db.query(query, params, (error, results) => {
      if (error) {
        console.error("Database query error:", error);
        reject(error);
      } else {
        console.log("Database query results:", results);
        resolve(results);
      }
    });
  });
};

// Test koneksi database
router.get("/test", async (req, res) => {
  try {
    console.log("Testing database connection...");
    console.log("Database object:", typeof db);
    console.log("Database query method:", typeof db.query);

    const result = await executeQuery("SELECT 1 as test");
    res.json({
      message: "Database connection successful",
      result: result,
    });
  } catch (err) {
    console.error("Database connection test failed:", err);
    res.status(500).json({
      error: "Database connection failed",
      details: err.message,
      stack: err.stack,
    });
  }
});

// Tambah user
router.post("/", async (req, res) => {
  const { name, nip, username, password } = req.body;

  // Validasi input
  if (!name || !nip || !username || !password) {
    return res.status(400).json({
      error: "Semua field (name, nip, username, password) harus diisi",
    });
  }

  try {
    console.log("Attempting to insert user:", { name, nip, username });
    const result = await executeQuery(
      "INSERT INTO users (name, nip, username, password) VALUES (?, ?, ?, ?)",
      [name, nip, username, password]
    );
    console.log("Insert result:", result);
    res.status(201).json({ message: "User berhasil ditambahkan" });
  } catch (err) {
    console.error("Error di POST /users:", err);
    res.status(500).json({
      error: "Gagal menambahkan user",
      details: err.message,
    });
  }
});

// Ambil semua user
router.get("/", async (req, res) => {
  try {
    console.log("Attempting to fetch all users...");

    // Cek apakah tabel users ada
    const tableExists = await executeQuery("SHOW TABLES LIKE 'users'");
    console.log("Table exists check:", tableExists);

    if (!tableExists || tableExists.length === 0) {
      return res.status(500).json({
        error: "Tabel 'users' tidak ditemukan di database",
      });
    }

    const rows = await executeQuery("SELECT * FROM users");
    console.log("Fetched users:", rows);
    console.log("Number of users:", rows ? rows.length : 0);

    res.json(rows || []);
  } catch (err) {
    console.error("Error di GET /users:", err);
    console.error("Error stack:", err.stack);
    res.status(500).json({
      error: "Gagal mengambil data users",
      details: err.message,
      code: err.code || "UNKNOWN_ERROR",
    });
  }
});

// Get user by ID
router.get("/:id", async (req, res) => {
  const { id } = req.params;

  try {
    console.log("Attempting to fetch user with ID:", id);
    const rows = await executeQuery("SELECT * FROM users WHERE id = ?", [id]);

    if (!rows || rows.length === 0) {
      return res.status(404).json({ message: "User tidak ditemukan" });
    }

    res.json(rows[0]);
  } catch (err) {
    console.error("Error di GET /users/:id:", err);
    res.status(500).json({
      error: "Gagal mengambil data user",
      details: err.message,
    });
  }
});

// Update user
// Update user (partial update)
router.put("/:id", async (req, res) => {
  const { id } = req.params;
  const { name, nip, username, password } = req.body;

  try {
    // Ambil data lama dulu
    const oldUser = await executeQuery("SELECT * FROM users WHERE id = ?", [id]);
    if (!oldUser || oldUser.length === 0) {
      return res.status(404).json({ message: "User tidak ditemukan" });
    }

    // Kalau field kosong → pakai data lama
    const updatedUser = {
      name: name || oldUser[0].name,
      nip: nip || oldUser[0].nip,
      username: username || oldUser[0].username,
      password: password || oldUser[0].password,
    };

    // Update ke database
    const result = await executeQuery(
      "UPDATE users SET name = ?, nip = ?, username = ?, password = ? WHERE id = ?",
      [updatedUser.name, updatedUser.nip, updatedUser.username, updatedUser.password, id]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User tidak ditemukan" });
    }

    res.json({ message: "User berhasil diperbarui" });
  } catch (err) {
    console.error("Error di PUT /users:", err);
    res.status(500).json({
      error: "Gagal memperbarui user",
      details: err.message,
    });
  }
});


// Hapus user
router.delete("/:id", async (req, res) => {
  const { id } = req.params;

  try {
    console.log("Attempting to delete user with ID:", id);
    const result = await executeQuery("DELETE FROM users WHERE id = ?", [id]);

    console.log("Delete result:", result);

    if (result.affectedRows === 0) {
      return res.status(404).json({ message: "User tidak ditemukan" });
    }

    res.json({ message: "User berhasil dihapus" });
  } catch (err) {
    console.error("Error di DELETE /users:", err);
    res.status(500).json({
      error: "Gagal menghapus user",
      details: err.message,
    });
  }
});

// Login admin
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username dan password harus diisi" });
  }

  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';
  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Query error:', err);
      return res.status(500).json({ error: "Server error" });
    }

    if (results.length > 0) {
      // Login berhasil
      return res.status(200).json({ message: "Login berhasil", user: results[0] });
    } else {
      // Username atau password salah
      return res.status(401).json({ error: "Username atau password salah" });
    }
  });
});


module.exports = router;
