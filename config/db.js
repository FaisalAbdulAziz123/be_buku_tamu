// config/db.js - Perbaikan Stabil dan Siap Produksi
const mysql = require("mysql");

// Gunakan Pool agar koneksi lebih stabil
const pool = mysql.createPool({
  connectionLimit: 10,
  host: "localhost",
  user: "root", // sesuaikan
  password: "", // sesuaikan
  database: "buku_tamu", // sesuaikan
  charset: "utf8mb4",
});

// Fungsi query dengan Promise
const queryPromise = (sql, values = []) => {
  return new Promise((resolve, reject) => {
    pool.query(sql, values, (error, results) => {
      if (error) {
        console.error("❌ Query error:", error);
        return reject(error);
      }
      resolve(results);
    });
  });
};

// Fungsi cek koneksi
const checkConnection = () => {
  return queryPromise("SELECT 1");
};

module.exports = {
  pool,
  query: pool.query.bind(pool),
  queryPromise,
  checkConnection,
};
