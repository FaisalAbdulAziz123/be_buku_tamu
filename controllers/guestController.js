const db = require('../config/db');

// Get all guests (optional)
exports.getAllGuests = (req, res) => {
  const sql = "SELECT * FROM guests";
  db.query(sql, (err, results) => {
    if (err) {
      console.error('Error fetching guests:', err);
      return res.status(500).json({ error: 'Gagal mengambil data tamu' });
    }
    res.json(results);
  });
};

// Create new guest - fungsi yang dipanggil POST /api/guests
exports.createGuest = (req, res) => {
  const { nama_lengkap, jenis_kelamin, email, no_hp, pekerjaan, tgl_kedatangan, alamat } = req.body;

  // Validasi sederhana
  if (!nama_lengkap || !jenis_kelamin || !no_hp || !tgl_kedatangan || !alamat) {
    return res.status(400).json({ error: 'Data tidak lengkap' });
  }

  const sql = `
    INSERT INTO guests (nama_lengkap, jenis_kelamin, email, no_hp, pekerjaan, tgl_kedatangan, alamat)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `;
  const values = [nama_lengkap, jenis_kelamin, email, no_hp, pekerjaan, tgl_kedatangan, alamat];

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error('Error inserting guest:', err);
      return res.status(500).json({ error: 'Gagal menyimpan data tamu' });
    }
    res.status(201).json({ message: 'Data tamu berhasil disimpan', id: result.insertId });
  });
};

// Delete guest by id (optional)
exports.deleteGuest = (req, res) => {
  const id = req.params.id;
  const sql = "DELETE FROM guests WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error('Error deleting guest:', err);
      return res.status(500).json({ error: 'Gagal menghapus data tamu' });
    }
    res.json({ message: 'Data tamu berhasil dihapus' });
  });
};
