// C:/Users/Dell/buku-tamuu/src/backend/routes/tamu.js
const express = require("express");
const router = express.Router();
const db = require("../config/db");
// const multer = require("multer"); // Uncomment jika Anda akan implementasi upload file
// const path = require("path");

// ... (Konfigurasi Multer jika ada, bisa sama seperti sebelumnya) ...

// GET /api/tamu - Ambil semua data tamu
router.get("/", (req, res) => {
  const sql = "SELECT * FROM tamu ORDER BY tanggal_kehadiran DESC, id DESC";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("❌ BACKEND: Gagal mengambil semua data tamu:", err);
      return res
        .status(500)
        .json({ error: "Gagal mengambil data tamu", detail: err.message });
    }
    res.json(results);
  });
});

// GET /api/tamu/:id - Ambil data tamu spesifik
router.get("/:id", (req, res) => {
  const guestId = req.params.id;
  const sql = "SELECT * FROM tamu WHERE id = ?";
  db.query(sql, [guestId], (err, results) => {
    if (err) {
      console.error(
        `❌ BACKEND: Gagal mengambil data tamu dengan ID ${guestId}:`,
        err
      );
      return res.status(500).json({
        error: "Gagal mengambil data tamu dari database",
        detail: err.message,
      });
    }
    if (results.length === 0) {
      console.log(`BACKEND: Tamu dengan ID ${guestId} tidak ditemukan.`);
      return res
        .status(404)
        .json({ message: `Data tamu dengan ID ${guestId} tidak ditemukan` });
    }
    console.log(`BACKEND: Tamu dengan ID ${guestId} ditemukan:`, results[0]);
    res.json(results[0]);
  });
});

// POST /api/tamu - Menyimpan data tamu baru
router.post("/", (req, res) => {
  const newGuestData = { ...req.body };
  console.log(
    "✔️ BACKEND: Menerima data POST /api/tamu:",
    JSON.stringify(newGuestData, null, 2)
  );

  const jam_submit_data = new Date();

  const {
    nama_lengkap,
    jenis_kelamin,
    email,
    no_hp,
    pekerjaan,
    alamat,
    keperluan,
    staff,
    dituju,
    tanggal_kehadiran,
    tujuan_kunjungan,
    topik_konsultasi,
    deskripsi_kebutuhan,
  } = newGuestData;

  const status = newGuestData.status || "Belum Diproses";

  if (
    !nama_lengkap ||
    !jenis_kelamin ||
    !keperluan ||
    !tanggal_kehadiran ||
    !alamat ||
    !no_hp
  ) {
    console.error(
      "❌ BACKEND: Data POST tidak lengkap. Wajib: Nama, JK, Keperluan, Tgl Kehadiran, Alamat, No HP.",
      newGuestData
    );
    return res.status(400).json({
      error:
        "Data wajib (Nama, Jenis Kelamin, No HP, Alamat, Keperluan, Tanggal Kehadiran) tidak lengkap.",
    });
  }

  let validatedDateKehadiran;
  try {
    const d = new Date(tanggal_kehadiran);
    if (isNaN(d.getTime())) {
      throw new Error(
        `Format tanggal tidak valid setelah parsing: ${tanggal_kehadiran}`
      );
    }
    validatedDateKehadiran = d;
  } catch (e) {
    console.error(
      "❌ BACKEND: Error parsing tanggal_kehadiran dari frontend:",
      tanggal_kehadiran,
      e
    );
    return res.status(400).json({
      error: "Format tanggal kehadiran tidak valid.",
      detail: e.message,
    });
  }

  // --- PERBAIKAN SQL QUERY ---
  // Hapus komentar JavaScript (//) dari dalam string SQL.
  // Jika ingin memberi catatan, gunakan komentar SQL /* ... */ atau letakkan di luar string.
  const sql = `
    INSERT INTO tamu (
      nama_lengkap, jenis_kelamin, email, no_hp, pekerjaan, alamat, keperluan, 
      staff, dituju, tanggal_kehadiran, status, 
      tujuan_kunjungan, topik_konsultasi, deskripsi_kebutuhan, 
      jam_submit_data
      /* Kolom yang tidak disebutkan di sini dan nullable 
         akan otomatis diisi NULL oleh database atau nilai defaultnya. */
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `;
  // Jumlah kolom di atas adalah 15, jadi 15 placeholder '?'.

  const values = [
    nama_lengkap,
    jenis_kelamin,
    email || null,
    no_hp,
    pekerjaan || null,
    alamat,
    keperluan,
    staff || null,
    dituju || null,
    validatedDateKehadiran,
    status,
    keperluan === "mitra_statistik" || keperluan === "tamu_umum"
      ? tujuan_kunjungan || null
      : null,
    keperluan === "konsultasi_statistik" ? topik_konsultasi || null : null,
    keperluan === "konsultasi_statistik" ? deskripsi_kebutuhan || null : null,
    jam_submit_data,
  ];
  // Pastikan array 'values' ini memiliki 15 item.

  console.log(
    "✔️ BACKEND: Values yang akan diinsert ke DB:",
    JSON.stringify(values, null, 2)
  );

  db.query(sql, values, (err, result) => {
    if (err) {
      console.error("❌ BACKEND: Gagal menyimpan data tamu baru ke DB:", err);
      return res.status(500).json({
        error: "Gagal menyimpan data tamu ke database.",
        detail: err.message,
        sqlState: err.sqlState,
        sqlMessage: err.sqlMessage, // Ini penting untuk debug
      });
    }
    console.log(
      "✔️ BACKEND: Data tamu baru berhasil disimpan, ID:",
      result.insertId
    );
    db.query(
      "SELECT * FROM tamu WHERE id = ?",
      [result.insertId],
      (errSelect, newGuestArray) => {
        if (errSelect || newGuestArray.length === 0) {
          console.error(
            "❌ BACKEND: Gagal mengambil data tamu setelah insert:",
            errSelect
          );
          return res.status(201).json({
            message:
              "Data tamu berhasil disimpan! (Gagal mengambil data terbaru setelah penyimpanan)",
            id: result.insertId,
            status: status,
          });
        }
        res.status(201).json({
          message: "Data tamu berhasil disimpan!",
          id: result.insertId,
          guest: newGuestArray[0],
        });
      }
    );
  });
});

// ... (kode PUT dan DELETE Anda) ...
router.put("/:id", (req, res) => {
  const guestId = req.params.id;
  const receivedFields = req.body;
  const currentTime = new Date();

  console.log(`✔️ BACKEND: Menerima permintaan PUT untuk /api/tamu/${guestId}`);
  console.log(
    "✔️ BACKEND: Data yang diterima (req.body) untuk diupdate:",
    JSON.stringify(receivedFields, null, 2)
  );

  const selectSql = "SELECT * FROM tamu WHERE id = ?";
  db.query(selectSql, [guestId], (errFetch, currentResults) => {
    if (errFetch) {
      console.error(
        `❌ BACKEND: Gagal mengambil data tamu ID ${guestId} sebelum update:`,
        errFetch
      );
      return res.status(500).json({
        error: "Gagal memproses update (fetch awal).",
        detail: errFetch.message,
      });
    }
    if (currentResults.length === 0) {
      return res
        .status(404)
        .json({ error: `Data tamu ID ${guestId} tidak ditemukan.` });
    }
    const currentGuest = currentResults[0];

    const fieldsToUpdate = {};
    const allowedFieldsToUpdate = [
      "nama_lengkap",
      "jenis_kelamin",
      "email",
      "no_hp",
      "pekerjaan",
      "alamat",
      "keperluan",
      "staff",
      "dituju",
      "tanggal_kehadiran",
      "status",
      "tujuan_kunjungan",
      "topik_konsultasi",
      "deskripsi_kebutuhan",
      "diterima_oleh",
      "isi_pertemuan",
      "dokumentasi",
    ];

    allowedFieldsToUpdate.forEach((field) => {
      if (receivedFields.hasOwnProperty(field)) {
        if (field === "tanggal_kehadiran" && receivedFields[field]) {
          try {
            const d = new Date(receivedFields[field]);
            if (isNaN(d.getTime()))
              throw new Error("Format tanggal tidak valid saat update");
            fieldsToUpdate[field] = d;
          } catch (e) {
            console.warn(
              `⚠️ BACKEND: Format tanggal_kehadiran diabaikan saat update karena tidak valid: ${receivedFields[field]}`
            );
          }
        } else {
          fieldsToUpdate[field] =
            receivedFields[field] === "" || receivedFields[field] === undefined
              ? null
              : receivedFields[field];
        }
      }
    });

    if (
      !currentGuest.jam_diterima &&
      (fieldsToUpdate.status === "Diproses" ||
        (fieldsToUpdate.diterima_oleh &&
          fieldsToUpdate.diterima_oleh !== currentGuest.diterima_oleh))
    ) {
      fieldsToUpdate.jam_diterima = currentTime;
      console.log(`✔️ BACKEND: jam_diterima di-set untuk ID ${guestId}`);
    }
    if (
      !currentGuest.jam_selesai_tindak_lanjut &&
      fieldsToUpdate.status === "Selesai"
    ) {
      fieldsToUpdate.jam_selesai_tindak_lanjut = currentTime;
      console.log(
        `✔️ BACKEND: jam_selesai_tindak_lanjut di-set untuk ID ${guestId}`
      );
    }

    if (fieldsToUpdate.hasOwnProperty("keperluan")) {
      if (fieldsToUpdate.keperluan === "konsultasi_statistik") {
        if (!fieldsToUpdate.hasOwnProperty("tujuan_kunjungan"))
          fieldsToUpdate.tujuan_kunjungan = null;
      } else if (
        fieldsToUpdate.keperluan === "mitra_statistik" ||
        fieldsToUpdate.keperluan === "tamu_umum"
      ) {
        if (!fieldsToUpdate.hasOwnProperty("topik_konsultasi"))
          fieldsToUpdate.topik_konsultasi = null;
        if (!fieldsToUpdate.hasOwnProperty("deskripsi_kebutuhan"))
          fieldsToUpdate.deskripsi_kebutuhan = null;
      }
    }

    const fieldEntries = Object.entries(fieldsToUpdate).filter(
      ([key, value]) => value !== undefined
    );

    if (fieldEntries.length === 0) {
      console.log(
        "✔️ BACKEND: Tidak ada field yang perlu diupdate untuk ID:",
        guestId
      );
      return res
        .status(200)
        .json({ message: "Tidak ada data yang diubah.", guest: currentGuest });
    }

    const setClauses = fieldEntries.map(([key]) => `\`${key}\` = ?`).join(", ");
    const finalValues = fieldEntries.map(([, value]) => value);
    finalValues.push(guestId);

    const updateSql = `UPDATE tamu SET ${setClauses} WHERE id = ?`;
    console.log("✔️ BACKEND: SQL Update Query:", updateSql);
    console.log(
      "✔️ BACKEND: Values untuk SQL Update:",
      JSON.stringify(finalValues, null, 2)
    );

    db.query(updateSql, finalValues, (errUpdate, result) => {
      if (errUpdate) {
        console.error(
          `❌ BACKEND: Gagal mengupdate data tamu ID ${guestId}:`,
          errUpdate
        );
        return res.status(500).json({
          error: "Gagal mengupdate data tamu di database.",
          detail: errUpdate.sqlMessage || errUpdate.message,
        });
      }
      if (result.affectedRows === 0) {
        return res.status(404).json({
          error: `Data tamu dengan ID ${guestId} tidak ditemukan saat mencoba update.`,
        });
      }
      console.log(`✔️ BACKEND: Data tamu ID ${guestId} berhasil diupdate.`);
      db.query(selectSql, [guestId], (errFetchAgain, updatedGuestResult) => {
        if (errFetchAgain || updatedGuestResult.length === 0) {
          console.error(
            `❌ BACKEND: Gagal mengambil data tamu ID ${guestId} setelah update:`,
            errFetchAgain
          );
          return res.status(200).json({
            message:
              "Data tamu berhasil diperbarui (gagal mengambil data terbaru setelah update).",
            updated_id: guestId,
          });
        }
        res.json({
          message: "Data tamu berhasil diperbarui!",
          guest: updatedGuestResult[0],
        });
      });
    });
  });
});

router.delete("/:id", (req, res) => {
  const guestId = req.params.id;
  console.log(`BACKEND: Menerima permintaan DELETE untuk /api/tamu/${guestId}`);
  const sql = "DELETE FROM tamu WHERE id = ?";
  db.query(sql, [guestId], (err, result) => {
    if (err) {
      console.error(
        `❌ BACKEND: Gagal menghapus data tamu ID ${guestId}:`,
        err
      );
      return res
        .status(500)
        .json({ error: "Gagal menghapus data tamu", detail: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: `Data tamu dengan ID ${guestId} tidak ditemukan untuk dihapus`,
      });
    }
    console.log(`BACKEND: Data tamu ID ${guestId} berhasil dihapus.`);
    res.json({ message: "Data tamu berhasil dihapus" });
  });
});

module.exports = router;
