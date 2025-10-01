import React, { useState } from 'react';

function FormBukuTamu() {
  const [formData, setFormData] = useState({
    nama: '',
    instansi: '',
    tujuan: '',
    noTelepon: '',
    tanggal: ''
  });

  const handleChange = (e) => {
    setFormData({ ...formData, [e.target.name]: e.target.value });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();

    try {
      const res = await fetch('http://localhost:5000/api/tamu', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData)
      });

      if (res.ok) {
        alert('Data berhasil dikirim!');
        setFormData({ nama: '', instansi: '', tujuan: '', noTelepon: '', tanggal: '' });
      } else {
        alert('Gagal mengirim data');
      }
    } catch (err) {
      console.error(err);
      alert('Terjadi kesalahan saat mengirim data');
    }
  };

  return (
    <form onSubmit={handleSubmit} className="form">
      <input name="nama" placeholder="Nama" value={formData.nama} onChange={handleChange} required />
      <input name="instansi" placeholder="Instansi" value={formData.instansi} onChange={handleChange} required />
      <input name="tujuan" placeholder="Tujuan" value={formData.tujuan} onChange={handleChange} required />
      <input name="noTelepon" placeholder="No. Telepon" value={formData.noTelepon} onChange={handleChange} required />
      <input type="date" name="tanggal" value={formData.tanggal} onChange={handleChange} required />
      <button type="submit">Kirim</button>
    </form>
  );
}

export default FormBukuTamu;
