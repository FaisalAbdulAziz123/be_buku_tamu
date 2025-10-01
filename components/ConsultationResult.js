import React, { useState } from "react";

const ConsultationResult = ({ guest, penerima }) => {
  const [hasil, setHasil] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    // Simpan hasil konsultasi ke backend di sini
    alert(`Hasil disimpan:\n${hasil}`);
  };

  return (
    <div>
      <h3>Hasil Konsultasi</h3>
      <p>
        <strong>Nama Tamu:</strong> {guest.nama}
      </p>
      <p>
        <strong>Diterima oleh:</strong> {penerima}
      </p>
      <textarea
        value={hasil}
        onChange={(e) => setHasil(e.target.value)}
        placeholder="Tuliskan hasil konsultasi di sini..."
        rows={6}
      />
      <button onClick={handleSubmit}>Simpan</button>
    </div>
  );
};

export default ConsultationResult;
