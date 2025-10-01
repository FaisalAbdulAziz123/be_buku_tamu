import React, { useState } from "react";

const ReceiveGuest = ({ guest, onContinue }) => {
  const [penerima, setPenerima] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    onContinue(penerima);
  };

  return (
    <form onSubmit={handleSubmit}>
      <h3>Terima Tamu</h3>
      <p>
        <strong>Nama:</strong> {guest.nama}
      </p>
      <input
        type="text"
        placeholder="Diterima oleh..."
        value={penerima}
        onChange={(e) => setPenerima(e.target.value)}
        required
      />
      <button type="submit">Lanjutkan ke Hasil Konsultasi</button>
    </form>
  );
};

export default ReceiveGuest;
