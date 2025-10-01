// src/components/GuestDetailModal.js
import React, { useContext } from "react";
import { GuestContext } from "../context/GuestContext";

const GuestDetail = ({ onClose }) => {
  const { selectedGuest } = useContext(GuestContext);

  return (
    <div className="modal">
      <div className="modal-content">
        <h3>Detail Tamu</h3>
        {selectedGuest && (
          <ul>
            {Object.entries(selectedGuest).map(([key, value]) => (
              <li key={key}>
                <strong>{key.replace(/_/g, " ")}:</strong> {value || "-"}
              </li>
            ))}
          </ul>
        )}
        <button onClick={onClose}>Tutup</button>
      </div>
    </div>
  );
};

export default GuestDetail;
