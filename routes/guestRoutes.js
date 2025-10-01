const express = require('express');
const router = express.Router();
const guestController = require('../controllers/guestController');

router.get('/', guestController.getAllGuests);
router.post('/', guestController.createGuest);   // Endpoint untuk simpan data tamu
router.delete('/:id', guestController.deleteGuest);

module.exports = router;
