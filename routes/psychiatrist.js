const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const { requireRole } = require('../middleware/auth');
const csrf = require('csurf');
const csrfProtection = csrf();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Se alle patienter, som psykologen er tilknyttet
router.get('/patients', requireRole('psychiatrist'), csrfProtection, async (req, res) => {
    const { rows } = await pool.query('SELECT id, email FROM users WHERE psychiatrist_id = $1', [req.user.id]);
    res.render('psychiatrist_patients', { patients: rows, user: req.user, csrfToken: req.csrfToken() });
});

// Se noter for en specifik patient
router.get('/notes/:patientId', requireRole('psychiatrist'), csrfProtection, async (req, res) => {
    const patientId = req.params.patientId;
    const check = await pool.query('SELECT * FROM users WHERE id = $1 AND psychiatrist_id = $2', [patientId, req.user.id]);
    if (check.rows.length === 0) return res.status(403).send("Ingen adgang til denne patient");

    const notes = await pool.query('SELECT content FROM notes WHERE userid = $1', [patientId]);
    res.render('psychiatrist_notes', { notes: notes.rows, patientId, user: req.user, csrfToken: req.csrfToken() });
});

module.exports = router;
