const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const { requireRole } = require('../middleware/auth');
const csrf = require('csurf');
const csrfProtection = csrf();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Patient: se egne noter
router.get('/', requireRole('patient'), csrfProtection, async (req, res) => {
    const { rows } = await pool.query('SELECT * FROM notes WHERE userid = $1', [req.user.id]);
    res.render('index_patient', {
        notes: rows,
        user: req.user,
        csrfToken: req.csrfToken() // 👈 Vigtigt!
    });
});

// Patient: tilføj notat
router.post('/add', requireRole('patient'), csrfProtection, async (req, res) => {
    await pool.query('INSERT INTO notes (userid, content) VALUES ($1, $2)', [req.user.id, req.body.note]);
    res.redirect('/journal');
});

// Psykiater: se alle patientnotater
router.get('/all', requireRole('psychiatrist'), csrfProtection, async (req, res) => {
    const { rows } = await pool.query(`
        SELECT u.email, n.content
        FROM notes n
                 JOIN users u ON n.userid = u.id
        ORDER BY u.email
    `);
    res.render('index_psychiatrist', {
        notes: rows,
        user: req.user,
        csrfToken: req.csrfToken() // hvis formularer bruges
    });
});

module.exports = router;
