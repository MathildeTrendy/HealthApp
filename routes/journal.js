const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const { requireRole } = require('../middleware/auth');
const csrf = require('csurf');
const csrfProtection = csrf();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// Patient: se egne noter
router.get('/', requireRole('patient'), csrfProtection, async (req, res) => {
    const userInfo = await pool.query('SELECT first_name, last_name FROM users WHERE id = $1', [req.user.id]);
    const { rows } = await pool.query('SELECT * FROM notes WHERE userid = $1 ORDER BY created_at DESC', [req.user.id]);

    res.render('index_patient', {
        notes: rows,
        user: { ...req.user, ...userInfo.rows[0] },
        csrfToken: req.csrfToken()
    });
});

// Patient: tilføj notat
router.post('/add', requireRole('patient'), csrfProtection, async (req, res) => {
    const { note, subject } = req.body;
    await pool.query('INSERT INTO notes (userid, subject, content) VALUES ($1, $2, $3)', [req.user.id, subject, note]);
    res.redirect('/journal');
});

// Psykiater: se alle patientnotater
router.get('/all', requireRole('psychiatrist'), csrfProtection, async (req, res) => {
    const { rows } = await pool.query(`
        SELECT u.first_name, u.last_name, n.subject, n.content, n.created_at
        FROM notes n
                 JOIN users u ON n.userid = u.id
        ORDER BY n.created_at DESC
    `);
    res.render('index_psychiatrist', {
        notes: rows,
        user: req.user,
        csrfToken: req.csrfToken()
    });
});

module.exports = router;
