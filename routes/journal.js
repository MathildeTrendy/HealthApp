const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect('/login');
}

router.get('/', ensureAuthenticated, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).send('Forbidden');
    const { rows } = await pool.query('SELECT * FROM notes WHERE userid = $1', [req.user.id]);
    res.render('index_patient', { notes: rows, user: req.user });
});

router.post('/add', ensureAuthenticated, async (req, res) => {
    if (req.user.role !== 'patient') return res.status(403).send('Forbidden');
    await pool.query('INSERT INTO notes (userid, content) VALUES ($1, $2)', [req.user.id, req.body.note]);
    res.redirect('/journal');
});

router.get('/all', ensureAuthenticated, async (req, res) => {
    if (req.user.role !== 'psychiatrist') return res.status(403).send('Forbidden');
    const { rows } = await pool.query(`
    SELECT u.email, n.content
    FROM notes n
    JOIN users u ON n.userid = u.id
    ORDER BY u.email
  `);
    res.render('index_psychiatrist', { notes: rows, user: req.user });
});

module.exports = router;
