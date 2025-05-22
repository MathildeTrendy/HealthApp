const express = require('express');
const router = express.Router();
const { Pool } = require('pg');
const csrf = require('csurf');
const crypto = require('crypto');
const { requireAuth } = require('../middleware/auth');
const csrfProtection = csrf();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const ALGORITHM = 'aes-256-cbc';
const KEY = Buffer.from(process.env.MESSAGE_ENCRYPTION_KEY, 'utf-8');
const IV_LENGTH = 16;

function encrypt(text) {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return iv.toString('hex') + ':' + encrypted;
}

function decrypt(encrypted) {
    const [ivHex, data] = encrypted.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
    let decrypted = decipher.update(data, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
}

router.get('/:otherUserId', requireAuth, csrfProtection, async (req, res) => {
    const { otherUserId } = req.params;
    const currentUser = req.user;

    // Find modpart og tjek adgang
    const otherUser = (await pool.query('SELECT * FROM users WHERE id = $1', [otherUserId])).rows[0];
    if (!otherUser) return res.send('Bruger ikke fundet');

    const isPatient = currentUser.role === 'patient' && currentUser.psychiatrist_id === otherUser.id;
    const isPsychiatrist = currentUser.role === 'psychiatrist';
    const patient = isPatient ? currentUser : isPsychiatrist ? (await pool.query('SELECT * FROM users WHERE id = $1 AND psychiatrist_id = $2', [otherUserId, currentUser.id])).rows[0] : null;

    if (!isPatient && !patient) return res.send('Ingen adgang');

    const messages = (await pool.query(
        'SELECT * FROM private_messages WHERE (sender_id = $1 AND receiver_id = $2) OR (sender_id = $2 AND receiver_id = $1) ORDER BY created_at ASC',
        [currentUser.id, otherUserId]
    )).rows.map(m => ({
        ...m,
        content: decrypt(m.encrypted_content)
    }));

    res.render('messages', {
        messages,
        user: currentUser,
        otherUser,
        csrfToken: req.csrfToken()
    });
});

router.post('/send/:otherUserId', requireAuth, csrfProtection, async (req, res) => {
    const { otherUserId } = req.params;
    const currentUser = req.user;
    const encrypted = encrypt(req.body.message);

    // Simpel adgangstjek
    if (currentUser.role === 'patient' && currentUser.psychiatrist_id !== otherUserId) return res.send("Ugyldig adgang");

    await pool.query(
        'INSERT INTO private_messages (sender_id, receiver_id, encrypted_content) VALUES ($1, $2, $3)',
        [currentUser.id, otherUserId, encrypted]
    );

    res.redirect('/messages/' + otherUserId);
});

module.exports = router;
