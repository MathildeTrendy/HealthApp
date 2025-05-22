const bcrypt = require('bcrypt');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-openidconnect');
const path = require('path');
const flash = require('connect-flash');
const { Pool } = require('pg');
const crypto = require('crypto'); // til lokal bruger-ID
require('dotenv').config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const app = express();

// Middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(flash());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

// Passport OpenID Connect Strategy
passport.use('oidc', new Strategy({
    issuer: process.env.OIDC_ISSUER,
    authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenURL: 'https://oauth2.googleapis.com/token',
    userInfoURL: 'https://openidconnect.googleapis.com/v1/userinfo',
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: 'http://localhost:3000/auth/callback',
    scope: ['openid', 'profile', 'email']
}, async (issuer, subject, profile, jwtClaims, accessToken, refreshToken, params, done) => {
    const id = subject;
    const email = profile.emails?.[0]?.value || '';
    try {
        const existing = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        if (existing.rows.length > 0) return done(null, existing.rows[0]);
        return done(null, { id, email, role: null }); // bruger skal vælge rolle
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(passport.initialize());
app.use(passport.session());

// Rollevalg (kun første gang)
app.get('/choose-role', (req, res) => {
    if (!req.isAuthenticated() || req.user.role) return res.redirect('/');
    res.render('login', { user: req.user });
});

app.post('/choose-role', async (req, res) => {
    const role = req.body.role;
    await pool.query('INSERT INTO users (id, email, role) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET role = $3', [
        req.user.id, req.user.email, role
    ]);
    req.user.role = role;
    res.redirect('/');
});

// Google authentication routes
app.get('/auth', passport.authenticate('oidc'));

app.get('/auth/callback',
    passport.authenticate('oidc', { failureRedirect: '/login' }),
    (req, res) => {
        if (!req.user.role) return res.redirect('/choose-role');
        res.redirect('/');
    }
);

// Klassisk registrering (kun patienter)
app.get('/register', (req, res) => {
    res.render('register');
});

app.post('/register', async (req, res) => {
    const { email, password } = req.body;
    const hashed = await bcrypt.hash(password, 12);

    const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) {
        return res.send("Bruger findes allerede");
    }

    const id = 'local-' + crypto.randomUUID();
    await pool.query(
        'INSERT INTO users (id, email, role, password_hash) VALUES ($1, $2, $3, $4)',
        [id, email, 'patient', hashed]
    );

    req.login({ id, email, role: 'patient' }, err => {
        if (err) return res.send("Fejl ved login");
        return res.redirect('/');
    });
});

// Klassisk login
app.get('/login/local', (req, res) => {
    res.render('login_local');
});

app.post('/login/local', async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);

    if (result.rows.length === 0) return res.send("Ugyldig login");

    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);

    if (!match) return res.send("Forkert adgangskode");

    req.login(user, err => {
        if (err) return res.send("Fejl ved login");
        return res.redirect('/');
    });
});

// Login-landing med begge muligheder
app.get('/login', (req, res) => {
    res.send(`
        <a href="/auth">Login med Google</a><br>
        <a href="/login/local">Login med email og kodeord</a>
    `);
});

app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('/login'));
});

// Rollebaseret routing
app.get('/', (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    if (req.user.role === 'patient') return res.redirect('/journal');
    if (req.user.role === 'psychiatrist') return res.redirect('/journal/all');
    return res.send('Ugyldig rolle');
});

// Routes
const journalRoutes = require('./routes/journal');
app.use('/journal', journalRoutes);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
