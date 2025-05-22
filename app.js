const bcrypt = require('bcrypt');
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-openidconnect');
const path = require('path');
const flash = require('connect-flash');
const { Pool } = require('pg');
const crypto = require('crypto');
const csrf = require('csurf');
const { requireRole } = require('./middleware/auth');
require('dotenv').config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const app = express();

// Middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: false
    }
}));
app.use(flash());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

const csrfProtection = csrf();
app.use(csrfProtection);
app.use((req, res, next) => {
    res.locals.csrfToken = req.csrfToken();
    next();
});

// Passport OIDC
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
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        if (result.rows.length > 0) return done(null, result.rows[0]);
        return done(null, { id, email, role: null });
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(passport.initialize());
app.use(passport.session());

// Vælg rolle ved første besøg
app.get('/', csrfProtection, (req, res) => {
    if (req.isAuthenticated()) {
        if (req.user.role === 'patient') return res.redirect('/journal');
        if (req.user.role === 'psychiatrist') return res.redirect('/psychiatrist/patients');
        return res.send('Ugyldig rolle');
    }
    res.render('role_choice', { csrfToken: req.csrfToken() });
});

// Gem rollevalg midlertidigt i session og send videre til login/registrer
app.post('/choose-role-first', csrfProtection, (req, res) => {
    const { role } = req.body;
    if (!['patient', 'psychiatrist'].includes(role)) return res.send('Ugyldig rolle');
    req.session.chosenRole = role;
    res.redirect('/login-options');
});

// Vis login/registreringsvalg
app.get('/login-options', csrfProtection, (req, res) => {
    const role = req.session.chosenRole;
    if (!role) return res.redirect('/');
    res.render('login_options', { role, csrfToken: req.csrfToken() });
});

// Registrering (med psykologvalg hvis patient)
app.get('/register', csrfProtection, async (req, res) => {
    const role = req.session.chosenRole || 'patient';
    let psychiatrists = [];
    if (role === 'patient') {
        const result = await pool.query("SELECT id, email FROM users WHERE role = 'psychiatrist'");
        psychiatrists = result.rows;
    }
    res.render('register', { csrfToken: req.csrfToken(), role, psychiatrists });
});

app.post('/register', csrfProtection, async (req, res) => {
    const { email, password, psychiatrist_id } = req.body;
    const role = req.session.chosenRole || 'patient';
    const hashed = await bcrypt.hash(password, 12);
    const existing = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existing.rows.length > 0) return res.send("Bruger findes allerede");

    const id = 'local-' + crypto.randomUUID();
    await pool.query(
        'INSERT INTO users (id, email, role, password_hash, psychiatrist_id) VALUES ($1, $2, $3, $4, $5)',
        [id, email, role, hashed, role === 'patient' ? psychiatrist_id : null]
    );
    req.login({ id, email, role }, err => {
        if (err) return res.send("Fejl ved login");
        return res.redirect('/journal');
    });
});

// Klassisk login
app.get('/login/local', csrfProtection, (req, res) => {
    res.render('login_local', { csrfToken: req.csrfToken() });
});

app.post('/login/local', csrfProtection, async (req, res) => {
    const { email, password } = req.body;
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) return res.send("Ugyldig login");
    const user = result.rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) return res.send("Forkert adgangskode");

    req.login(user, err => {
        if (err) return res.send("Fejl ved login");
        if (user.role === 'patient') return res.redirect('/journal');
        if (user.role === 'psychiatrist') return res.redirect('/psychiatrist/patients');
        return res.send("Ugyldig rolle");
    });
});

// Google login flow
app.get('/auth', passport.authenticate('oidc'));
app.get('/auth/callback',
    passport.authenticate('oidc', { failureRedirect: '/login-options' }),
    (req, res) => {
        if (!req.user.role && req.session.chosenRole) {
            req.user.role = req.session.chosenRole;
            pool.query(
                'INSERT INTO users (id, email, role) VALUES ($1, $2, $3) ON CONFLICT (id) DO UPDATE SET role = $3',
                [req.user.id, req.user.email, req.user.role]
            );
        }
        if (req.user.role === 'patient') return res.redirect('/journal');
        if (req.user.role === 'psychiatrist') return res.redirect('/psychiatrist/patients');
        return res.send('Ugyldig rolle');
    }
);

// Logout
app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('/'));
});

// Patientnotater og psykologvisning
const journalRoutes = require('./routes/journal');
const psychiatristRoutes = require('./routes/psychiatrist');
app.use('/journal', journalRoutes);
app.use('/psychiatrist', psychiatristRoutes);

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
