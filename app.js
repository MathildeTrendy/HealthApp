const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { Strategy } = require('passport-openidconnect');
const path = require('path');
const flash = require('connect-flash');
const { Pool } = require('pg');
require('dotenv').config();

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

const app = express();

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));
app.use(flash());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.set('view engine', 'ejs');

passport.use(new Strategy({
    issuer: process.env.OIDC_ISSUER,
    authorizationURL: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenURL: 'https://oauth2.googleapis.com/token',
    userInfoURL: 'https://openidconnect.googleapis.com/v1/userinfo',
    clientID: process.env.OIDC_CLIENT_ID,
    clientSecret: process.env.OIDC_CLIENT_SECRET,
    callbackURL: process.env.OIDC_CALLBACK_URL,
    scope: ['openid', 'profile', 'email']
}, async (issuer, sub, profile, accessToken, refreshToken, params, done) => {
    const id = sub;
    const email = profile?.emails?.[0]?.value || 'unknown@example.com';

    try {
        const result = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
        if (result.rows.length === 0) {
            return done(null, { id, email, role: null }); // ny bruger
        }
        return done(null, result.rows[0]); // eksisterende bruger
    } catch (err) {
        return done(err);
    }
}));

passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

app.use(passport.initialize());
app.use(passport.session());

// Midlertidig rollevalg
app.get('/choose-role', (req, res) => {
    if (!req.isAuthenticated() || req.user.role) return res.redirect('/');
    res.render('login', { user: req.user });
});

app.post('/choose-role', async (req, res) => {
    const role = req.body.role;
    await pool.query('INSERT INTO users (id, email, role) VALUES ($1, $2, $3)', [
        req.user.id, req.user.email, role
    ]);
    req.user.role = role;
    res.redirect('/');
});

// Authentication
app.get('/auth', passport.authenticate('openidconnect'));
app.get('/auth/callback',
    passport.authenticate('openidconnect', { failureRedirect: '/login' }),
    (req, res) => {
        if (!req.user.role) return res.redirect('/choose-role');
        res.redirect('/');
    }
);

app.get('/login', (req, res) => res.send('<a href="/auth">Login med Google</a>'));
app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('/login'));
});

// Rollebaseret routing
app.get('/', (req, res) => {
    if (!req.isAuthenticated()) return res.redirect('/login');
    if (req.user.role === 'patient') return res.redirect('/journal');
    if (req.user.role === 'psychiatrist') return res.redirect('/journal/all');
});

// Routes
const journalRoutes = require('./routes/journal');
app.use('/journal', journalRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
