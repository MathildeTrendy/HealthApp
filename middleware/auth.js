function requireAuth(req, res, next) {
    if (!req.isAuthenticated()) {
        return res.status(401).send('Du skal være logget ind.');
    }
    next();
}

function requireRole(role) {
    return function (req, res, next) {
        if (!req.isAuthenticated()) {
            return res.status(401).send('Du skal være logget ind.');
        }
        if (req.user.role !== role) {
            return res.status(403).send('Adgang nægtet: forkert rolle.');
        }
        next();
    };
}

module.exports = {
    requireAuth,
    requireRole
};
