# Mental Sundhedsdagbog – Secure Software Development

Dette er et eksamensprojekt i faget **Secure Software Development**.

Formålet med systemet er at give patienter mulighed for at føre en privat mental sundhedsdagbog, som deres tilknyttede psykolog også kan tilgå. Derudover kan patient og psykolog sende beskeder til hinanden. Projektet har fokus på sikkerhed, adgangskontrol og beskyttelse af personfølsomme oplysninger.

## 🛠 Funktioner
- Login med Google (OpenID Connect) eller klassisk login med email og adgangskode
- Rollebaseret adgang (patient/psykiater)
- Patienter kan skrive noter med emne og se tidligere noter
- Psykologer kan læse noter for deres tilknyttede patienter
- Besked-funktion (privat, krypteret besked mellem patient og psykolog)
- Adgangskontrol på alle ruter
- STRIDE- og attack-tree-baseret trusselsmodellering
- Sikker kode med bl.a. CSRF-beskyttelse, inputvalidering, Helmet og rate limiting

---

## 📦 Installation

1. **Klon repo**
```bash
git clone https://github.com/MathildeTrendy/HealthApp.git
```

2. **Installer afhængigheder**
```bash
npm install
```

3. **Opret `.env`-fil i roden:**
```env
DATABASE_URL=postgresql://brugernavn:password@host:port/database
SESSION_SECRET=noget-meget-hemmeligt
GOOGLE_CLIENT_ID=din-google-client-id
GOOGLE_CLIENT_SECRET=din-google-client-secret
OIDC_ISSUER=https://accounts.google.com
MESSAGE_ENCRYPTION_KEY=1234567890abcdef1234567890abcdef
```

> **OBS:** MESSAGE_ENCRYPTION_KEY skal være 32 tegn og bruges til AES-beskedkryptering.

4. **Sæt PostgreSQL op**
   - Supabase anvendes som database, men enhver PostgreSQL-instans kan bruges.
   - Du skal oprette følgende tabeller:

```sql
CREATE TABLE users (
    id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    role TEXT,
    password_hash TEXT,
    first_name TEXT,
    last_name TEXT,
    birth_date DATE,
    phone_number TEXT,
    start_date DATE,
    psychiatrist_id TEXT REFERENCES users(id)
);

CREATE TABLE notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    userid TEXT REFERENCES users(id),
    subject TEXT,
    content TEXT,
    created_at TIMESTAMP DEFAULT now()
);

CREATE TABLE private_messages (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sender_id TEXT,
    receiver_id TEXT,
    encrypted_content TEXT,
    read BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT now()
);
```

---

## 🚀 Kør projektet lokalt

```bash
node app.js 
```

Gå derefter til:

```
http://localhost:3000
```

---

## 🔒 Sikkerhedstiltag

- [x] STRIDE-analyse og Attack Tree
- [x] OpenID Connect (Google)
- [x] Klassisk login med adgangskodepolitik (min. 12 tegn, stort + småt bogstav, tal og specialtegn)
- [x] Password-bekræftelse ved registrering
- [x] AES-kryptering af beskeder
- [x] CSRF-beskyttelse (`csurf`)
- [x] Inputvalidering (`express-validator`)
- [x] Rate limiting på login (`express-rate-limit`)
- [x] Helmet – sikre HTTP-headers
- [x] Rollesikrede ruter og session-baseret adgangskontrol
- [x] Secure, HttpOnly og SameSite-cookies

---

## 👤 Brugerkonti

Du kan oprette brugere manuelt via registreringsflowet:
- Vælg rolle
- Opret bruger via email og password (Google også muligt)
- Log ind

En psykolog skal vælges, når en patient oprettes.

---

## 🧪 Test

Du kan teste følgende:
- En patient kan kun se egne noter
- En psykolog kan kun se noter fra sine egne patienter
- En patient og psykolog kan sende beskeder til hinanden
- En bruger kan ikke tilgå andres indhold (403 eller redirect)
- Forsøg på CSRF giver 403-fejl

---
