
-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Stocke le hash du mot de passe
    is_admin BOOLEAN DEFAULT FALSE,     -- Gestion des rôles
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des événements
CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description_short TEXT NOT NULL,
    description_long TEXT NOT NULL,
    event_date TIMESTAMP NOT NULL,
    location VARCHAR(255) NOT NULL,
    available_seats INTEGER NOT NULL CHECK (available_seats >= 0),
    image_url VARCHAR(255), -- URL de l'image de l'événement
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Table des inscriptions (lien entre utilisateurs et événements)
CREATE TABLE IF NOT EXISTS registrations (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL,
    event_id INTEGER NOT NULL,
    registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE,
    UNIQUE (user_id, event_id) -- Un utilisateur ne peut s'inscrire qu'une seule fois au même événement
);

-- Index pour améliorer les performances des requêtes
CREATE INDEX IF NOT EXISTS idx_registrations_user_id ON registrations (user_id);
CREATE INDEX IF NOT EXISTS idx_registrations_event_id ON registrations (event_id);
CREATE INDEX IF NOT EXISTS idx_events_event_date ON events (event_date);


CREATE EXTENSION IF NOT EXISTS pgcrypto;

INSERT INTO users (username, email, password_hash, is_admin)
VALUES (
    'admin',
    'admin@events.com',
    crypt('eventsmanager', gen_salt('bf')),
    TRUE
);