# Events - eventribe

## Structure 📂

/Events
├── composer.json
├── composer.lock
├── vercel.json
├── api/ # Tous les fichiers
│ ├── index.php # Page d'accueil (liste des événements)
│ ├── event_detail.php # Page de détail d'un événement
│ ├── register.php # Formulaire d'inscription
│ ├── login.php # Formulaire de connexion
│ ├── logout.php # Déconnexion
│ ├── register_event.php # Inscription à un événement
│ ├── unregister_event.php # Désinscription d'un événement
| ├── header.php
│ ├── db_connect.php # Connexion à la base de données
│ ├── auth_functions.php # Fonctions d'authentification et de gestion des utilisateurs
│ ├── event_functions.php # Fonctions de gestion des événements
│ ├── legal_mentions.php # Mentions légales et politique de confidentialité
│ ├── footer.php
│ └── admin/ # Interface d'administration (back-office)
| │ ├── index.php # Dashboard admin
│ | ├── manage_events.php # Gestion CRUD des événements
│ | ├── admin_guard.php # Verification en plus
│ | ├── manage_users.php # Gestion des utilisateurs
│ | ├── manage_registrations.php # Gestion des inscriptions
│ | ├── header.php
│ | ├── footer.php
| ├── public/
│ | ├── styles/
│ | | └── styles.css
│ | ├── scripts/
│ | | └── script.js
│ | ├── images/

- [.github](.github/) is a folder that used to place Github related stuff, like CI pipeline.
- [public](public/) is a folder that contains the php files and the static files like images, scripts, and styles.
- [.env.example](.env.example) is a file that contains the environment variables used in this app.
- [.gitignore](.gitignore) is a file to exclude some folders and files from Git.
- [.vercelignore](.vercelignore) is a file to exclude some folders and files from Vercel.
- [LICENSE](LICENSE) is a file that contains the license used in this app.
- [README.md](README.md) is the file you are reading now.
- [composer.json](composer.json) is a file that contains the dependencies used and metadata in this app.
- [composer.lock](composer.lock) is a file that contains detailed list of all the dependencies and their specific versions that are currently installed in this app.
- [vercel.json](vercel.json) is a file that contains configuration and override the default behavior of Vercel.

## Installation 🛠️
