<?php

require_once(__DIR__ . '/db_connect.php');

/**
 * Enregistre un nouvel utilisateur.
 * @param string $username Nom d'utilisateur.
 * @param string $email Adresse email.
 * @param string $password Mot de passe en clair.
 * @return bool Vrai si l'inscription est réussie, faux sinon.
 */
function registerUser($username, $email, $password)
{
    global $pdo; // Accède à l'objet PDO global

    // Vérifie si l'utilisateur ou l'email existe déjà
    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = :username OR email = :email");
    $stmt->execute(['username' => $username, 'email' => $email]);
    if ($stmt->fetch()) {
        $_SESSION['message'] = "Le nom d'utilisateur ou l'email existe déjà.";
        return false;
    }

    // Hache le mot de passe avant de le stocker
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    try {
        // Prépare et exécute la requête d'insertion
        $stmt = $pdo->prepare("INSERT INTO users (username, email, password_hash) VALUES (:username, :email, :password_hash)");
        $stmt->execute([
            'username' => $username,
            'email' => $email,
            'password_hash' => $password_hash
        ]);
        $_SESSION['message'] = "Inscription réussie ! Vous pouvez maintenant vous connecter.";
        return true;
    } catch (PDOException $e) {
        // Gère les erreurs d'insertion
        $_SESSION['message'] = "Erreur lors de l'inscription : " . $e->getMessage();
        return false;
    }
}

/**
 * Connecte un utilisateur.
 * @param string $email Email de l'utilisateur.
 * @param string $password Mot de passe en clair.
 * @return bool Vrai si la connexion est réussie, faux sinon.
 */
function loginUser($email, $password)
{
    global $pdo;
    try {
        // Prépare la requête pour récupérer l'utilisateur par son email
        $stmt = $pdo->prepare("SELECT id, username, password_hash, is_admin FROM users WHERE email = :email");
        $stmt->execute(['email' => $email]);
        $user = $stmt->fetch();

        // Si l'utilisateur est trouvé et le mot de passe est correct
        if ($user && password_verify($password, $user['password_hash'])) {
            // Démarre la session si ce n'est pas déjà fait
            if (session_status() == PHP_SESSION_NONE) {
                session_start();
            }

            // Enregistre les informations de l'utilisateur dans la session
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            $_SESSION['is_admin'] = $user['is_admin'];
            $_SESSION['message'] = "Connexion réussie. Bienvenue, " . htmlspecialchars($user['username']) . "!";
            return true;
        } else {
            // Affiche un message d'erreur si l'email ou le mot de passe est incorrect
            $_SESSION['message'] = "Email ou mot de passe incorrect.";
            return false;
        }
    } catch (PDOException $e) {
        error_log("Erreur de connexion : " . $e->getMessage());
        $_SESSION['message'] = "Une erreur est survenue lors de la connexion.";
        return false;
    }
}

/**
 * Déconnecte un utilisateur en détruisant sa session.
 */
function logoutUser()
{
    // Démarre la session si ce n'est pas déjà fait
    if (session_status() == PHP_SESSION_NONE) {
        session_start();
    }
    // Supprime toutes les variables de session
    $_SESSION = array();
    // Détruit la session
    session_destroy();
    // Affiche un message de déconnexion
    $_SESSION['message'] = "Vous avez été déconnecté avec succès.";
}

/**
 * Vérifie si l'utilisateur est connecté.
 * @return bool
 */
function isUserLoggedIn()
{
    // Vérifie si la session a été démarrée et si l'ID de l'utilisateur existe
    return isset($_SESSION['user_id']);
}

/**
 * Vérifie si l'utilisateur connecté est un administrateur.
 * @return bool
 */
function isUserAdmin()
{
    // Vérifie si l'utilisateur est connecté et si son statut d'admin est vrai
    return isUserLoggedIn() && isset($_SESSION['is_admin']) && $_SESSION['is_admin'];
}

/**
 * Récupère tous les utilisateurs.
 * @return array Une liste d'utilisateurs ou un tableau vide.
 */
function getAllUsers()
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("SELECT id, username, email, is_admin, created_at FROM users ORDER BY created_at DESC");
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Erreur lors de la récupération des utilisateurs : " . $e->getMessage());
        return [];
    }
}

/**
 * Supprime un utilisateur par son ID.
 * @param int $userId ID de l'utilisateur.
 * @return bool Vrai si la suppression est réussie, faux sinon.
 */
function deleteUser($userId)
{
    global $pdo;
    try {
        // Prépare et exécute la requête de suppression
        $stmt = $pdo->prepare("DELETE FROM users WHERE id = :id");
        return $stmt->execute(['id' => $userId]);
    } catch (PDOException $e) {
        error_log("Erreur lors de la suppression de l'utilisateur : " . $e->getMessage());
        return false;
    }
}

/**
 * Met à jour le statut admin d'un utilisateur.
 * @param int $userId ID de l'utilisateur.
 * @param bool $isAdmin Nouveau statut admin.
 * @return bool Vrai si la mise à jour est réussie, faux sinon.
 */
function updateUserAdminStatus($userId, $isAdmin)
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("UPDATE users SET is_admin = :is_admin WHERE id = :id");
        return $stmt->execute(['id' => $userId, 'is_admin' => $isAdmin]);
    } catch (PDOException $e) {
        error_log("Erreur lors de la mise à jour du statut admin : " . $e->getMessage());
        return false;
    }
}
