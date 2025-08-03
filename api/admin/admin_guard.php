<?php
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
require_once __DIR__ . '/api/auth_functions.php';

if (!isUserLoggedIn() || !isUserAdmin()) {
    $_SESSION['message'] = "Accès non autorisé. Vous devez être administrateur.";
    header('Location: /api/login.php');
    exit();
}
