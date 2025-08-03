<?php

require_once(__DIR__ . '/db_connect.php');
require_once(__DIR__ . '/auth_functions.php');
require_once(__DIR__ . '/event_functions.php');

// Vérifie si l'utilisateur est connecté
if (!isUserLoggedIn()) {
    $_SESSION['message'] = "Vous devez être connecté pour vous inscrire à un événement.";
    header('Location: /api/login.php');
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $eventId = $_POST['event_id'] ?? null;
    $userId = $_SESSION['user_id'];

    if ($eventId && is_numeric($eventId)) {
        if (registerForEvent($userId, $eventId)) {
            // Message de succès déjà défini dans registerForEvent()
        } else {
            // Message d'erreur déjà défini dans registerForEvent()
        }
    } else {
        $_SESSION['message'] = "ID d'événement invalide.";
    }
} else {
    $_SESSION['message'] = "Requête invalide.";
}

// Redirige vers la page de détail de l'événement ou la page d'accueil
if ($eventId) {
    header('Location: /api/event_detail.php?id=' . htmlspecialchars($eventId));
} else {
    header('Location: /');
}
exit();
