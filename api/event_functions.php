<?php

require_once(__DIR__ . '/db_connect.php');

/**
 * Récupère tous les événements avec le nombre d'inscrits.
 * @return array Liste des événements.
 */
function getAllEventsWithRegistrationCount()
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            SELECT
                e.id,
                e.title,
                e.event_date,
                e.location,
                e.description_short,
                e.available_seats,
                e.image_url,
                COUNT(r.id) AS registered_count
            FROM
                events e
            LEFT JOIN
                registrations r ON e.id = r.event_id
            GROUP BY
                e.id, e.title, e.event_date, e.location, e.description_short, e.available_seats, e.image_url
            ORDER BY
                e.event_date ASC
        ");
        $stmt->execute();
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Erreur lors de la récupération des événements : " . $e->getMessage());
        return [];
    }
}

/**
 * Récupère un événement par son ID.
 * @param int $eventId ID de l'événement.
 * @return array|false Les détails de l'événement ou faux si non trouvé.
 */
function getEventById($eventId)
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("SELECT * FROM events WHERE id = :id");
        $stmt->execute(['id' => $eventId]);
        return $stmt->fetch();
    } catch (PDOException $e) {
        error_log("Erreur lors de la récupération de l'événement : " . $e->getMessage());
        return false;
    }
}

/**
 * Crée un nouvel événement.
 * @param array $data Données de l'événement (title, description_short, description_long, event_date, location, available_seats, image_url).
 * @return bool Vrai si la création est réussie, faux sinon.
 */
function createEvent($data)
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            INSERT INTO events (title, description_short, description_long, event_date, location, available_seats, image_url)
            VALUES (:title, :description_short, :description_long, :event_date, :location, :available_seats, :image_url)
        ");
        return $stmt->execute([
            'title' => $data['title'],
            'description_short' => $data['description_short'],
            'description_long' => $data['description_long'],
            'event_date' => $data['event_date'],
            'location' => $data['location'],
            'available_seats' => $data['available_seats'],
            'image_url' => $data['image_url'] ?? null // L'URL de l'image est facultative
        ]);
    } catch (PDOException $e) {
        error_log("Erreur lors de la création de l'événement : " . $e->getMessage());
        return false;
    }
}

/**
 * Met à jour un événement existant.
 * @param int $eventId ID de l'événement.
 * @param array $data Données de l'événement à mettre à jour.
 * @return bool Vrai si la mise à jour est réussie, faux sinon.
 */

if (!empty($data['image_url'])) {
    error_log("Image à enregistrer : " . $data['image_url']);
} else {
    error_log("Aucune image à enregistrer !");
}

function updateEvent($eventId, $data)
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            UPDATE events
            SET
                title = :title,
                description_short = :description_short,
                description_long = :description_long,
                event_date = :event_date,
                location = :location,
                available_seats = :available_seats,
                image_url = :image_url
            WHERE id = :id
        ");
        return $stmt->execute([
            'id' => $eventId,
            'title' => $data['title'],
            'description_short' => $data['description_short'],
            'description_long' => $data['description_long'],
            'event_date' => $data['event_date'],
            'location' => $data['location'],
            'available_seats' => $data['available_seats'],
            'image_url' => $data['image_url'] ?? null
        ]);
    } catch (PDOException $e) {
        error_log("Erreur lors de la mise à jour de l'événement : " . $e->getMessage());
        return false;
    }
}

/**
 * Supprime un événement.
 * @param int $eventId ID de l'événement.
 * @return bool Vrai si la suppression est réussie, faux sinon.
 */
function deleteEvent($eventId)
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("DELETE FROM events WHERE id = :id");
        return $stmt->execute(['id' => $eventId]);
    } catch (PDOException $e) {
        error_log("Erreur lors de la suppression de l'événement : " . $e->getMessage());
        return false;
    }
}

/**
 * Enregistre un utilisateur à un événement.
 * @param int $userId ID de l'utilisateur.
 * @param int $eventId ID de l'événement.
 * @return bool Vrai si l'inscription est réussie, faux sinon.
 */
function registerForEvent($userId, $eventId)
{
    global $pdo;
    try {
        // Vérifie si l'utilisateur est déjà inscrit
        $stmt = $pdo->prepare("SELECT id FROM registrations WHERE user_id = :user_id AND event_id = :event_id");
        $stmt->execute(['user_id' => $userId, 'event_id' => $eventId]);
        if ($stmt->fetch()) {
            $_SESSION['message'] = "Vous êtes déjà inscrit à cet événement.";
            return false;
        }

        // Vérifie si des places sont disponibles
        $event = getEventById($eventId);
        if (!$event || $event['available_seats'] <= 0) {
            $_SESSION['message'] = "Plus de places disponibles ou événement introuvable.";
            return false;
        }

        // Commence une transaction pour s'assurer de la cohérence
        $pdo->beginTransaction();

        // Insére l'inscription
        $stmt = $pdo->prepare("INSERT INTO registrations (user_id, event_id) VALUES (:user_id, :event_id)");
        $stmt->execute(['user_id' => $userId, 'event_id' => $eventId]);

        // Décrémente le nombre de places disponibles
        $stmt = $pdo->prepare("UPDATE events SET available_seats = available_seats - 1 WHERE id = :event_id");
        $stmt->execute(['event_id' => $eventId]);

        $pdo->commit(); // Valide la transaction
        $_SESSION['message'] = "Inscription à l'événement réussie !";
        return true;
    } catch (PDOException $e) {
        $pdo->rollBack(); // Annule la transaction en cas d'erreur
        error_log("Erreur lors de l'inscription à l'événement : " . $e->getMessage());
        $_SESSION['message'] = "Erreur lors de l'inscription à l'événement : " . $e->getMessage();
        return false;
    }
}

/**
 * Désinscrit un utilisateur d'un événement.
 * @param int $userId ID de l'utilisateur.
 * @param int $eventId ID de l'événement.
 * @return bool Vrai si la désinscription est réussie, faux sinon.
 */
function unregisterFromEvent($userId, $eventId)
{
    global $pdo;
    try {
        // Vérifie si l'utilisateur est bien inscrit
        $stmt = $pdo->prepare("SELECT id FROM registrations WHERE user_id = :user_id AND event_id = :event_id");
        $stmt->execute(['user_id' => $userId, 'event_id' => $eventId]);
        if (!$stmt->fetch()) {
            $_SESSION['message'] = "Vous n'êtes pas inscrit à cet événement.";
            return false;
        }

        // Commence une transaction
        $pdo->beginTransaction();

        // Supprime l'inscription
        $stmt = $pdo->prepare("DELETE FROM registrations WHERE user_id = :user_id AND event_id = :event_id");
        $stmt->execute(['user_id' => $userId, 'event_id' => $eventId]);

        // Incrémente le nombre de places disponibles
        $stmt = $pdo->prepare("UPDATE events SET available_seats = available_seats + 1 WHERE id = :event_id");
        $stmt->execute(['event_id' => $eventId]);

        $pdo->commit(); // Valider la transaction
        $_SESSION['message'] = "Désinscription de l'événement réussie.";
        return true;
    } catch (PDOException $e) {
        $pdo->rollBack(); // Annuler la transaction
        error_log("Erreur lors de la désinscription de l'événement : " . $e->getMessage());
        $_SESSION['message'] = "Erreur lors de la désinscription de l'événement : " . $e->getMessage();
        return false;
    }
}

/**
 * Vérifie si un utilisateur est inscrit à un événement.
 * @param int $userId ID de l'utilisateur.
 * @param int $eventId ID de l'événement.
 * @return bool Vrai si inscrit, faux sinon.
 */
function isUserRegisteredForEvent($userId, $eventId)
{
    global $pdo;
    $stmt = $pdo->prepare("SELECT id FROM registrations WHERE user_id = :user_id AND event_id = :event_id");
    $stmt->execute(['user_id' => $userId, 'event_id' => $eventId]);
    return (bool)$stmt->fetch();
}

/**
 * Récupère la liste des participants pour un événement donné.
 * @param int $eventId ID de l'événement.
 * @return array Liste des participants.
 */
function getParticipantsForEvent($eventId)
{
    global $pdo;
    try {
        $stmt = $pdo->prepare("
            SELECT
                u.id AS user_id,
                u.username,
                u.email,
                r.registered_at
            FROM
                users u
            JOIN
                registrations r ON u.id = r.user_id
            WHERE
                r.event_id = :event_id
            ORDER BY
                r.registered_at ASC
        ");
        $stmt->execute(['event_id' => $eventId]);
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Erreur lors de la récupération des participants : " . $e->getMessage());
        return [];
    }
}

function countRegistrations()
{
    global $pdo;
    $stmt = $pdo->query("SELECT COUNT(*) FROM registrations");
    return (int) $stmt->fetchColumn();
}


/**
 * Recherche des événements par titre ou description.
 * @param string $searchTerm Le terme de recherche.
 * @return array Liste des événements correspondants avec le nombre d'inscrits.
 */
function searchEvents($searchTerm)
{
    global $pdo;
    try {
        $searchTerm = '%' . $searchTerm . '%';
        $stmt = $pdo->prepare("
            SELECT
                e.id,
                e.title,
                e.event_date,
                e.location,
                e.description_short,
                e.available_seats,
                e.image_url,
                COUNT(r.id) AS registered_count
            FROM
                events e
            LEFT JOIN
                registrations r ON e.id = r.event_id
            WHERE
                e.title ILIKE :searchTerm OR e.description_short ILIKE :searchTerm OR e.description_long ILIKE :searchTerm
            GROUP BY
                e.id, e.title, e.event_date, e.location, e.description_short, e.available_seats, e.image_url
            ORDER BY
                e.event_date ASC
        ");
        $stmt->execute(['searchTerm' => $searchTerm]);
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Erreur lors de la recherche d'événements : " . $e->getMessage());
        return [];
    }
}
