<?php
require_once(__DIR__ . 'admin_guard.php');

require_once(__DIR__ . '/api/db_connect.php');
require_once(__DIR__ . '/api/auth_functions.php');
require_once(__DIR__ . '/api/event_functions.php');

$action = $_GET['action'] ?? '';
$eventId = $_GET['id'] ?? null;

// Gère les actions POST (création, modification, suppression)
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_POST['create_event'])) {

        $imagePath = null;

        if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
            $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
            $fileType = mime_content_type($_FILES['image']['tmp_name']);

            if (!in_array($fileType, $allowedTypes)) {
                $_SESSION['message'] = "Format d'image non autorisé. Seuls les fichiers JPG, PNG et GIF sont acceptés.";
            } else {
                $uploadDir = '../public/images/uploads/';
                if (!is_dir($uploadDir)) {
                    mkdir($uploadDir, 0755, true);
                }

                $filename = basename($_FILES['image']['name']);
                $targetPath = $uploadDir . uniqid() . '_' . $filename;

                if (move_uploaded_file($_FILES['image']['tmp_name'], $targetPath)) {
                    $imagePath = $targetPath;
                } else {
                    $_SESSION['message'] = "Erreur lors de l'upload de l'image.";
                }
            }
        }


        $data = [
            'title' => trim($_POST['title'] ?? ''),
            'description_short' => trim($_POST['description_short'] ?? ''),
            'description_long' => trim($_POST['description_long'] ?? ''),
            'event_date' => trim($_POST['event_date'] ?? ''),
            'location' => trim($_POST['location'] ?? ''),
            'available_seats' => (int)($_POST['available_seats'] ?? 0),
            'image_url' => $imagePath
        ];

        if (empty($data['title']) || empty($data['description_short']) || empty($data['description_long']) || empty($data['event_date']) || empty($data['location']) || $data['available_seats'] < 0) {
            $_SESSION['message'] = "Veuillez remplir tous les champs obligatoires et vérifier les places disponibles.";
        } else {
            if (createEvent($data)) {
                $_SESSION['message'] = "Événement créé avec succès !";
            } else {
                $_SESSION['message'] = "Erreur lors de la création de l'événement.";
            }
        }
    } elseif (isset($_POST['update_event'])) {
        $eventId = $_POST['event_id'] ?? null;

        // Récupère les données actuelles de l'événement pour conserver l'image existante si aucune nouvelle n'est téléchargée
        $currentEvent = getEventById($eventId);

        if (!$currentEvent) {
            $_SESSION['message'] = "Événement à modifier introuvable.";
            header('Location: /manage_events.php');
            exit();
        }

        // Initialise imagePath avec l'URL de l'image existante
        $imagePath = $currentEvent['image_url'];

        // Gère le téléchargement de la nouvelle image
        if (isset($_FILES['image']) && $_FILES['image']['error'] === UPLOAD_ERR_OK) {
            $allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
            $fileType = mime_content_type($_FILES['image']['tmp_name']);

            if (!in_array($fileType, $allowedTypes)) {
                $_SESSION['message'] = "Format d'image non autorisé. Seuls les fichiers JPG, PNG et GIF sont acceptés.";
            } else {
                $uploadDir = '../public/images/uploads/';
                if (!is_dir($uploadDir)) {
                    mkdir($uploadDir, 0755, true);
                }

                $filename = basename($_FILES['image']['name']);
                $targetPath = $uploadDir . uniqid() . '_' . $filename;

                if (move_uploaded_file($_FILES['image']['tmp_name'], $targetPath)) {
                    // Nouvelle image téléchargée avec succès, met à jour le chemin
                    $imagePath = $targetPath;
                    // Supprime l'ancienne image si elle existe
                    if ($currentEvent['image_url'] && file_exists($currentEvent['image_url'])) {
                        unlink($currentEvent['image_url']);
                    }
                } else {
                    $_SESSION['message'] = "Erreur lors de l'upload de la nouvelle image.";
                }
            }
        }
        // Si aucune nouvelle image n'est téléchargée, $imagePath conserve l'ancienne valeur.

        $data = [
            'title' => trim($_POST['title'] ?? ''),
            'description_short' => trim($_POST['description_short'] ?? ''),
            'description_long' => trim($_POST['description_long'] ?? ''),
            'event_date' => trim($_POST['event_date'] ?? ''),
            'location' => trim($_POST['location'] ?? ''),
            'available_seats' => (int)($_POST['available_seats'] ?? 0),
            'image_url' => $imagePath // Utilise le chemin d'image déterminé
        ];

        if (empty($data['title']) || empty($data['description_short']) || empty($data['description_long']) || empty($data['event_date']) || empty($data['location']) || $data['available_seats'] < 0) {
            $_SESSION['message'] = "Veuillez remplir tous les champs obligatoires et vérifier les places disponibles.";
        } else {
            if (updateEvent($eventId, $data)) {
                $_SESSION['message'] = "Événement mis à jour avec succès !";
            } else {
                $_SESSION['message'] = "Erreur lors de la mise à jour de l'événement.";
            }
        }
    } elseif (isset($_POST['delete_event'])) {
        $eventId = $_POST['event_id'] ?? null;
        if ($eventId && is_numeric($eventId)) {
            // l'événement est récupéré ici pour supprimer l'image associée du serveur
            $eventToDelete = getEventById($eventId);
            if ($eventToDelete && $eventToDelete['image_url'] && file_exists($eventToDelete['image_url'])) {
                unlink($eventToDelete['image_url']);
            }

            if (deleteEvent($eventId)) {
                $_SESSION['message'] = "Événement supprimé avec succès !";
            } else {
                $_SESSION['message'] = "Erreur lors de la suppression de l'événement.";
            }
        } else {
            $_SESSION['message'] = "ID d'événement invalide pour la suppression.";
        }
    }
    header('Location: manage_events.php'); // Redirige pour éviter la soumission multiple
    exit();
}

$pageTitle = "Gestion des Événements";
include '/api/admin/header.php';
?>

<h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">Gestion des Événements</h1>

<?php if ($action === 'create'): ?>
    <!-- Formulaire création d'événement -->
    <div class="max-w-2xl mx-auto bg-white p-8 rounded-lg shadow-lg">
        <h2 class="text-2xl font-bold text-gray-900 mb-6 text-center">Créer un nouvel événement</h2>
        <form action="manage_events.php?action=create" method="POST" enctype="multipart/form-data">
            <div class="mb-4">
                <label for="title" class="block text-sm font-medium text-gray-700">Évènement :</label>
                <input type="text" id="title" name="title" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" required>
            </div>
            <div class="mb-4">
                <label for="description_short" class="block text-sm font-medium text-gray-700">Courte description :</label>
                <textarea id="description_short" name="description_short" rows="3" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" required></textarea>
            </div>
            <div class="mb-4">
                <label for="description_long" class="block text-sm font-medium text-gray-700">Description longue :</label>
                <textarea id="description_long" name="description_long" rows="6" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" required></textarea>
            </div>
            <div class="mb-4">
                <label for="event_date" class="block text-sm font-medium text-gray-700">Date et heure :</label>
                <input type="datetime-local" id="event_date" name="event_date" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" required>
            </div>
            <div class="mb-4">
                <label for="location" class="block text-sm font-medium text-gray-700">Lieu :</label>
                <input type="text" id="location" name="location" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" required>
            </div>
            <div class="mb-4">
                <label for="available_seats" class="block text-sm font-medium text-gray-700">Nombre de places disponibles :</label>
                <input type="number" id="available_seats" name="available_seats" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" min="0" required>
            </div>
            <div class="mb-6">
                <label for="image" class="block text-sm font-medium text-gray-700">Image de l'événement :</label>
                <input type="file" id="image" name="image" accept="image/*" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
            </div>
            <div class="mb-6">
                <img id="preview" src="#" class="w-full h-48 object-cover rounded-lg">
            </div>
            <button type="submit" name="create_event" class="font-bold text-lg text-[#347fd4] hover:text-indigo-900 border-2 rounded-full bg-white hover:bg-amber-50 px-4 p-2 shadow-lg transition duration-300 ease-in-out w-full cursor-pointer">Créer l'événement</button>
        </form>
        <div class="mt-4 text-center">
            <a href="manage_events.php" class="font-bold text-red-600 hover:text-red-900 border-1 rounded-full bg-white hover:bg-amber-50 px-4 py-2 shadow-lg transition duration-300 ease-in-out">Annuler</a>
        </div>
    </div>

<?php elseif ($action === 'edit' && $eventId): ?>
    <?php
    $event = getEventById($eventId);
    if (!$event) {
        $_SESSION['message'] = "Événement à modifier introuvable.";
        header('Location: /manage_events.php');
        exit();
    }
    ?>
    <!-- Formulaire modification événement -->
    <div class="max-w-2xl mx-auto bg-white p-8 rounded-lg shadow-lg">
        <h2 class="text-2xl font-bold text-gray-900 mb-6 text-center">Modifier l'événement : <?php echo htmlspecialchars($event['title']); ?></h2>
        <form action="manage_events.php" method="POST" enctype="multipart/form-data">
            <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
            <div class="mb-4">
                <label for="title" class="block text-sm font-medium text-gray-700">Évènement :</label>
                <input type="text" id="title" name="title" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" value="<?php echo htmlspecialchars($event['title']); ?>" required>
            </div>
            <div class="mb-4">
                <label for="description_short" class="block text-sm font-medium text-gray-700">Courte description :</label>
                <textarea id="description_short" name="description_short" rows="3" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" required><?php echo htmlspecialchars($event['description_short']); ?></textarea>
            </div>
            <div class="mb-4">
                <label for="description_long" class="block text-sm font-medium text-gray-700">Description longue :</label>
                <textarea id="description_long" name="description_long" rows="6" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" required><?php echo htmlspecialchars($event['description_long']); ?></textarea>
            </div>
            <div class="mb-4">
                <label for="event_date" class="block text-sm font-medium text-gray-700">Date et heure :</label>
                <input type="datetime-local" id="event_date" name="event_date" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" value="<?php echo date('Y-m-d\TH:i', strtotime($event['event_date'])); ?>" required>
            </div>
            <div class="mb-4">
                <label for="location" class="block text-sm font-medium text-gray-700">Lieu :</label>
                <input type="text" id="location" name="location" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" value="<?php echo htmlspecialchars($event['location']); ?>" required>
            </div>
            <div class="mb-4">
                <label for="available_seats" class="block text-sm font-medium text-gray-700">Nombre de places disponibles :</label>
                <input type="number" id="available_seats" name="available_seats" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm" min="0" value="<?php echo htmlspecialchars($event['available_seats']); ?>" required>
            </div>
            <div class="mb-6">
                <label for="image" class="block text-sm font-medium text-gray-700">Image de l'événement :</label>
                <input type="file" id="image" name="image" accept="image/*" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm">
            </div>
            <div class="mb-6">
                <img id="preview" src="#" class="w-full h-48 object-cover rounded-lg hidden">
            </div>
            <?php if (!empty($event['image_url'])): ?>
                <div class="mb-6">
                    <p class="block text-sm font-medium text-gray-700 mb-2">Image actuelle :</p>
                    <img id="current-image" src="/<?php echo ltrim(htmlspecialchars($event['image_url']), '/'); ?>" alt="Image de l'événement <?php echo htmlspecialchars($event['title']); ?>" class="w-full h-48 object-cover rounded-lg">
                </div>
            <?php endif; ?>
            <button type="submit" name="update_event" class="font-bold text-lg text-[#347fd4] hover:text-indigo-900 border-2 rounded-full bg-white hover:bg-amber-50 px-4 p-2 shadow-lg transition duration-300 ease-in-out w-full cursor-pointer">Mettre à jour l'événement</button>
        </form>
        <div class="mt-4 text-center">
            <a href="/api/admin/manage_events.php" class="font-bold text-red-600 hover:text-red-900 border-1 rounded-full bg-white hover:bg-amber-50 px-4 py-2 shadow-lg transition duration-300 ease-in-out">Annuler</a>
        </div>
    </div>

<?php else: // Affiche la liste des événements 
?>
    <div class="mb-6 text-right">
        <a href="/api/admin/manage_events.php?action=create" class="px-5 py-2 rounded-full text-xl text-[#FFF] hover:text-gray-800 font-medium transition-colors border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-amber-50 hover:border-gray-800 cursor-pointer duration-300 ease-in-out">Créer un nouvel événement</a>
    </div>

    <?php
    $events = getAllEventsWithRegistrationCount();
    if (empty($events)): ?>
        <p class="text-center text-gray-600 text-lg">Aucun événement à gérer pour le moment.</p>
    <?php else: ?>
        <div class="bg-white rounded-lg shadow-lg overflow-hidden overflow-x-auto">
            <table class="min-w-full divide-y divide-gray-200">
                <thead class="bg-gray-50">
                    <tr>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Évènement</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Lieu</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Places Disp.</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Inscrits</th>
                        <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                    </tr>
                </thead>
                <tbody class="bg-white divide-y divide-gray-200">
                    <?php foreach ($events as $event): ?>
                        <tr>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900"><?php echo htmlspecialchars($event['title']); ?></td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo date('d/m/Y H:i', strtotime($event['event_date'])); ?></td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo htmlspecialchars($event['location']); ?></td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo htmlspecialchars($event['available_seats']); ?></td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo htmlspecialchars($event['registered_count']); ?></td>
                            <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                <a href="manage_events.php?action=edit&id=<?php echo htmlspecialchars($event['id']); ?>" class="text-[#4A90E2] hover:text-indigo-900 border-1 rounded-full bg-white hover:bg-amber-50 px-4 pb-1 pt-1 shadow-lg h-7 mr-4">Modifier</a>
                                <form action="manage_events.php" method="POST" class="inline-block" onsubmit="return confirm('Êtes-vous sûr de vouloir supprimer cet événement ? Toutes les inscriptions associées seront également supprimées.');">
                                    <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                                    <button type="submit" name="delete_event" class="text-red-600 hover:text-red-900 border-1 rounded-full bg-white hover:bg-amber-50 px-2.5 pb-1 pt-0.5 shadow-lg h-7 cursor-pointer">Supprimer</button>
                                </form>
                            </td>
                        </tr>
                    <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    <?php endif; ?>
<?php endif; ?>

<div class="mt-10">
    <a href="/api/admin/index.php" class="px-5 py-2 rounded-full text-base text-[#FFF] hover:text-gray-800 font-medium transition-colors border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-[#FFF] hover:border-gray-800 cursor-pointer duration-300 ease-in-out">Retour</a>
</div>

<?php include '/api/admin/footer.php'; ?>