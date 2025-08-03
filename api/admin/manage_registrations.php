<?php
require_once(__DIR__ . 'admin_guard.php');

require_once(__DIR__ . '/api/db_connect.php');
require_once(__DIR__ . '/api/auth_functions.php');
require_once(__DIR__ . '/api/event_functions.php');


// Gère la désinscription d'un participant
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['unregister_participant'])) {
    $userId = $_POST['user_id'] ?? null;
    $eventId = $_POST['event_id'] ?? null;

    if ($userId && is_numeric($userId) && $eventId && is_numeric($eventId)) {
        if (unregisterFromEvent($userId, $eventId)) {
            $_SESSION['message'] = "Participant désinscrit avec succès !";
        } else {
            $_SESSION['message'] = "Erreur lors de la désinscription du participant.";
        }
    } else {
        $_SESSION['message'] = "Données de désinscription invalides.";
    }
    header('Location: /manage_registrations.php'); // Redirige pour éviter la soumission multiple
    exit();
}

$pageTitle = "Gestion des Inscriptions";
include '/api/admin/header.php';

$events = getAllEventsWithRegistrationCount();
?>

<h1 class="text-4xl font-extrabold text-gray-900 mb-12 text-center">Gestion des Inscriptions</h1>

<?php if (empty($events)): ?>
    <p class="text-center text-gray-600 text-lg">Aucun événement n'est disponible pour gérer les inscriptions.</p>
<?php else: ?>
    <div class="grid grid-cols-1 2xl:grid-cols-2 gap-10">
        <?php foreach ($events as $event): ?>
            <div class="max-w-4xl w-full bg-white rounded-lg shadow-lg p-4 md:p-6 mx-auto" data-aos="fade-up">
                <h2 class=" text-2xl font-bold text-gray-900 mb-4">
                    <?php echo htmlspecialchars($event['title']); ?> <!-- Évènement -->
                    <span class="text-gray-500 text-base">(<?php echo htmlspecialchars($event['registered_count']); ?> inscrits)</span>
                </h2>
                <img src="/<?php echo ltrim(htmlspecialchars($event['image_url']), '/'); ?>" alt=" Image de l'événement" class="w-full h-48 object-cover rounded-t-lg">

                <?php
                $participants = getParticipantsForEvent($event['id']);
                if (empty($participants)): ?>
                    <p class="text-gray-600">Aucun participant inscrit à cet événement pour le moment.</p>
                <?php else: ?>
                    <div class="overflow-x-auto">
                        <table class="min-w-full divide-y divide-gray-200">
                            <thead class="bg-gray-50">
                                <tr>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Nom d'utilisateur</th>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date d'inscription</th>
                                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                                </tr>
                            </thead>
                            <tbody class="bg-white divide-y divide-gray-200">
                                <?php foreach ($participants as $participant): ?>
                                    <tr>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900"><?php echo htmlspecialchars($participant['username']); ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo htmlspecialchars($participant['email']); ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo date('d/m/Y H:i', strtotime($participant['registered_at'])); ?></td>
                                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                                            <form action="manage_registrations.php" method="POST" class="inline-block" onsubmit="return confirm('Êtes-vous sûr de vouloir désinscrire <?php echo htmlspecialchars($participant['username']); ?> de cet événement ?');">
                                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($participant['user_id']); ?>">
                                                <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                                                <button type="submit" name="unregister_participant" class="text-red-600 hover:text-red-900  border-1 rounded-full bg-white hover:bg-amber-50 px-2.5 pb-1 pt-0.5 shadow-lg h-7">Désinscrire</button>
                                            </form>
                                        </td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<div class="mt-10">
    <a href="/api/admin/index.php" class="px-5 py-2 rounded-full text-base text-[#FFF] hover:text-gray-800 font-medium transition-colors border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-[#FFF] hover:border-gray-800 cursor-pointer duration-300 ease-in-out">Retour</a>
</div>

<?php include '/api/admin/footer.php'; ?>