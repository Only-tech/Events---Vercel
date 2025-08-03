<?php
require_once(__DIR__ . 'admin_guard.php');

require_once(__DIR__ . '/api/db_connect.php');
require_once(__DIR__ . '/api/auth_functions.php');
require_once(__DIR__ . '/api/event_functions.php');



$pageTitle = "eventribe - Tableau de bord Admin";
include '/api/admin/header.php';

// Les nombres totales d'événements, d'utilisateurs et d'inscriptions
$totalEvents = count(getAllEventsWithRegistrationCount());
$totalUsers = countUsers();
$totalRegistrations = countRegistrations();
function countUsers()
{
    global $pdo;
    $stmt = $pdo->query("SELECT COUNT(*) FROM users");
    return (int) $stmt->fetchColumn();
}
?>


<h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">Tableau de bord Administrateur</h1>

<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 mb-8">
    <div class="bg-white rounded-lg shadow-lg overflow-hidden p-6 text-center">
        <h2 class="text-xl font-semibold text-gray-800 mb-2">Total Événements</h2>
        <p class="text-5xl font-bold text-indigo-600"><?php echo htmlspecialchars($totalEvents); ?></p>
    </div>
    <!-- Cartes de statistiques -->
    <div class="bg-white rounded-lg shadow-lg overflow-hidden p-6 text-center">
        <h2 class="text-xl font-semibold text-gray-800 mb-2">Utilisateurs Enregistrés</h2>
        <p class="text-5xl font-bold text-gray-600"><?php echo htmlspecialchars($totalUsers); ?></p>
    </div>
    <div class="bg-white rounded-lg shadow-lg overflow-hidden p-6 text-center">
        <h2 class="text-xl font-semibold text-gray-800 mb-2">Inscriptions Totales</h2>
        <p class="text-5xl font-bold text-gray-600"><?php echo htmlspecialchars($totalRegistrations); ?></p>
    </div>
</div>

<div class=" bg-white rounded-lg shadow-lg p-6">
    <h2 class="text-2xl font-bold text-gray-900 mb-4">Actions Administrateur</h2>
    <ul class="space-y-4">
        <li>
            <a href=" manage_events.php" class="px-5 py-2 rounded-full text-xl text-[#FFF] hover:text-gray-800 font-medium transition-colors border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-amber-50 hover:border-gray-800 cursor-pointer duration-300 ease-in-out w-full block text-center">
                Gérer les Événements (Créer, Modifier, Supprimer)
            </a>
        </li>
        <li>
            <a href="manage_registrations.php" class="px-5 py-2 rounded-full text-xl text-[#FFF] hover:text-gray-800 font-medium transition-colors border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-amber-50 hover:border-gray-800 cursor-pointer duration-300 ease-in-out w-full block text-center">
                Gérer les Inscriptions (Voir les participants, Désinscrire)
            </a>
        </li>
    </ul>
</div>

<?php include '/api/admin/footer.php'; ?>