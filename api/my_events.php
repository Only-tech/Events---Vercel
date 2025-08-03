<?php

require_once(__DIR__ . '/db_connect.php');
require_once(__DIR__ . '/auth_functions.php');
require_once(__DIR__ . '/event_functions.php');

// Redirige si non connecté
if (!isUserLoggedIn()) {
    $_SESSION['message'] = "Vous devez être connecté pour voir vos inscriptions.";
    header('Location: /api/login.php');
    exit();
}

$pageTitle = "Mes Inscriptions";
include(__DIR__ . '/header.php');

$userId = $_SESSION['user_id'];

// Fonction pour récupérer les événements inscrits par l'utilisateur
function getRegisteredEventsForUser($userId)
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
                r.registered_at
            FROM
                events e
            JOIN
                registrations r ON e.id = r.event_id
            WHERE
                r.user_id = :user_id
            ORDER BY
                e.event_date ASC
        ");
        $stmt->execute(['user_id' => $userId]);
        return $stmt->fetchAll();
    } catch (PDOException $e) {
        error_log("Erreur lors de la récupération des événements inscrits : " . $e->getMessage());
        return [];
    }
}

$myEvents = getRegisteredEventsForUser($userId);
?>

<h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">Mes Inscriptions</h1>

<?php if (empty($myEvents)): ?>
    <p class="text-center text-gray-600 text-lg">Vous n'êtes inscrit à aucun événement pour le moment.</p>
    <div class="text-center mt-4">
        <a href="/" class="inline-block px-5 py-2 rounded-full text-base font-medium transition-colors group border-[0.5px] shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-[#F0EEE5] hover:bg-[#E8E5D8] hover:border-transparent duration-300 ease-in-out">
            Découvrir des événements<!-- -->&nbsp;<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 256 256" class="inline-block -translate-y-0.5 group-hover:animate-bounce">
                <path d="M205.66,149.66l-72,72a8,8,0,0,1-11.32,0l-72-72a8,8,0,0,1,11.32-11.32L120,196.69V40a8,8,0,0,1,16,0V196.69l58.34-58.35a8,8,0,0,1,11.32,11.32Z"></path>
            </svg>
        </a>
    </div>
<?php else: ?>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        <?php foreach ($myEvents as $event): ?>
            <div class="bg-[rgb(248,248,236)] rounded-lg shadow-lg overflow-hidden flex flex-col">
                <div class="p-6 flex-grow flex flex-col">
                    <h2 class="text-2xl font-bold text-gray-900 mb-2"><?php echo htmlspecialchars($event['title']); ?></h2>
                    <p class="text-gray-600 text-sm mb-2">
                        <i class="fas fa-calendar-alt mr-1"></i> <?php echo date('d/m/Y H:i', strtotime($event['event_date'])); ?> GMT+2
                    </p>
                    <p class="text-gray-600 text-sm mb-4">
                        <i class="fas fa-map-marker-alt mr-1"></i> <?php echo htmlspecialchars($event['location']); ?>
                    </p>
                    <p class="text-gray-700 mb-4 flex-grow"><?php echo htmlspecialchars($event['description_short']); ?></p>
                    <p class="text-sm text-gray-500 mb-4">Inscrit le <?php echo date('d/m/Y H:i', strtotime($event['registered_at'])); ?></p>
                    <div class="mt-auto flex flex-wrap justify-evenly items-center gap-3">
                        <a href="event_detail.php?id=<?php echo htmlspecialchars($event['id']); ?>" class="inline-block px-5 py-2 rounded-full text-base font-medium transition-colors group border-[0.5px] shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-[#F0EEE5] hover:bg-[#E8E5D8] hover:border-transparent duration-300 ease-in-out">
                            En savoir plus<!-- -->&nbsp;<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 256 256" class="inline-block -translate-y-0.5 group-hover:animate-bounce">
                                <path d="M205.66,149.66l-72,72a8,8,0,0,1-11.32,0l-72-72a8,8,0,0,1,11.32-11.32L120,196.69V40a8,8,0,0,1,16,0V196.69l58.34-58.35a8,8,0,0,1,11.32,11.32Z"></path>
                            </svg>
                        </a>
                        <form action="unregister_event.php" method="POST" onsubmit="return confirm('Êtes-vous sûr de vouloir annuler votre inscription à cet événement ?');">
                            <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                            <button type="submit" class="px-5 py-2 rounded-full text-base text-[#FFF] hover:text-[#ff952aff] font-medium transition-colors group border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-[#FFF] hover:border-[#ff952aff] cursor-pointer duration-300 ease-in-out">Se désinscrire</button>
                        </form>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<div class="mt-10">
    <a href="/" class="px-5 py-2 rounded-full text-base text-[#FFF] hover:text-[#ff952aff] font-medium transition-colors border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-[#FFF] hover:border-[#ff952aff] cursor-pointer duration-300 ease-in-out">Retour</a>
</div>


<?php include(__DIR__ . '/footer.php'); ?>