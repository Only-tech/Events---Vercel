<?php

require_once(__DIR__ . '/db_connect.php');
require_once(__DIR__ . '/event_functions.php');
require_once(__DIR__ . '/auth_functions.php');

$eventId = $_GET['id'] ?? null;

if (!$eventId || !is_numeric($eventId)) {
    $_SESSION['message'] = "ID d'événement invalide.";
    header('Location: /');
    exit();
}

$event = getEventById($eventId);

if (!$event) {
    $_SESSION['message'] = "Événement introuvable.";
    header('Location: /');
    exit();
}

$pageTitle = htmlspecialchars($event['title']);
include(__DIR__ . '/header.php');

$isLoggedIn = isUserLoggedIn();
$isRegistered = false;
if ($isLoggedIn) {
    $isRegistered = isUserRegisteredForEvent($_SESSION['user_id'], $eventId);
}

// Calcule les places restantes
$registeredCount = count(getParticipantsForEvent($eventId));
$remainingSeats = $event['available_seats'] - $registeredCount;
?>

<div class="p-3 bg-[rgb(248,248,236)] rounded-lg shadow-lg md:p-8 xl:max-w-7xl mx-auto items-center">
    <h1 class="text-4xl font-extrabold text-gray-900 mb-4"><?php echo htmlspecialchars($event['title']); ?></h1>

    <?php if (!empty($event['image_url'])): ?>
        <img src="<?php echo htmlspecialchars($event['image_url']); ?>" alt="Image de l'événement <?php echo htmlspecialchars($event['title']); ?>" class="w-full h-96 object-cover rounded-lg mb-6" onerror="this.onerror=null;this.src='https://placehold.co/1200x400/E0E0E0/333333?text=Image+non+disponible';">
    <?php else: ?>
        <div class="w-full h-96 bg-gray-200 flex items-center justify-center text-gray-500 text-2xl rounded-lg mb-6">
            [Image de l'événement non disponible]
        </div>
    <?php endif; ?>

    <div class="flex flex-col md:flex-row gap-6 mb-6">

        <div class="min-w-[330px] xl:min-w-[380px]">
            <p class="text-gray-700 text-lg mb-2">
                <i class="fas fa-calendar-alt mr-1"></i> <?php echo date('d/m/Y H:i', strtotime($event['event_date'])); ?> GMT+2
            </p>
            <p class="text-gray-700 text-lg mb-2">
                <i class="fas fa-map-marker-alt mr-1"></i> <?php echo htmlspecialchars($event['location']); ?>
            </p>
            <p class="text-gray-700 text-lg mb-2">
                <strong class="text-gray-900">Places disponibles :</strong> <?php echo htmlspecialchars($remainingSeats); ?>
            </p>
        </div>
        <div>
            <p class="text-gray-700 leading-relaxed"><?php echo nl2br(htmlspecialchars($event['description_long'])); ?></p>
        </div>
    </div>

    <div class="mt-8 flex justify-center">
        <?php if ($isLoggedIn): ?>
            <?php if ($isRegistered): ?>
                <form action="unregister_event.php" method="POST">
                    <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                    <button type="submit" class="px-5 py-2 rounded-full text-base text-[#FFF] hover:text-[#ff952aff] font-medium transition-colors group border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-[#FFF] hover:border-[#ff952aff] cursor-pointer duration-300 ease-in-out">Se désinscrire</button>
                </form>
            <?php elseif ($remainingSeats > 0): ?>
                <form action="register_event.php" method="POST">
                    <input type="hidden" name="event_id" value="<?php echo htmlspecialchars($event['id']); ?>">
                    <button type="submit" class="px-5 py-2 rounded-full text-base font-medium transition-colors group border-[0.5px] shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-[#F0EEE5] hover:bg-[#E8E5D8] hover:border-transparent duration-300 ease-in-out cursor-pointer">
                        S'inscrire<!-- -->&nbsp;<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
                            viewBox="0 0 256 256" class="inline-block -translate-y-0.5 group-hover:animate-bounce">
                            <path d="M136 120h56a8 8 0 0 1 0 16h-56v56a8 8 0 0 1-16 0v-56H64a8 8 0 0 1 0-16h56V64a8 8 0 0 1 16 0v56z" />
                        </svg>
                    </button>
                </form>
            <?php else: ?>
                <p class="text-red-600 font-bold text-lg">Complet !</p>
            <?php endif; ?>
        <?php else: ?>
            <p class="text-gray-600">
                <a href="login.php" class="text-indigo-600 hover:underline">Connectez-vous</a> pour vous inscrire à cet événement.
            </p>
        <?php endif; ?>
    </div>
</div>

<a href="/" class="mt-10 px-5 py-2 rounded-full text-base text-[#FFF] hover:text-[#ff952aff] font-medium transition-colors group border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-[#FFF] hover:border-[#ff952aff] cursor-pointer duration-300 ease-in-out">Retour</a>

<?php include(__DIR__ . '/footer.php'); ?>