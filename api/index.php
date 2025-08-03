<?php

require_once(__DIR__ . '/db_connect.php');
require_once(__DIR__ . '/event_functions.php');
require_once(__DIR__ . '/auth_functions.php'); // Pour isUserLoggedIn() et isUserAdmin()

$pageTitle = "eventribe - Événements à venir";
include(__DIR__ . '/header.php');

$searchTerm = $_GET['search'] ?? '';

if (!empty($searchTerm)) {
    $events = searchEvents($searchTerm);
} else {
    $events = getAllEventsWithRegistrationCount();
}
?>

<h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center [@media(max-width:438px)]:mt-8">
    <?php echo !empty($searchTerm) ? 'Résultats de recherche pour "' . htmlspecialchars($searchTerm) . '"' : 'Découvrez les événements à venir'; ?>
</h1>

<?php if (empty($events)): ?>
    <p class="text-center text-gray-600 text-lg">Aucun événement n'est disponible pour le moment. Revenez plus tard !</p>
<?php else: ?>
    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        <?php foreach ($events as $event): ?>
            <div class="bg-[rgb(248,248,236)] rounded-lg shadow-lg overflow-hidden flex flex-col group hover:shadow-2xl" data-aos="fade-up">
                <div class="w-full h-48 overflow-hidden xl:h-80">
                    <?php if (!empty($event['image_url'])): ?>
                        <img src=" <?php echo htmlspecialchars($event['image_url']); ?>" alt="Image de l'événement <?php echo htmlspecialchars($event['title']); ?>" class="w-full h-48 xl:h-80 object-cover rounded-t-lg group-hover:scale-110 transition duration-500 ease-in-out group-hover:rotate-1" onerror="this.onerror=null;this.src='https://placehold.co/600x400/E0E0E0/333333?text=Image+non+disponible';">
                    <?php else: ?>
                        <div class="w-full h-48 bg-gray-200 flex items-center justify-center text-gray-500 text-lg rounded-t-lg">
                            [Image de l'événement non disponible]
                        </div>
                    <?php endif; ?>
                </div>
                <div class="p-4 md:p-6 flex-grow flex flex-col">
                    <h2 class="text-2xl font-bold text-gray-900 mb-2"><?php echo htmlspecialchars($event['title']); ?></h2>
                    <p class="text-gray-600 text-sm mb-2">
                        <i class="fas fa-calendar-alt mr-1"></i> <?php echo date('d/m/Y H:i', strtotime($event['event_date'])); ?> GMT+2
                    </p>
                    <p class="text-gray-600 text-sm mb-4">
                        <i class="fas fa-map-marker-alt mr-1"></i> <?php echo htmlspecialchars($event['location']); ?>
                    </p>
                    <p class="text-gray-700 mb-4 flex-grow"><?php echo htmlspecialchars($event['description_short']); ?></p>
                    <div class="mt-auto flex flex-row [@media(max-width:449px)]:flex-col  [@media(min-width:768px)]:[@media(max-width:980px)]:flex-col  [@media(min-width:1024px)]:[@media(max-width:1536px)]:flex-col justify-between items-center gap-3">
                        <span class="text-sm text-gray-500">
                            Places disponibles: <?php echo htmlspecialchars($event['available_seats']); ?>
                            (Inscrits: <?php echo htmlspecialchars($event['registered_count']); ?>)
                        </span>
                        <a href="/api/event_detail.php?id=<?php echo htmlspecialchars($event['id']); ?>" class="inline-block px-5 py-2 rounded-full text-base font-medium transition-colors group border-[0.5px] shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-[#F0EEE5] hover:bg-[#E8E5D8] hover:border-transparent">
                            En savoir plus<!-- -->&nbsp;<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 256 256" class="inline-block -translate-y-0.5 group-hover:animate-bounce">
                                <path d="M205.66,149.66l-72,72a8,8,0,0,1-11.32,0l-72-72a8,8,0,0,1,11.32-11.32L120,196.69V40a8,8,0,0,1,16,0V196.69l58.34-58.35a8,8,0,0,1,11.32,11.32Z"></path>
                            </svg>
                        </a>
                    </div>
                </div>
            </div>
        <?php endforeach; ?>
    </div>
<?php endif; ?>

<?php include(__DIR__ . '/footer.php'); ?>