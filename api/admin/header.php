<?php

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}

require_once(__DIR__ . '/api/auth_functions.php');

?>
<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $pageTitle ?? 'Administration'; ?></title>
    <link rel="stylesheet" href="../public/styles/styles.css">
    <!-- <link rel="stylesheet" href="/styles/output.css"> -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" integrity="sha512-..." crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link href="https://unpkg.com/aos@2.3.4/dist/aos.css" rel="stylesheet">
    <link rel="icon" type="image/svg+xml" href="../public/images/adminWhite-logo.svg">
</head>

<body class="min-h-screen w-full flex flex-col text-[#333] bg-[#f4f7f6] font-['Inter', sans-serif] lateralScrollBar"
    style="background-image: url('../public/images/SplashPaint.svg'); background-repeat: no-repeat; background-position: center; background-size: cover; background-attachment: fixed;">
    <header class="fixed flex flex-row justify-between items-center z-10000 w-full bg-gray-900 text-white shadow-lg transition-opacity duration-500 py-4 px-[5%]">
        <a href="/admin/index.php" class="relative w-[55px] h-[55px] group" data-title="Administration">
            <img class="relative z-100 inset-0 w-[50px] h-[50px] animate-bounce transition-opacity duration-300 group-hover:opacity-0" src="../public/images/adminWhite-logo.svg" />
            <img class="absolute z-10 inset-0 w-[50px] h-[50px] opacity-0 group-hover:opacity-65 transition-opacity duration-300 group-hover:scale-110" src="../public/images/adminWhite-logo.svg" />
        </a>
        <nav class="flex flex-row gap-8 items-center bg-gray-900">
            <a href="/admin/index.php" class="text-lg transition-opacity duration-300 hover:opacity-65 whitespace-nowrap">Tableau de bord</a>
            <ul class="mobile-menu flex gap-8 text-lg [@media(max-width:840px)]:[display:none]">
                <li><a href="/admin/manage_events.php" class="relative flex flex-row items-center gap-1 transition-opacity duration-300 hover:opacity-65" data-title="Gérer les Événements">
                        <img class="relative inset-0 w-[20px] h-[20px]" src="../public/images/SetWhite-logo.svg" />
                        <span>Événements</span>
                    </a>
                </li>
                <li><a href="/admin/manage_registrations.php" class="relative flex flex-row items-center gap-1 transition-opacity duration-300 hover:opacity-65" data-title="Gérer les Inscriptions">
                        <img class="relative inset-0 w-[20px] h-[20px]" src="../public/images/SetWhite-logo.svg" />
                        <span>Inscriptions</span>
                    </a>
                </li>
                <li><a href="/admin/manage_users.php" class="relative flex flex-row items-center gap-1 transition-opacity duration-300 hover:opacity-65" data-title="Gérer les Utilisateurs">
                        <img class="relative inset-0 w-[20px] h-[20px]" src="../public/images/SetWhite-logo.svg" />
                        <span>Utilisateurs</span>
                    </a>
                </li>
                <li>
                    <a href="/logout.php" class="flex flex-row items-center gap-2 transition-opacity duration-300 hover:opacity-65" data-title="Déconnexion">
                        <span>(<?php echo htmlspecialchars($_SESSION['username']); ?>)</span>
                        <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="25" height="25" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                            <path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5"></path>
                            <polyline points="16 17 21 12 16 7"></polyline>
                            <line x1="21" y1="12" x2="9" y2="12"></line>
                        </svg>
                    </a>
                </li>
            </ul>
            <button id="burgerBtn" class="flex text-4xl [@media(min-width:840px)]:[display:none]" data-title="Menu">☰</button>
        </nav>
    </header>

    <main class="flex-grow max-w-[95%] xl:max-w-[90%] w-full py-30 mx-auto">
        <?php
        // Affiche les messages de session (succès/erreur)
        if (isset($_SESSION['message'])): ?>
            <div class="p-4 mb-4 rounded-lg <?php echo strpos($_SESSION['message'], 'réussie') !== false || strpos($_SESSION['message'], 'succès') !== false ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>" role="alert">
                <?php echo htmlspecialchars($_SESSION['message']); ?>
            </div>
        <?php unset($_SESSION['message']);
        endif;
        ?>


        <!-- ---------------scroll top button------------------ -->
        <button id="scrollTopBtn" data-title="Retour en Haut" class="group">
            <svg width="1.7em" height="1.7em" viewBox="34 -7.5 80 80" xmlns="http://www.w3.org/2000/svg">
                <path d="M 38 24 L 38 36 L 74 15 L 110 36 L 110 24 L 74 2 L 38 24 Z" fill="#4A90E2" class="group-hover:fill-[#111827]" />
                <path d="M 46 53 L 46 63 L 74 45 L 102 63 L 102 53 L 74 33 L 46 53 Z" fill="#111827" class="group-hover:fill-[#4A90E2]" />
            </svg>
        </button>