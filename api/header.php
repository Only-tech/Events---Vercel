<?php

if (session_status() == PHP_SESSION_NONE) {
    session_start();
}
?>
<!DOCTYPE html>
<html lang="fr">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $pageTitle ?? 'Gestion d\'Événements'; ?></title>
    <link href="../public/styles/styles.css" rel="stylesheet">
    <!-- <link href="../public/styles/output.css" rel="stylesheet"> -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.0/css/all.min.css" integrity="sha512-..." crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link href="https://unpkg.com/aos@2.3.4/dist/aos.css" rel="stylesheet">
    <link rel="icon" type="image/svg+xml" href="../public/images/SplashPaintYellow.svg">
</head>

<body class="min-h-screen w-full flex flex-col text-[#333] bg-[#f5f5dc] font-['Inter', sans-serif]"
    style="background-image: url('../public/images/SplashPaintOrange.svg'); background-repeat: no-repeat; background-position: center; background-size: cover; background-attachment: fixed;">
    <header class="fixed top-0 z-10000 bg-[#f5f5dc] text-gray-900 shadow-lg transition-opacity duration-500 px-[5%] py-2 w-full">
        <nav class="flex sm:flex-row justify-between items-center bg-inherit [@media(max-width:730px)]:flex-wrap gap-2">
            <a href="/" class="[@media(max-width:730px)]:order-1 [@media(max-width:400px)]:[] relative text-lg font-semibold mb-2 md:mb-0 w-[75px] h-[75px] flex items-center justify-center overflow-hidden group">
                <span class="relative z-10 hover:text-[#ff952aff] bg-[#f5f5dc] transition-colors duration-300 ease-in-out cursor-pointer">eventribe</span>
                <div class="absolute inset-0 w-full h-[80px] bg-[url('../public/images/SplashPaintCom.svg')] group-hover:bg-[url('../public/images/SplashPaintOrange.svg')] bg-no-repeat bg-center bg-contain opacity-80 animate-pulse"></div>
            </a>

            <div class="relative flex-grow mx-4 max-w-lg [@media(max-width:730px)]:order-3">
                <form action="/api/index.php" method="GET" class="group flex items-center">
                    <div class="group w-full flex flex-row rounded-full border border-gray-300 transition duration-300 hover:border-[#ff952aff] group-focus:ring-[#ff952aff] group-focus-within:border-[#ff952aff] overflow-hidden">
                        <input type="text" name="search" placeholder="Rechercher un événement..."
                            class="w-full px-4 py-2 border-none border-transparent outline-none text-sm"
                            value="<?php echo htmlspecialchars($_GET['search'] ?? ''); ?>">
                        <?php if (isset($_GET['search']) && $_GET['search'] !== ''): ?>
                            <a href="/api/index.php" class="p-1 flex items-center justify-center " title="Effacer la recherche"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
                                    viewBox="0 0 256 256" class="inline-block rotate-135 animate-pulse">
                                    <path d="M136 120h56a8 8 0 0 1 0 16h-56v56a8 8 0 0 1-16 0v-56H64a8 8 0 0 1 0-16h56V64a8 8 0 0 1 16 0v56z" />
                                </svg></a>
                        <?php endif; ?>
                    </div>
                    <button type="submit" class="ml-2 p-2 rounded-full bg-[#ff952aff] text-white hover:bg-[#111827] transition-colors duration-300" data-title="Rechercher">
                        <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" class="lucide lucide-search">
                            <circle cx="11" cy="11" r="8" />
                            <path d="m21 21-4.3-4.3" />
                        </svg>
                    </button>
                </form>
            </div>

            <ul class="mobile-menu flex gap-8 text-lg font-medium bg-inherit [@media(max-width:840px)]:[display:none] [@media(max-width:730px)]:order-2">
                <li>
                    <a href="/" class=" transition-colors group duration-300" data-title="Accueil">
                        <svg width="25" height="25" viewBox="-4 -4 108 108" xmlns="http://www.w3.org/2000/svg">
                            <path d="M 50 5  L 91.1 36.93  Q 95 40 95 45  L 95 95  C 95 97.7614 92.7614 100 90 100  L 69 100  Q 64 100 64 95  L 64 65  Q 64 60 59 60  L 41 60  Q 36 60 36 65  L 36 95  Q 36 100 31 100  L 10 100  C 7.23858 100 5 97.7614 5 95  L 5 45  Q 5 40 8.9 36.93  L 50 5 Z
                        " fill="none" stroke="#111827" stroke-width="8" class="group-hover:stroke-[#ff952aff]" />
                        </svg>
                    </a>
                </li>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <li><a href="my_events.php" class="hover:text-[#ff952aff] transition duration-300">Mes Inscriptions</a></li>
                    <?php if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']): ?>
                        <li>
                            <a href="/api/admin/index.php" class="relative group" data-title="Aller à l'Administration">
                                <img class="relative z-100 inset-0 w-7.5 h-7.5 animate-bounce transition-opacity duration-300 group-hover:opacity-0" src="../public/images/adminGray-logo.svg" />
                                <img class="absolute z-10 inset-0 w-7.5 h-7.5 opacity-0 group-hover:opacity-100 transition-opacity duration-300 group-hover:scale-110" src="../public/images/adminOrange-logo.svg" />
                            </a>
                        </li>
                    <?php endif; ?>
                    <li>
                        <a href="/api/logout.php" class="flex flex-row items-center gap-2 hover:text-[#ff952aff] transition duration-300" data-title="Déconnexion">
                            <span>(<?php echo htmlspecialchars($_SESSION['username']); ?>)</span>
                            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" width="25" height="25" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <path d="M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h5"></path>
                                <polyline points="16 17 21 12 16 7"></polyline>
                                <line x1="21" y1="12" x2="9" y2="12"></line>
                            </svg>
                        </a>
                    </li>
                <?php else: ?>
                    <li><a href="/api/login.php" class="hover:text-[#ff952aff] transition duration-300">Connexion</a></li>
                    <li><a href="/api/register.php" class="hover:text-[#ff952aff] transition duration-300">Inscription</a></li>
                <?php endif; ?>
            </ul>
            <button id="burgerBtn" class="flex justify-end text-4xl [@media(min-width:840px)]:[display:none] [@media(min-width:439px)]:order-3 [@media(max-width:438px)]:order-2" data-title="Menu">☰</button>
        </nav>
    </header>

    <main class="flex-grow max-w-[95%] w-full py-30 mx-auto">
        <?php
        // Affiche les messages de session (succès/erreur)
        if (isset($_SESSION['message'])): ?>
            <div class="p-4 mb-4 rounded-lg <?php echo strpos($_SESSION['message'], 'réussie') !== false || strpos($_SESSION['message'], 'succès') !== false ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'; ?>" role="alert">
                <?php echo htmlspecialchars($_SESSION['message']); ?>
            </div>
        <?php unset($_SESSION['message']); // Supprime le message après l'affichage
        endif;
        ?>

        <!-- ---------------scroll top button------------------ -->
        <button id="scrollTopBtn" data-title="Retour en Haut" class="group">
            <svg width="1.7em" height="1.7em" viewBox="34 -7.5 80 80" xmlns="http://www.w3.org/2000/svg">
                <path d="M 38 24 L 38 36 L 74 15 L 110 36 L 110 24 L 74 2 L 38 24 Z" fill="#ff952aff" class="group-hover:fill-[#111827]" />
                <path d="M 46 53 L 46 63 L 74 45 L 102 63 L 102 53 L 74 33 L 46 53 Z" fill="#111827" class="group-hover:fill-[#ff952aff]" />
            </svg>
        </button>