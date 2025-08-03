<?php

require_once __DIR__ . '/db_connect.php';
require_once(__DIR__ . '/auth_functions.php');


if (isUserLoggedIn()) {
    header('Location: /'); // Redirige si déjà connecté
    exit();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (empty($email) || empty($password)) {
        $_SESSION['message'] = "Veuillez remplir tous les champs.";
    } else {
        if (loginUser($email, $password)) {
            header('Location: /'); // Redirige vers la page d'accueil après connexion réussie
            exit();
        }
        // Le message d'erreur est déjà défini dans loginUser()
    }
    header('Location: /api/login.php'); // Redirige pour afficher le message
    exit();
}

$pageTitle = "Connexion";
include(__DIR__ . '/header.php');
?>

<div class="max-w-md mx-auto bg-[rgb(248,248,236)] p-8 rounded-lg shadow-lg">
    <h1 class="text-3xl font-bold text-gray-900 mb-6 text-center">Connexion</h1>
    <form action="login.php" method="POST">
        <div class="mb-4">
            <label for="email" class="block text-sm font-medium text-gray-700">Email :</label>
            <input type="email" id="email" name="email" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff] sm:text-sm" required>
        </div>
        <div class="mb-6">
            <label for="password" class="block text-sm font-medium text-gray-700">Mot de passe :</label>
            <input type="password" id="password" name="password" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff] sm:text-sm" required>
        </div>
        <button type="submit" class="w-full px-5 py-2 rounded-full text-base font-medium transition-colors border-[0.5px] shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-[#F0EEE5] hover:bg-[#E8E5D8] hover:border-transparent duration-300 ease-in-out cursor-pointer">Se connecter</button>
    </form>
    <p class="mt-6 text-center text-gray-600">
        Pas encore de compte ? <a href="register.php" class="text-indigo-600 hover:underline">Inscrivez-vous ici</a>.
    </p>
</div>

<?php include(__DIR__ . '/footer.php'); ?>