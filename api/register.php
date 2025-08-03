<?php

require_once(__DIR__ . '/db_connect.php');
require_once(__DIR__ . '/auth_functions.php');


if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    if (empty($username) || empty($email) || empty($password) || empty($confirm_password)) {
        $_SESSION['message'] = "Veuillez remplir tous les champs.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $_SESSION['message'] = "Format d'email invalide.";
    } elseif ($password !== $confirm_password) {
        $_SESSION['message'] = "Les mots de passe ne correspondent pas.";
    } elseif (strlen($password) < 6) {
        $_SESSION['message'] = "Le mot de passe doit contenir au moins 6 caractères.";
    } else {
        if (registerUser($username, $email, $password)) {
            header('Location: /api/login.php'); // Redirige vers la page de connexion après inscription réussie
            exit();
        }
        // Le message d'erreur est déjà défini dans registerUser()
    }
    header('Location: /api/register.php'); // Redirige pour afficher le message
    exit();
}

$pageTitle = "Inscription";
include(__DIR__ . '/header.php');
?>

<div class="max-w-md mx-auto bg-[rgb(248,248,236)] p-8 rounded-lg shadow-lg">
    <h1 class="text-3xl font-bold text-gray-900 mb-6 text-center">Inscription</h1>
    <?php if (!empty($_SESSION['message'])): ?>
        <div class="mb-4 text-red-600 text-center font-semibold">
            <?php echo htmlspecialchars($_SESSION['message']); ?>
            <?php unset($_SESSION['message']); ?>
        </div>
    <?php endif; ?>

    <form action="register.php" method="POST">
        <div class="mb-4">
            <label for="username" class="block text-sm font-medium text-gray-700">Nom d'utilisateur :</label>
            <input type="text" id="username" name="username" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff] sm:text-sm" required>
        </div>
        <div class="mb-4">
            <label for="email" class="block text-sm font-medium text-gray-700">Email :</label>
            <input type="email" id="email" name="email" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff] sm:text-sm" required>
        </div>
        <div class="mb-4">
            <label for="password" class="block text-sm font-medium text-gray-700">Mot de passe :</label>
            <input type="password" id="password" name="password" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff] sm:text-sm" required>
        </div>
        <div class="mb-6">
            <label for="confirm_password" class="block text-sm font-medium text-gray-700">Confirmer le mot de passe :</label>
            <input type="password" id="confirm_password" name="confirm_password" class="mt-1 block w-full px-3 py-2 border border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff] sm:text-sm" required>
        </div>
        <button type="submit" class="px-5 py-2 rounded-full text-base font-medium transition-colors group border-[0.5px] shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-[#F0EEE5] hover:bg-[#E8E5D8] hover:border-transparent duration-300 ease-in-out cursor-pointer w-full">
            S'inscrire<!-- -->&nbsp;<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor"
                viewBox="0 0 256 256" class="inline-block -translate-y-0.5 group-hover:animate-bounce">
                <path d="M136 120h56a8 8 0 0 1 0 16h-56v56a8 8 0 0 1-16 0v-56H64a8 8 0 0 1 0-16h56V64a8 8 0 0 1 16 0v56z" />
            </svg>
        </button>
    </form>
    <p class="mt-6 text-center text-gray-600">
        Déjà un compte ? <a href="login.php" class="text-indigo-600 hover:underline">Connectez-vous ici</a>.
    </p>
</div>

<?php include(__DIR__ . '/footer.php'); ?>