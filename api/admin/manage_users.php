<?php
require_once(__DIR__ . '/api/admin_guard.php');

require_once(__DIR__ . '/api/db_connect.php');
require_once(__DIR__ . '/api/auth_functions.php');


$pageTitle = "Gestion des Utilisateurs";

// Gère la suppression d'un utilisateur
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_user'])) {
    $userIdToDelete = $_POST['user_id'] ?? null;

    if ($userIdToDelete && is_numeric($userIdToDelete)) {
        // Empêche l'admin de se supprimer lui-même
        if ($userIdToDelete == $_SESSION['user_id']) {
            $_SESSION['message'] = "Vous ne pouvez pas supprimer votre propre compte.";
        } else {
            if (deleteUser($userIdToDelete)) {
                $_SESSION['message'] = "Utilisateur supprimé avec succès !";
            } else {
                $_SESSION['message'] = "Erreur lors de la suppression de l'utilisateur.";
            }
        }
    } else {
        $_SESSION['message'] = "ID utilisateur invalide pour la suppression.";
    }
    header('Location: /manage_users.php'); // Redirige pour éviter la soumission multiple
    exit();
}


// Gère le changement de statut admin
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['toggle_admin_status'])) {
    $userIdToToggle = $_POST['user_id'] ?? null;
    $currentAdminStatus = filter_var($_POST['current_admin_status'] ?? false, FILTER_VALIDATE_BOOLEAN);
    $newAdminStatus = !$currentAdminStatus; // Inverse le statut

    if ($userIdToToggle && is_numeric($userIdToToggle)) {
        // Empêche de retirer le statut admin au seul admin restant et permet aussi la modification.
        if (updateUserAdminStatus($userIdToToggle, $newAdminStatus)) {
            $_SESSION['message'] = "Statut administrateur mis à jour avec succès !";
        } else {
            $_SESSION['message'] = "Erreur lors de la mise à jour du statut administrateur.";
        }
    } else {
        $_SESSION['message'] = "ID utilisateur invalide pour la mise à jour du statut.";
    }
    header('Location: /manage_users.php');
    exit();
}

include '/admin/header.php'; // header spécifique à l'admin

$users = getAllUsers();
?>

<h1 class="text-4xl font-extrabold text-gray-900 mb-8 text-center">Gestion des Utilisateurs</h1>

<?php if (empty($users)): ?>
    <p class="text-center text-gray-600 text-lg">Aucun utilisateur enregistré pour le moment.</p>
<?php else: ?>
    <div class="bg-white rounded-lg shadow-lg overflow-hidden">
        <table class="min-w-full divide-y divide-gray-200">
            <thead class="bg-gray-50">
                <tr>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">ID</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Nom d'utilisateur</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Admin</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Date d'inscription</th>
                    <th scope="col" class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
                </tr>
            </thead>
            <tbody class="bg-white divide-y divide-gray-200">
                <?php foreach ($users as $user): ?>
                    <tr>
                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900"><?php echo htmlspecialchars($user['id']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo htmlspecialchars($user['username']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo htmlspecialchars($user['email']); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                            <form action="manage_users.php" method="POST" class="inline-block">
                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                <input type="hidden" name="current_admin_status" value="<?php echo $user['is_admin'] ? 'true' : 'false'; ?>">
                                <button type="submit" name="toggle_admin_status" class="px-2 py-1 rounded-full text-xs font-semibold <?php echo $user['is_admin'] ? 'bg-green-100 text-green-800 hover:bg-green-200' : 'bg-gray-100 text-gray-800 hover:bg-gray-200'; ?>">
                                    <?php echo $user['is_admin'] ? 'Oui' : 'Non'; ?>
                                </button>
                            </form>
                        </td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500"><?php echo date('d/m/Y H:i', strtotime($user['created_at'])); ?></td>
                        <td class="px-6 py-4 whitespace-nowrap text-sm font-medium">
                            <form action="manage_users.php" method="POST" class="inline-block" onsubmit="return confirm('Êtes-vous sûr de vouloir supprimer l\'utilisateur <?php echo htmlspecialchars($user['username']); ?> ?');">
                                <input type="hidden" name="user_id" value="<?php echo htmlspecialchars($user['id']); ?>">
                                <button type="submit" name="delete_user" class="text-red-600 hover:text-red-900  border-1 rounded-full bg-white hover:bg-amber-50 px-2.5 pb-1 pt-0.5 shadow-lg h-7">Supprimer</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
            </tbody>
        </table>
    </div>
<?php endif; ?>

<div class="mt-10">
    <a href="/admin/index.php" class="px-5 py-2 rounded-full text-base text-[#FFF] hover:text-gray-800 font-medium transition-colors border-[0.5px] border-transparent shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-gray-800 hover:bg-[#FFF] hover:border-gray-800 cursor-pointer duration-300 ease-in-out">Retour</a>
</div>

<?php include '/admin/footer.php'; ?>