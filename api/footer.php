<?php
?>
</main>

<footer class="bg-[#f5f5dc] pt-10 pb-2 w-full">

    <div class="flex flex-wrap gap-20 justify-between pb-10 w-full max-w-[95%] px-3">
        <div class="max-w-md  [@media(max-width:449px)]:max-w-[300px] text-justify  [@media(max-width:849px)]:order-3  [@media(max-width:849px)]:justify-center mx-auto">
            <h3 class="text-2xl font-bold mb-6">À propos de nous</h3>
            <p>
                Eventribe connecte organisateurs et passionnés à travers des rencontres humaines et projets culturels.
                Que vous soyez artiste, pro ou curieux, la plateforme vous accompagne : création d’événements, inscriptions, suivi et bien plus encore.
                Notre mantra : accessibilité, créativité, fluidité. <br>Rejoignez la tribu et donnez vie à vos idées !
            </p>
        </div>
        <div class=" [@media(max-width:849px)]:order-1  [@media(max-width:849px)]:justify-center mx-auto">
            <h3 class="text-2xl font-bold mb-6">Navigation</h3>
            <ul class="flex flex-col space-x-4 text-lg font-medium">
                <li><a href="/" class="hover:text-[#ff952aff] transition duration-300">Accueil</a></li>
                <?php if (isset($_SESSION['user_id'])): ?>
                    <li><a href="/my_events.php" class="hover:text-[#ff952aff] transition duration-300">Mes Inscriptions</a></li>
                    <?php if (isset($_SESSION['is_admin']) && $_SESSION['is_admin']): ?>
                        <li><a href="/api/admin/index.php" class="hover:text-[#ff952aff] transition duration-300">Administration</a></li>
                    <?php endif; ?>
                    <li><a href="/api/logout.php" class="hover:text-[#ff952aff] transition duration-300">Déconnexion (<?php echo htmlspecialchars($_SESSION['username']); ?>)</a></li>
                <?php else: ?>
                    <li><a href="/api/login.php" class="hover:text-[#ff952aff] transition duration-300">Connexion</a></li>
                    <li><a href="/api/register.php" class="hover:text-[#ff952aff] transition duration-300">Inscription</a></li>
                <?php endif; ?>
                <li><a href="/api/legal_mentions.php" class="hover:text-[#ff952aff] transition duration-300">Mentions Légales</a></li>
                <li><a href="/api/legal_mentions.php#politique-confidentialite" class="hover:text-[#ff952aff] transition duration-300">Politique de Confidentialité</a></li>
            </ul>
        </div>
        <div class=" [@media(max-width:849px)]:order-2  [@media(max-width:849px)]:justify-center mx-auto">
            <div class="mb-6">
                <h3 class="text-2xl font-bold mb-6">Nos partenaires</h3>
                <div class="flex gap-10">
                    <ul class="flex flex-col space-x-4 text-lg font-medium">
                        <li><a href="/" class="hover:text-[#ff952aff] transition duration-300">Cultura</a></li>
                        <li><a href="/" class="hover:text-[#ff952aff] transition duration-300">Eventura</a></li>
                        <li><a href="/" class="hover:text-[#ff952aff] transition duration-300">Futuremploi</a></li>
                    </ul>
                    <ul class="flex flex-col space-x-4 text-lg font-medium">
                        <li><a href="/" class="hover:text-[#ff952aff] transition duration-300">RobboTech</a></li>
                        <li><a href="/" class="hover:text-[#ff952aff] transition duration-300">Educom</a></li>
                        <li><a href="/" class="hover:text-[#ff952aff] transition duration-300">Socialista</a></li>
                    </ul>
                </div>
            </div>
            <!-- Bouton contact -->
            <button onclick="document.getElementById('contactModal').classList.remove('hidden')"
                class="fixed z-1000 bottom-0 left-10 bg-[#ff952aff] text-xl font-semibold px-8 py-2 rounded-t-full text-gray-900 hover:text-[#ff952aff] transition-colors group border-0 shadow-sm shadow-[hsl(var(--always-black)/5.1%)] hover:bg-gray-900 cursor-pointer duration-300 ease-in-out">
                Contactez-nous
            </button>

            <!-- Modale -->
            <div id="contactModal" class="fixed w-full inset-0 bg-black/50 flex items-center justify-center z-50 hidden">
                <div class="bg-[rgb(248,248,236)] rounded-lg shadow-lg p-6 w-full max-w-md relative group">
                    <button onclick="document.getElementById('contactModal').classList.add('hidden')" class="top-[-1rem] left-[100%] text-gray-500 hover:text-[#ff952aff] text-2xl font-bold hover:animate-pulse transform duration-300 ease-in-out" data-title="Quitter">&times;</button>
                    <h2 class="text-xl text-gray-900 text-center font-semibold mb-4 mt-[-2.5rem]">Contactez-nous</h2>
                    <form id="contact-form" class="grid gap-4">
                        <input type="text" name="name" placeholder="Votre nom | Votre organisation" class="w-[260px] border p-2  border-gray-300 rounded-full shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff]" required>
                        <textarea name="message" rows="4" placeholder="Votre message" class="border p-2 resize-none  border-gray-300 rounded-md shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff] w-full" required></textarea>
                        <div class="flex gap-4 justify-end [@media(max-width:449px)]:flex-col">
                            <input type="email" name="email" placeholder="Votre email" class="border p-2 border-gray-300 rounded-full shadow-sm focus:outline-none focus:ring-[#ff952aff] focus:border-[#ff952aff]" required>
                            <button type="submit" class="px-5 py-2 rounded-full text-base font-medium transition-colors group border-[0.5px] shadow-sm shadow-[hsl(var(--always-black)/5.1%)] bg-[#F0EEE5] hover:bg-[#E8E5D8] hover:border-transparent duration-300 ease-in-out cursor-pointer">
                                Envoyer<!-- -->&nbsp;<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" viewBox="0 0 256 256" class="inline-block -translate-y-0.5 group-hover:animate-bounce">
                                    <path d="M205.66,149.66l-72,72a8,8,0,0,1-11.32,0l-72-72a8,8,0,0,1,11.32-11.32L120,196.69V40a8,8,0,0,1,16,0V196.69l58.34-58.35a8,8,0,0,1,11.32,11.32Z"></path>
                                </svg>
                            </button>
                        </div>
                        <div class="items-center flex flex-col">
                            <div id="loading-spinner" class="hidden mt-4">
                                <svg width="40" height="40" viewBox="0 0 50 50">
                                    <circle cx="25" cy="25" r="20" stroke="#ff952aff" stroke-width="5" fill="none" stroke-linecap="round" stroke-dasharray="30 70">
                                        <animateTransform
                                            attributeName="transform"
                                            type="rotate"
                                            repeatCount="indefinite"
                                            dur="1s"
                                            from="0 25 25"
                                            to="360 25 25" />
                                    </circle>
                                </svg>
                            </div>
                            <p id="form-status" class="w-full text-center border-0 mt-4 p-4 rounded-lg"></p>
                        </div>
                    </form>
                </div>
            </div>

            <div class="relative justify-center items-center mx-auto w-[150px] h-[150px]">
                <a href="/" class="relative text-2xl font-semibold mb-2 md:mb-0 w-[100px] h-[100px] flex items-center justify-center overflow-hidden group">
                    <span class="relative z-10 hover:text-[#ff952aff] bg-[#f5f5dc] transition-colors duration-300 ease-in-out cursor-pointer">eventribe</span>
                    <div class="absolute inset-0 w-[100px] h-[100px] bg-[url('../public/images/SplashPaintCom.svg')] group-hover:bg-[url('../public/images/SplashPaintOrange.svg')] bg-no-repeat bg-center bg-contain opacity-80 animate-pulse"></div>
                </a>
            </div>
        </div>
    </div>
    <div class="text-center text-sm [@media(max-width:800px)]:mb-10">
        Cédrick &copy; <?php echo date('Y'); ?> eventribe. All rights reserved.
    </div>
</footer>

<script src="../public/scripts/navBar.js"></script>
<script src="https://unpkg.com/aos@2.3.4/dist/aos.js"></script>
<script>
    AOS.init();
</script>
<script src="../public/scripts/onTopButton.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@emailjs/browser@3/dist/email.min.js"></script>
<script src="../public/scripts/Email.js"></script>
</body>

</html>