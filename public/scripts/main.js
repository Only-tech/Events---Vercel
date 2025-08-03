    // Prévisualisation de l'image à l'upload
    const input = document.getElementById('image');
    const preview = document.getElementById('preview');
    const currentImage = document.getElementById('current-image'); // Ajout pour l'image actuelle

    input.addEventListener('change', function() {
        const file = this.files[0];
        if (file) {
            const reader = new FileReader();

            reader.onload = function(e) {
                preview.src = e.target.result;
                preview.style.display = 'flex';
                if (currentImage) {
                    currentImage.style.display = 'none';
                }
            }

            reader.readAsDataURL(file);
        } else {
            preview.src = '#';
            preview.style.display = 'none';
            if (currentImage) {
                currentImage.style.display = 'flex';
            }
        }
    });

    // Au chargement de la page, si une image existe déjà, affiche la prévisualisation de l'image actuelle
    document.addEventListener('DOMContentLoaded', function() {
        if (currentImage && currentImage.src && currentImage.src !== window.location.origin + '/') {
            currentImage.style.display = 'flex';
        }
    });