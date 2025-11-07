// Gestion des onglets
function switchTab(tabIndex) {
    // Masquer tous les onglets
    const tabs = document.querySelectorAll('.tab');
    const contents = document.querySelectorAll('.tab-content');
    
    tabs.forEach(tab => tab.classList.remove('active'));
    contents.forEach(content => content.classList.remove('active'));
    
    // Activer l'onglet sélectionné
    tabs[tabIndex].classList.add('active');
    contents[tabIndex].classList.add('active');
}

// Fonction utilitaire pour convertir bytes en texte
function bytesToText(bytes) {
    try {
        return new TextDecoder().decode(new Uint8Array(bytes));
    } catch {
        return '[binary data]';
    }
}

// Initialisation au chargement de la page
document.addEventListener('DOMContentLoaded', function() {
    console.log('Démonstrateur ChaCha20-Poly1305 chargé');
    
    // Ajouter des exemples au clic sur les labels (optionnel)
    const examples = {
        'chacha-key': 'ma clé secrète',
        'chacha-message': 'Bonjour, ceci est un message test!',
        'poly-key': '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b',
        'poly-message': 'Message à authentifier',
        'aead-key': 'clé AEAD secrète',
        'aead-message': 'Message confidentiel à chiffrer',
        'aead-aad': 'Métadonnées publiques'
    };
    
    // Ajouter un bouton "Exemple" pour chaque input
    Object.keys(examples).forEach(id => {
        const input = document.getElementById(id);
        if (input) {
            const container = input.parentElement;
            const exampleBtn = document.createElement('button');
            exampleBtn.textContent = '📝 Exemple';
            exampleBtn.className = 'action-btn';
            exampleBtn.style.cssText = 'width: auto; padding: 8px 20px; font-size: 0.9em; margin-top: 5px; margin-left: 10px;';
            exampleBtn.onclick = (e) => {
                e.preventDefault();
                input.value = examples[id];
            };
            container.appendChild(exampleBtn);
        }
    });
});
