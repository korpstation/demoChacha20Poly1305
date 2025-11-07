// ============================================
// FONCTIONS UTILITAIRES COMMUNES
// ============================================

// Conversion texte vers bytes UTF-8
function textToBytes(text) {
    const encoder = new TextEncoder();
    return Array.from(encoder.encode(text));
}

// Conversion bytes vers texte UTF-8
function bytesToText(bytes) {
    const decoder = new TextDecoder();
    return decoder.decode(new Uint8Array(bytes));
}

// Conversion bytes vers hexadécimal
function bytesToHex(bytes) {
    return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Conversion hexadécimal vers bytes
function hexToBytes(hex) {
    hex = hex.replace(/\s/g, '');
    if (hex.length % 2 !== 0) {
        throw new Error('Hex string must have even length');
    }
    const bytes = [];
    for (let i = 0; i < hex.length; i += 2) {
        bytes.push(parseInt(hex.substr(i, 2), 16));
    }
    return bytes;
}

// Conversion d'une clé texte en bytes de 32 octets (pour ChaCha20)
function textKeyTo32Bytes(text) {
    const encoder = new TextEncoder();
    const bytes = Array.from(encoder.encode(text));
    
    // Étendre ou tronquer à 32 octets
    if (bytes.length === 0) {
        // Si vide, remplir avec des zéros
        return new Array(32).fill(0);
    } else if (bytes.length < 32) {
        // Répéter la clé jusqu'à atteindre 32 octets
        const result = [];
        while (result.length < 32) {
            result.push(...bytes);
        }
        return result.slice(0, 32);
    } else {
        // Tronquer
        return bytes.slice(0, 32);
    }
}

// Génération d'un nonce aléatoire (12 octets = 96 bits)
function generateRandomNonce() {
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    return Array.from(nonce);
}

// Génération d'une clé aléatoire (32 octets = 256 bits)
function generateRandomKey() {
    const key = new Uint8Array(32);
    crypto.getRandomValues(key);
    return Array.from(key);
}

// Addition modulo 2^32
function add32(a, b) {
    return (a + b) >>> 0;
}

// Rotation à gauche (left rotate)
function rotl(a, b) {
    return ((a << b) | (a >>> (32 - b))) >>> 0;
}

// XOR de deux tableaux de bytes
function xorBytes(a, b) {
    const result = [];
    for (let i = 0; i < Math.max(a.length, b.length); i++) {
        result.push((a[i] || 0) ^ (b[i] || 0));
    }
    return result;
}

// Conversion little-endian: 4 bytes -> uint32
function bytesToU32LE(bytes, offset = 0) {
    return (
        (bytes[offset] |
        (bytes[offset + 1] << 8) |
        (bytes[offset + 2] << 16) |
        (bytes[offset + 3] << 24)) >>> 0
    );
}

// Conversion uint32 -> 4 bytes little-endian
function u32ToBytes(value) {
    return [
        value & 0xff,
        (value >>> 8) & 0xff,
        (value >>> 16) & 0xff,
        (value >>> 24) & 0xff
    ];
}

// Affichage d'une matrice 4x4
function displayMatrix(matrix, highlightIndices = []) {
    let html = '<div class="matrix-container">';
    for (let i = 0; i < 16; i++) {
        const isHighlight = highlightIndices.includes(i);
        const classes = isHighlight ? 'matrix-cell highlight' : 'matrix-cell';
        html += `<div class="${classes}">${matrix[i].toString(16).padStart(8, '0')}</div>`;
    }
    html += '</div>';
    return html;
}

// Affichage d'une matrice avec label (pour l'addition finale)
function displayMatrixWithLabel(matrix, label = '', cssClass = '') {
    let html = '<div class="matrix-grid">';
    for (let i = 0; i < 16; i++) {
        const classes = `matrix-grid-cell ${cssClass}`;
        html += `<div class="${classes}">${matrix[i].toString(16).padStart(8, '0')}</div>`;
    }
    html += '</div>';
    
    if (label) {
        html = `<div>
            <div style="text-align:center; font-weight:bold; margin-bottom:8px; color:#2e4eb8;">${label}</div>
            ${html}
        </div>`;
    }
    
    return html;
}

// Affichage de bytes
function displayBytes(bytes, highlightIndices = []) {
    let html = '<div class="byte-display">';
    bytes.forEach((b, i) => {
        const isHighlight = highlightIndices.includes(i);
        const classes = isHighlight ? 'byte highlight' : 'byte';
        html += `<div class="${classes}">${b.toString(16).padStart(2, '0')}</div>`;
    });
    html += '</div>';
    return html;
}

// Validation d'une clé hexadécimale
function validateHexKey(hex, expectedBytes) {
    hex = hex.replace(/\s/g, '');
    if (!/^[0-9a-fA-F]*$/.test(hex)) {
        return { valid: false, error: 'La clé doit contenir uniquement des caractères hexadécimaux' };
    }
    if (hex.length !== expectedBytes * 2) {
        return { valid: false, error: `La clé doit contenir ${expectedBytes} octets (${expectedBytes * 2} caractères hex)` };
    }
    return { valid: true };
}

// Validation d'un nonce hexadécimal
function validateHexNonce(hex) {
    hex = hex.replace(/\s/g, '');
    if (hex === '') return { valid: true }; // Optionnel
    if (!/^[0-9a-fA-F]*$/.test(hex)) {
        return { valid: false, error: 'Le nonce doit contenir uniquement des caractères hexadécimaux' };
    }
    if (hex.length !== 24) {
        return { valid: false, error: 'Le nonce doit contenir 12 octets (24 caractères hex)' };
    }
    return { valid: true };
}

// Padding pour AEAD (alignement sur 16 octets)
function pad16(arr) {
    const pad = (16 - (arr.length % 16)) % 16;
    return arr.concat(new Array(pad).fill(0));
}

// Formatage d'un nombre BigInt en hex
function bigIntToHex(value, bytes = 16) {
    let hex = value.toString(16);
    return hex.padStart(bytes * 2, '0');
}

// Affichage formaté d'une opération
function displayOperation(title, content) {
    return `
        <div class="operation-display">
            <h4>${title}</h4>
            ${content}
        </div>
    `;
}

// Affichage d'un bloc Poly1305
function displayPolyBlock(title, content) {
    return `
        <div class="poly-block">
            <h5>${title}</h5>
            ${content}
        </div>
    `;
}

// Toggle pour les options avancées ChaCha20
function toggleAdvancedChacha() {
    const advanced = document.getElementById('chacha20-advanced');
    advanced.classList.toggle('hidden');
}

// Toggle pour les options avancées AEAD
function toggleAdvancedAEAD() {
    const advanced = document.getElementById('aead-advanced');
    advanced.classList.toggle('hidden');
}

// Copie dans le presse-papier
function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Copié dans le presse-papier !');
    }).catch(err => {
        console.error('Erreur lors de la copie:', err);
    });
}

// Affichage d'une erreur
function showError(message) {
    alert('❌ Erreur: ' + message);
}

// Affichage d'un succès
function showSuccess(message) {
    alert('✅ ' + message);
}
