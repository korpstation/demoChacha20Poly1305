// ============================================
// AEAD (ChaCha20-Poly1305) - Logique complète IDENTIQUE aux onglets séparés
// ============================================

let aeadState = {
    currentStep: 0,
    steps: [],
    quarterRoundSteps: {}, // Pour naviguer dans les opérations de chaque QR
    mode: 'encrypt' // 'encrypt' ou 'decrypt'
};

// Génération des étapes AEAD avec démonstration IDENTIQUE à ChaCha20 et Poly1305
function generateAEADSteps() {
    const steps = [];
    const mode = aeadState.mode;
    
    // Étape 0: Vue d'ensemble
    steps.push({
        title: mode === 'encrypt' ? 'Vue d\'ensemble AEAD (Chiffrement + Authentification)' : 'Vue d\'ensemble AEAD (Déchiffrement + Vérification)',
        type: 'overview',
        mode: mode,
        message: mode === 'encrypt' ? aeadState.messageText : null,
        aad: aeadState.aadText || '',
        keyHex: aeadState.keyHex,
        nonce: aeadState.nonce,
        ciphertext: mode === 'decrypt' ? aeadState.ciphertext : null,
        tag: mode === 'decrypt' ? aeadState.expectedTag : null
    });
    
    // ===== PARTIE 1: CHIFFREMENT/DÉCHIFFREMENT DU MESSAGE =====
    
    steps.push({
        title: mode === 'encrypt' ? '🔐 Partie 1/3: Chiffrement du message' : '🔓 Partie 1/3: Déchiffrement du message',
        type: 'part-separator',
        description: 'Utilisation de ChaCha20 avec compteur=1'
    });
    
    let messageBytes, ciphertext;
    
    if (mode === 'encrypt') {
        messageBytes = textToBytes(aeadState.messageText);
        
        steps.push({
            title: 'Message à chiffrer',
            type: 'message-to-encrypt',
            messageText: aeadState.messageText,
            messageBytes: messageBytes
        });
    } else {
        ciphertext = aeadState.ciphertext;
        
        steps.push({
            title: 'Ciphertext à déchiffrer',
            type: 'ciphertext-to-decrypt',
            ciphertext: ciphertext
        });
    }
    
    // Configuration pour chiffrement/déchiffrement
    steps.push({
        title: 'Configuration pour ' + (mode === 'encrypt' ? 'chiffrement' : 'déchiffrement'),
        type: 'config',
        purpose: mode === 'encrypt' ? 'Chiffrement' : 'Déchiffrement',
        keyHex: aeadState.keyHex,
        nonce: aeadState.nonce,
        counter: 1
    });
    
    // Initialisation ChaCha20 compteur=1
    const initialState1 = chacha20Block(aeadState.keyHex, 1, aeadState.nonce);
    steps.push({
        title: "Initialisation de l'état ChaCha20 (4×4) - Compteur=1",
        type: 'init',
        counter: 1,
        state: [...initialState1]
    });
    
    // 20 rounds avec TOUS les détails
    let workingState1 = [...initialState1];
    
    for (let round = 0; round < 10; round++) {
        const columnQRs = [[0,4,8,12], [1,5,9,13], [2,6,10,14], [3,7,11,15]];
        for (let i = 0; i < columnQRs.length; i++) {
            const [a,b,c,d] = columnQRs[i];
            const qrDetail = performQuarterRoundWithSteps(workingState1, a, b, c, d);
            const stateBefore = [...workingState1];
            applyQuarterRound(workingState1, a, b, c, d);
            const stateAfter = [...workingState1];
            
            steps.push({
                title: `Round ${round*2+1} - Quarter Round ${i+1}/4 (Colonne)`,
                type: 'quarter-round',
                roundNum: round*2+1,
                roundType: 'column',
                indices: [a,b,c,d],
                qrSteps: qrDetail.steps,
                stateBefore,
                stateAfter
            });
        }
        
        const diagonalQRs = [[0,5,10,15], [1,6,11,12], [2,7,8,13], [3,4,9,14]];
        for (let i = 0; i < diagonalQRs.length; i++) {
            const [a,b,c,d] = diagonalQRs[i];
            const qrDetail = performQuarterRoundWithSteps(workingState1, a, b, c, d);
            const stateBefore = [...workingState1];
            applyQuarterRound(workingState1, a, b, c, d);
            const stateAfter = [...workingState1];
            
            steps.push({
                title: `Round ${round*2+2} - Quarter Round ${i+1}/4 (Diagonale)`,
                type: 'quarter-round',
                roundNum: round*2+2,
                roundType: 'diagonal',
                indices: [a,b,c,d],
                qrSteps: qrDetail.steps,
                stateBefore,
                stateAfter
            });
        }
    }
    
    // Addition finale
    const stateAfterRounds1 = [...workingState1];
    const finalState1 = workingState1.map((v, i) => add32(v, initialState1[i]));
    
    steps.push({
        title: "Addition de l'état initial à l'état après rounds",
        type: 'add-initial',
        initialState: initialState1,
        stateAfterRounds: stateAfterRounds1,
        finalState: finalState1
    });
    
    // Sérialisation
    const keystream1 = [];
    finalState1.forEach(word => keystream1.push(...u32ToBytes(word)));
    
    steps.push({
        title: "Sérialisation en flux de clé (64 octets)",
        type: 'serialize',
        finalState: finalState1,
        keystream: keystream1
    });
    
    // XOR
    if (mode === 'encrypt') {
        ciphertext = messageBytes.map((b, i) => b ^ (keystream1[i] || 0));
        
        steps.push({
            title: "XOR du message avec le flux de clé",
            type: 'xor',
            mode: 'encrypt',
            message: messageBytes,
            keystream: keystream1.slice(0, messageBytes.length),
            result: ciphertext
        });
    } else {
        messageBytes = ciphertext.map((b, i) => b ^ (keystream1[i] || 0));
        
        steps.push({
            title: "XOR du ciphertext avec le flux de clé (déchiffrement)",
            type: 'xor',
            mode: 'decrypt',
            message: ciphertext,
            keystream: keystream1.slice(0, ciphertext.length),
            result: messageBytes
        });
    }
    
    // ===== PARTIE 2: GÉNÉRATION DE LA CLÉ POLY1305 AVEC CHACHA20 (COMPTEUR=0) =====
    
    steps.push({
        title: '🔑 Partie 2/3: Génération de la clé Poly1305',
        type: 'part-separator',
        description: 'Utilisation de ChaCha20 avec compteur=0 pour générer la clé Poly1305'
    });
    
    // Configuration pour clé Poly1305
    steps.push({
        title: 'Configuration pour génération clé Poly1305',
        type: 'config',
        purpose: 'Génération clé Poly1305',
        keyHex: aeadState.keyHex,
        nonce: aeadState.nonce,
        counter: 0
    });
    
    // Initialisation ChaCha20 compteur=0
    const initialState0 = chacha20Block(aeadState.keyHex, 0, aeadState.nonce);
    steps.push({
        title: "Initialisation de l'état ChaCha20 (4×4) - Compteur=0",
        type: 'init',
        counter: 0,
        state: [...initialState0]
    });
    
    // 20 rounds avec TOUS les détails comme dans ChaCha20
    let workingState0 = [...initialState0];
    
    for (let round = 0; round < 10; round++) {
        // Colonnes
        const columnQRs = [[0,4,8,12], [1,5,9,13], [2,6,10,14], [3,7,11,15]];
        for (let i = 0; i < columnQRs.length; i++) {
            const [a,b,c,d] = columnQRs[i];
            const qrDetail = performQuarterRoundWithSteps(workingState0, a, b, c, d);
            const stateBefore = [...workingState0];
            applyQuarterRound(workingState0, a, b, c, d);
            const stateAfter = [...workingState0];
            
            steps.push({
                title: `Round ${round*2+1} - Quarter Round ${i+1}/4 (Colonne)`,
                type: 'quarter-round',
                roundNum: round*2+1,
                roundType: 'column',
                indices: [a,b,c,d],
                qrSteps: qrDetail.steps,
                stateBefore,
                stateAfter
            });
        }
        
        // Diagonales
        const diagonalQRs = [[0,5,10,15], [1,6,11,12], [2,7,8,13], [3,4,9,14]];
        for (let i = 0; i < diagonalQRs.length; i++) {
            const [a,b,c,d] = diagonalQRs[i];
            const qrDetail = performQuarterRoundWithSteps(workingState0, a, b, c, d);
            const stateBefore = [...workingState0];
            applyQuarterRound(workingState0, a, b, c, d);
            const stateAfter = [...workingState0];
            
            steps.push({
                title: `Round ${round*2+2} - Quarter Round ${i+1}/4 (Diagonale)`,
                type: 'quarter-round',
                roundNum: round*2+2,
                roundType: 'diagonal',
                indices: [a,b,c,d],
                qrSteps: qrDetail.steps,
                stateBefore,
                stateAfter
            });
        }
    }
    
    // Addition de l'état initial
    const stateAfterRounds0 = [...workingState0];
    const finalState0 = workingState0.map((v, i) => add32(v, initialState0[i]));
    
    steps.push({
        title: "Addition de l'état initial à l'état après rounds",
        type: 'add-initial',
        initialState: initialState0,
        stateAfterRounds: stateAfterRounds0,
        finalState: finalState0
    });
    
    // Sérialisation
    const keystream0 = [];
    finalState0.forEach(word => keystream0.push(...u32ToBytes(word)));
    
    steps.push({
        title: "Sérialisation en flux de clé (64 octets)",
        type: 'serialize',
        finalState: finalState0,
        keystream: keystream0
    });
    
    // Extraction clé Poly1305
    const polyKeyBytes = keystream0.slice(0, 32);
    
    steps.push({
        title: '✂️ Extraction de la clé Poly1305 (32 premiers octets)',
        type: 'poly-key-extract',
        keystream: keystream0,
        polyKeyBytes: polyKeyBytes
    });
    
    // ===== PARTIE 3: AUTHENTIFICATION/VÉRIFICATION AVEC POLY1305 =====
    
    steps.push({
        title: mode === 'encrypt' ? '🔐 Partie 3/3: Authentification Poly1305' : '🔍 Partie 3/3: Vérification Poly1305',
        type: 'part-separator',
        description: 'Calcul du tag d\'authentification'
    });
    
    // Construction du buffer d'authentification
    const aadBytes = aeadState.aadText ? textToBytes(aeadState.aadText) : [];
    const aadPadded = pad16(aadBytes);
    const ctPadded = pad16(ciphertext);
    
    const aadLen = new Array(8).fill(0);
    const ctLen = new Array(8).fill(0);
    
    let lenVal = aadBytes.length;
    for (let i = 0; i < 8; i++) {
        aadLen[i] = lenVal & 0xff;
        lenVal >>>= 8;
    }
    
    lenVal = ciphertext.length;
    for (let i = 0; i < 8; i++) {
        ctLen[i] = lenVal & 0xff;
        lenVal >>>= 8;
    }
    
    const authData = [...aadPadded, ...ctPadded, ...aadLen, ...ctLen];
    
    steps.push({
        title: '📦 Construction du buffer d\'authentification',
        type: 'poly-auth-buffer',
        aadBytes: aadBytes,
        ciphertext: ciphertext,
        authData: authData
    });
    
    // Extraction r et s
    let r = polyKeyBytes.slice(0, 16);
    const s = polyKeyBytes.slice(16, 32);
    
    steps.push({
        title: '🔑 Extraction de r et s depuis la clé Poly1305',
        type: 'poly-extract',
        polyKey: polyKeyBytes,
        r: [...r],
        s: s
    });
    
    // Clamping
    const originalR = [...r];
    r = clampR(r);
    
    steps.push({
        title: '🔒 Clamping (restriction) de r',
        type: 'poly-clamp',
        originalR: originalR,
        clampedR: r
    });
    
    // Découpage en blocs
    const blocks = [];
    for (let i = 0; i < authData.length; i += 16) {
        blocks.push(authData.slice(i, Math.min(i + 16, authData.length)));
    }
    
    steps.push({
        title: `📦 Découpage en blocs de 16 octets`,
        type: 'poly-blocks',
        message: authData,
        blocks: blocks
    });
    
    // Traitement de chaque bloc (comme dans Poly1305)
    let accumulator = 0n;
    const p = (1n << 130n) - 5n;
    let rBigInt = 0n;
    for (let i = 0; i < r.length; i++) {
        rBigInt |= (BigInt(r[i]) << BigInt(i * 8));
    }
    
    blocks.forEach((block, index) => {
        let blockNum = 0n;
        for (let i = 0; i < block.length; i++) {
            blockNum |= (BigInt(block[i]) << BigInt(i * 8));
        }
        blockNum |= (1n << BigInt(block.length * 8));
        
        const oldAcc = accumulator;
        accumulator += blockNum;
        const afterAdd = accumulator;
        accumulator = (accumulator * rBigInt) % p;
        
        steps.push({
            title: `🔄 Traitement du bloc ${index + 1}/${blocks.length}`,
            type: 'poly-process-block',
            blockIndex: index,
            block: block,
            blockNum: blockNum,
            oldAcc: oldAcc,
            afterAdd: afterAdd,
            afterMul: accumulator,
            r: rBigInt,
            p: p
        });
    });
    
    // Addition de s et génération du tag
    let sBigInt = 0n;
    for (let i = 0; i < s.length; i++) {
        sBigInt |= (BigInt(s[i]) << BigInt(i * 8));
    }
    
    const beforeS = accumulator;
    accumulator += sBigInt;
    const tag = accumulator & ((1n << 128n) - 1n);
    const tagBytes = [];
    for (let i = 0; i < 16; i++) {
        tagBytes.push(Number((tag >> BigInt(i * 8)) & 0xffn));
    }
    
    steps.push({
        title: '➕ Addition de s et génération du tag final',
        type: 'poly-final',
        beforeS: beforeS,
        s: s,
        sBigInt: sBigInt,
        afterAdd: accumulator,
        tag: tagBytes
    });
    
    // Résultat final
    if (mode === 'encrypt') {
        steps.push({
            title: '✅ Résultat AEAD: Chiffrement + Authentification',
            type: 'aead-result',
            mode: mode,
            message: messageBytes,
            ciphertext: ciphertext,
            tagBytes: tagBytes,
            nonce: aeadState.nonce
        });
    } else {
        const expectedTag = aeadState.expectedTag;
        const isValid = tagBytes.length === expectedTag.length && 
                        tagBytes.every((b, i) => b === expectedTag[i]);
        
        steps.push({
            title: '🔍 Vérification du tag',
            type: 'poly-verify',
            computedTag: tagBytes,
            expectedTag: expectedTag,
            isValid: isValid
        });
        
        steps.push({
            title: isValid ? '✅ Résultat AEAD: Vérification réussie' : '❌ Résultat AEAD: Vérification échouée',
            type: 'aead-result',
            mode: mode,
            message: messageBytes,
            ciphertext: ciphertext,
            computedTag: tagBytes,
            expectedTag: expectedTag,
            isValid: isValid
        });
    }
    
    aeadState.steps = steps;
}

// Démarrer AEAD
function startAEAD() {
    const modeBtn = document.querySelector('#aead .mode-btn.active');
    const mode = modeBtn ? modeBtn.dataset.mode : 'encrypt';
    
    if (mode === 'encrypt') {
        // MODE CHIFFREMENT
        let keyText = document.getElementById('aead-key-text').value.trim();
        let nonce = document.getElementById('aead-nonce').value.trim();
        
        if (!keyText) {
            showError('Veuillez entrer une clé');
            return;
        }
        
        const keyData = normalizeKeyTextTo32Bytes(keyText);
        const keyHex = keyData.keyHex;
        
        // Nonce optionnel en chiffrement
        if (!nonce || nonce.length !== 24) {
            nonce = bytesToHex(generateRandomNonce());
        }
        
        const nonceValidation = validateHexNonce(nonce);
        if (!nonceValidation.valid) {
            showError(nonceValidation.error);
            return;
        }
        
        const message = document.getElementById('aead-message').value || '';
        if (!message) {
            showError('Veuillez entrer un message');
            return;
        }
        
        aeadState = {
            currentStep: 0,
            steps: [],
            quarterRoundSteps: {},
            mode: mode,
            keyHex: keyHex,
            keyBytes: hexToBytes(keyHex),
            nonce: nonce,
            messageText: message,
            aadText: document.getElementById('aead-aad').value || ''
        };
    } else {
        // MODE DÉCHIFFREMENT
        let keyText = document.getElementById('aead-key-text-decrypt').value.trim();
        let nonce = document.getElementById('aead-nonce-decrypt').value.trim();
        
        if (!keyText) {
            showError('Veuillez entrer une clé');
            return;
        }
        
        const keyData = normalizeKeyTextTo32Bytes(keyText);
        const keyHex = keyData.keyHex;
        
        // Le nonce est OBLIGATOIRE en déchiffrement
        if (!nonce || nonce.length !== 24) {
            showError('Le nonce est obligatoire pour le déchiffrement (24 caractères hexadécimaux)');
            return;
        }
        
        const nonceValidation = validateHexNonce(nonce);
        if (!nonceValidation.valid) {
            showError(nonceValidation.error);
            return;
        }
        
        const ciphertextHex = document.getElementById('aead-ciphertext').value.trim();
        const tagHex = document.getElementById('aead-tag').value.trim();
        
        if (!ciphertextHex) {
            showError('Veuillez entrer le ciphertext (en hexadécimal)');
            return;
        }
        
        if (!tagHex) {
            showError('Veuillez entrer le tag (en hexadécimal)');
            return;
        }
        
        // Validation du format hexadécimal
        if (!/^[0-9a-fA-F]+$/.test(ciphertextHex)) {
            showError('Le ciphertext doit être au format hexadécimal');
            return;
        }
        
        if (!/^[0-9a-fA-F]{32}$/.test(tagHex)) {
            showError('Le tag doit être de 32 caractères hexadécimaux (16 octets)');
            return;
        }
        
        // Le ciphertext doit avoir un nombre pair de caractères
        if (ciphertextHex.length % 2 !== 0) {
            showError('Le ciphertext doit avoir un nombre pair de caractères hexadécimaux');
            return;
        }
        
        try {
            const ciphertext = hexToBytes(ciphertextHex);
            const expectedTag = hexToBytes(tagHex);
            
            aeadState = {
                currentStep: 0,
                steps: [],
                quarterRoundSteps: {},
                mode: mode,
                keyHex: keyHex,
                keyBytes: hexToBytes(keyHex),
                nonce: nonce,
                ciphertext: ciphertext,
                expectedTag: expectedTag,
                aadText: document.getElementById('aead-aad-decrypt').value || ''
            };
        } catch (e) {
            showError('Erreur lors de la conversion hexadécimale: ' + e.message);
            return;
        }
    }
    
    generateAEADSteps();
    
    document.getElementById('aead-inputs').classList.add('hidden');
    document.getElementById('aead-viz').classList.remove('hidden');
    displayAEADStep(0);
}

// Afficher une étape AEAD - EXACTEMENT comme ChaCha20 et Poly1305
function displayAEADStep(stepIndex) {
    const step = aeadState.steps[stepIndex];
    const content = document.getElementById('aead-content');
    const titleEl = document.getElementById('aead-step-title');
    const progress = document.getElementById('aead-progress');
    
    titleEl.textContent = step.title;
    const percent = Math.round((stepIndex / (aeadState.steps.length - 1)) * 100);
    progress.style.width = percent + '%';
    progress.textContent = percent + '%';
    
    let html = '';
    
    if (step.type === 'overview') {
        html += displayOperation('📋 Vue d\'ensemble AEAD (ChaCha20-Poly1305)', `
            <p><strong>Mode:</strong> ${step.mode === 'encrypt' ? 'Chiffrement + Authentification' : 'Déchiffrement + Vérification'}</p>
            ${step.mode === 'encrypt' ? `<p><strong>Message:</strong> "${step.message}"</p>` : `<p><strong>Ciphertext (hex):</strong> ${bytesToHex(step.ciphertext)}</p>`}
            ${step.mode === 'decrypt' ? `<p><strong>Tag attendu (hex):</strong> ${bytesToHex(step.tag)}</p>` : ''}
            ${step.aad ? `<p><strong>AAD (Additional Authenticated Data):</strong> "${step.aad}"</p>` : ''}
            <p><strong>Clé (hex):</strong> ${step.keyHex}</p>
            <p><strong>Nonce (hex):</strong> ${step.nonce}</p>
            <div class="info-box" style="margin-top:10px;">
                <strong>ℹ️ Processus AEAD en 3 parties:</strong><br>
                1️⃣ ${step.mode === 'encrypt' ? 'Chiffrement' : 'Déchiffrement'} du message avec ChaCha20 (compteur=1)<br>
                2️⃣ Génération de la clé Poly1305 avec ChaCha20 (compteur=0)<br>
                3️⃣ ${step.mode === 'encrypt' ? 'Calcul' : 'Vérification'} du tag d'authentification avec Poly1305
            </div>
        `);
    }
    else if (step.type === 'part-separator') {
        html += `<div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 24px; border-radius: 12px; text-align: center; margin: 20px 0; box-shadow: 0 8px 20px rgba(102,126,234,0.4);">
            <h2 style="margin: 0 0 12px 0; font-size: 1.6rem;">${step.title}</h2>
            <p style="margin: 0; font-size: 1.1rem; opacity: 0.95;">${step.description}</p>
        </div>`;
    }
    else if (step.type === 'config') {
        html += displayOperation('🔧 Configuration', `
            <p><strong>Objectif:</strong> ${step.purpose}</p>
            <p><strong>Clé (32 octets en hex):</strong></p>
            ${displayBytes(hexToBytes(step.keyHex))}
            <p><strong>Nonce (12 octets en hex):</strong></p>
            ${displayBytes(hexToBytes(step.nonce))}
            <p><strong>Compteur:</strong> ${step.counter}</p>
            <div class="info-box" style="margin-top:8px;">
                <strong>ℹ️ Info:</strong> ChaCha20 génère un flux de 64 octets par bloc (compteur).
            </div>
        `);
    }
    else if (step.type === 'init') {
        html += displayOperation('🎯 État initial (4×4 mots de 32 bits)', 
            `<p>Constantes "expand 32-byte k", clé, compteur=${step.counter}, nonce</p>`);
        html += '<div class="matrix-container">';
        step.state.forEach((v, i) => {
            let label = i < 4 ? 'Constante' : (i < 12 ? 'Clé' : (i === 12 ? 'Compteur' : 'Nonce'));
            html += `<div class="matrix-cell">
                <small style="opacity:.7;">[${i}] ${label}</small><br>
                <strong>${v.toString(16).padStart(8,'0')}</strong>
            </div>`;
        });
        html += '</div>';
    }
    else if (step.type === 'quarter-round') {
        // EXACTEMENT comme ChaCha20
        const key = 'qr' + stepIndex;
        if (!aeadState.quarterRoundSteps[key]) aeadState.quarterRoundSteps[key] = 0;
        const opIndex = aeadState.quarterRoundSteps[key];
        
        html += displayOperation(`🔄 ${step.title}`, 
            `<p><strong>Indices:</strong> [${step.indices.join(', ')}] (a, b, c, d)</p>`);
        
        // Afficher l'état avant avec les indices mis en évidence
        html += '<div style="margin-top:12px;"><strong>État avant Quarter Round:</strong></div>';
        html += '<div class="matrix-container">';
        step.stateBefore.forEach((v, i) => {
            const isIdx = step.indices.includes(i);
            const cls = isIdx ? 'matrix-cell highlight' : 'matrix-cell';
            html += `<div class="${cls}">
                <small style="opacity:.7;">[${i}]</small><br>
                <strong>${v.toString(16).padStart(8,'0')}</strong>
            </div>`;
        });
        html += '</div>';
        
        // Si on est en train de parcourir les opérations
        if (opIndex < step.qrSteps.length) {
            const cur = step.qrSteps[opIndex];
            
            html += `<div class="operation-display" style="margin-top:16px; background: linear-gradient(135deg, #fff3cd 0%, #ffe69c 100%); border-left: 4px solid #ffc107;">
                <div style="text-align:center; margin-bottom:10px; font-size: 1.1rem;">
                    <strong>⚙️ Opération ${opIndex+1}/${step.qrSteps.length}</strong>
                </div>
                <h4 style="color:#856404; margin:8px 0; font-size: 1.15rem;">⚡ ${cur.op}</h4>
                <div style="background: rgba(255,255,255,0.7); padding: 10px; border-radius: 8px; margin-top: 8px;">
                    <code style="font-size: 0.95rem;">${cur.detail}</code>
                </div>
            </div>`;
            
            // Afficher la matrice avec les cellules actives colorées
            html += '<div style="margin-top:16px;"><strong>Cellules actives dans cette opération:</strong></div>';
            html += '<div class="matrix-container">';
            
            // Créer un état intermédiaire pour montrer les changements
            const intermediateState = [...step.stateBefore];
            // Appliquer les changements de l'opération actuelle
            Object.keys(cur.after).forEach(idx => {
                intermediateState[idx] = cur.after[idx];
            });
            
            step.stateBefore.forEach((v, i) => {
                let cls = 'matrix-cell';
                let displayValue = intermediateState[i];
                
                if (cur.indices.includes(i)) {
                    cls = 'matrix-cell active'; // Cellule active (jaune animé)
                } else {
                    cls = 'matrix-cell';
                }
                
                html += `<div class="${cls}">
                    <small style="opacity:.7;">[${i}]</small><br>
                    <strong>${displayValue.toString(16).padStart(8,'0')}</strong>
                </div>`;
            });
            html += '</div>';
            
            // Boutons de navigation dans les opérations
            html += `<div style="text-align:center; margin-top:16px;">
                <button class="btn btn-secondary" ${opIndex === 0 ? 'disabled' : ''} onclick="prevQROpAEAD(${stepIndex})">⬅️ Op. précédente</button>
                <button class="btn btn-primary" onclick="nextQROpAEAD(${stepIndex})">${opIndex === step.qrSteps.length - 1 ? 'Terminer QR' : 'Op. suivante'} ➡️</button>
            </div>`;
        } else {
            // Quarter round terminé - montrer le résultat
            html += `<div class="info-box" style="margin-top:16px; background: #d4edda; border-color: #28a745;"><strong>✅ Quarter Round terminé !</strong></div>`;
            
            html += '<div style="margin-top:12px;"><strong>État après Quarter Round:</strong></div>';
            html += '<div class="matrix-container">';
            step.stateAfter.forEach((v, i) => {
                const changed = step.stateBefore[i] !== v;
                html += `<div class="matrix-cell ${changed ? 'result' : ''}">
                    <small>[${i}]</small><br>
                    <strong>${v.toString(16).padStart(8,'0')}</strong>
                </div>`;
            });
            html += '</div>';
            
            // Résumé des opérations
            html += '<div class="operation-display" style="margin-top:16px;"><h4>📋 Résumé des opérations</h4>';
            html += '<div style="max-height: 300px; overflow-y: auto;">';
            step.qrSteps.forEach((op, i) => {
                html += `<div style="margin: 8px 0; padding: 8px; background: #f8f9fa; border-radius: 6px;">
                    <strong>${i+1}. ${op.op}</strong><br>
                    <code style="font-size: 0.85rem; color: #666;">${op.detail}</code>
                </div>`;
            });
            html += '</div></div>';
        }
    }
    else if (step.type === 'add-initial') {
        html += displayOperation('➕ Addition de l\'état initial', 
            '<p>Addition modulo 2³² de chaque mot : final[i] = (working[i] + initial[i]) mod 2³²</p>');
        
        // AFFICHAGE MATRICIEL AMÉLIORÉ
        html += '<div class="matrix-addition-container">';
        html += displayMatrixWithLabel(step.initialState, 'État Initial', 'highlight');
        html += '<div class="matrix-addition-label">+</div>';
        html += displayMatrixWithLabel(step.stateAfterRounds, 'État après Rounds', '');
        html += '<div class="matrix-addition-label">=</div>';
        html += displayMatrixWithLabel(step.finalState, 'État Final', 'result');
        html += '</div>';
        
        // Détails verticaux en dessous
        html += '<div style="margin-top:20px;"><h4 style="text-align:center; color:#2e4eb8;">Détails des additions</h4></div>';
        html += '<div style="max-width:800px; margin:0 auto;">';
        for (let i = 0; i < 16; i++) {
            html += `<div style="display:flex; gap:8px; align-items:center; margin:6px 0; justify-content:center;">
                <div class="byte">${step.initialState[i].toString(16).padStart(8,'0')}</div>
                <div style="font-weight:700;">+</div>
                <div class="byte highlight">${step.stateAfterRounds[i].toString(16).padStart(8,'0')}</div>
                <div style="font-weight:700;">=</div>
                <div class="byte" style="background:#28a745;color:white;">${step.finalState[i].toString(16).padStart(8,'0')}</div>
            </div>`;
        }
        html += '</div>';
    }
    else if (step.type === 'serialize') {
        html += displayOperation('📦 Sérialisation en flux de clé', 
            '<p>Les 16 mots (32 bits) sont convertis en 64 octets (little-endian).</p>');
        html += '<div class="matrix-container">';
        step.finalState.forEach((v, i) => {
            html += `<div class="matrix-cell">
                <small>[${i}]</small><br>
                <strong>${v.toString(16).padStart(8,'0')}</strong>
            </div>`;
        });
        html += '</div>';
        html += '<div style="margin-top:10px;"><strong>Flux de clé (64 octets):</strong></div>';
        html += displayBytes(step.keystream);
    }
    else if (step.type === 'poly-key-extract') {
        html += displayOperation('✂️ Extraction de la clé Poly1305', 
            '<p>Les <strong>32 premiers octets</strong> du flux de clé ChaCha20 deviennent la clé Poly1305.</p>');
        html += displayPolyBlock('Flux de clé ChaCha20 (64 octets)', displayBytes(step.keystream));
        html += displayPolyBlock('Clé Poly1305 extraite (32 premiers octets)', 
            displayBytes(step.polyKeyBytes, Array.from({length:32}, (_,i)=>i)));
    }
    else if (step.type === 'message-to-encrypt') {
        html += displayOperation('📝 Message à chiffrer', '');
        html += `<pre style="background:#f8f9fa; padding:15px; border-radius:8px; font-size:1.1rem;">"${step.messageText}"</pre>`;
        html += '<h5 style="color:#667eea; text-align:center; margin:15px 0;">Bytes du message :</h5>';
        html += displayBytes(step.messageBytes);
    }
    else if (step.type === 'ciphertext-to-decrypt') {
        html += displayOperation('🔒 Ciphertext à déchiffrer', '');
        html += displayBytes(step.ciphertext);
    }
    else if (step.type === 'xor') {
        const isEncrypt = step.mode === 'encrypt';
        html += displayOperation(`⚡ ${isEncrypt ? 'Chiffrement' : 'Déchiffrement'} (XOR)`, 
            `<p>${isEncrypt ? 'Message ⊕ Flux de clé = Ciphertext' : 'Ciphertext ⊕ Flux de clé = Message'}</p>`);
        
        html += `<div><strong>${isEncrypt ? 'Message' : 'Ciphertext'} (hex):</strong></div>`;
        html += displayBytes(step.message);
        
        html += '<div style="text-align:center; font-size:1.2rem; margin:8px;">⊕</div>';
        
        html += '<div><strong>Flux de clé (hex):</strong></div>';
        html += displayBytes(step.keystream, []);
        
        html += '<div style="text-align:center; font-size:1.2rem; margin:8px;">=</div>';
        
        html += `<div><strong>${isEncrypt ? 'Ciphertext' : 'Message déchiffré'} (hex):</strong></div>`;
        html += displayBytes(step.result);
        
        if (!isEncrypt) {
            html += `<div style="margin-top:16px; padding:15px; background:#e7f3ff; border-radius:8px; border-left:4px solid #2196F3;">
                <strong>📝 Message déchiffré (texte):</strong><br>
                <pre style="margin-top:8px; font-size:1.1rem; background:white; padding:10px; border-radius:4px;">"${bytesToText(step.result)}"</pre>
            </div>`;
        }
    }
    else if (step.type === 'poly-auth-buffer') {
        html += displayOperation('📦 Construction du buffer d\'authentification', `
            <p>Structure: AAD | padding | ciphertext | padding | len(AAD) | len(ciphertext)</p>
        `);
        if (step.aadBytes.length > 0) {
            html += displayPolyBlock(`AAD (${step.aadBytes.length} octets)`, displayBytes(step.aadBytes));
        }
        html += displayPolyBlock(`Ciphertext (${step.ciphertext.length} octets)`, displayBytes(step.ciphertext));
        html += `<h5 style="color:#667eea; text-align:center; margin:15px 0;">Buffer complet (${step.authData.length} octets) :</h5>`;
        html += displayBytes(step.authData);
    }
    else if (step.type === 'poly-extract') {
        html += displayOperation('🔑 Extraction de r et s', `
            <p>La clé Poly1305 de 32 octets est divisée en deux parties :</p>
            <ul style="margin-left:20px; margin-top:8px;">
                <li><strong>r</strong> (16 octets) : utilisé pour l'accumulation</li>
                <li><strong>s</strong> (16 octets) : ajouté à la fin</li>
            </ul>
        `);
        html += displayPolyBlock('Clé Poly1305 complète (32 octets)', displayBytes(step.polyKey));
        html += '<div style="display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-top:15px;">';
        html += displayPolyBlock('r (16 premiers octets)', displayBytes(step.r, Array.from({length:16}, (_,i)=>i)));
        html += displayPolyBlock('s (16 derniers octets)', displayBytes(step.s));
        html += '</div>';
    }
    else if (step.type === 'poly-clamp') {
        html += displayOperation('🔒 Clamping (restriction) de r', `
            <p>Certains bits de r sont mis à zéro pour assurer la sécurité :</p>
            <ul style="margin-left:20px; margin-top:8px;">
                <li>Octets 3, 7, 11, 15 : AND avec 15 (0x0F)</li>
                <li>Octets 4, 8, 12 : AND avec 252 (0xFC)</li>
            </ul>
        `);
        html += displayPolyBlock('r original', '<div class="byte-display">' + 
            step.originalR.map((b, idx) => {
                const changed = b !== step.clampedR[idx];
                return `<div class="byte ${changed ? 'active' : ''}">${b.toString(16).padStart(2,'0')}</div>`;
            }).join('') + '</div>');
        html += displayPolyBlock('r après clamping', displayBytes(step.clampedR, Array.from({length:16}, (_,i)=>i)));
    }
    else if (step.type === 'poly-blocks') {
        html += displayOperation('📦 Découpage en blocs de 16 octets', `
            <p>Le buffer d'authentification (${step.message.length} octets) est découpé en blocs de 16 octets maximum.</p>
        `);
        step.blocks.forEach((blk, j) => {
            html += displayPolyBlock(`Bloc ${j + 1}/${step.blocks.length} (${blk.length} octets)`, displayBytes(blk));
        });
    }
    else if (step.type === 'poly-process-block') {
        html += displayOperation(`🔄 Traitement du bloc ${step.blockIndex + 1}`, '');
        html += displayPolyBlock(`Bloc ${step.blockIndex + 1}`, displayBytes(step.block));
        html += '<div class="poly-computation" style="margin-top:15px;">';
        html += '<h5>Opérations :</h5>';
        html += `<p>1. Conversion du bloc en nombre (little-endian) + padding bit :</p>`;
        html += `<pre>block_num = 0x${step.blockNum.toString(16)}</pre>`;
        html += `<p>2. Addition à l'accumulateur :</p>`;
        html += `<pre>acc = 0x${step.oldAcc.toString(16)}\nacc += block_num\nacc = 0x${step.afterAdd.toString(16)}</pre>`;
        html += `<p>3. Multiplication par r modulo p = 2¹³⁰ - 5 :</p>`;
        html += `<pre>acc = (acc × r) mod p\nacc = 0x${step.afterMul.toString(16)}</pre>`;
        html += '</div>';
    }
    else if (step.type === 'poly-final') {
        html += displayOperation('➕ Addition de s et génération du tag', '');
        html += '<div class="poly-computation">';
        html += `<p>1. Accumulateur après traitement de tous les blocs :</p>`;
        html += `<pre>acc = 0x${step.beforeS.toString(16)}</pre>`;
        html += displayPolyBlock('s (16 octets)', displayBytes(step.s));
        html += `<p>2. Addition de s :</p>`;
        html += `<pre>s = 0x${step.sBigInt.toString(16)}\nacc += s\nacc = 0x${step.afterAdd.toString(16)}</pre>`;
        html += `<p>3. Extraction des 128 bits inférieurs (le tag) :</p>`;
        html += `<pre>tag = acc & (2¹²⁸ - 1)</pre>`;
        html += '</div>';
        html += displayPolyBlock('Tag Poly1305 calculé (16 octets)', displayBytes(step.tag, Array.from({length:16}, (_,i)=>i)));
    }
    else if (step.type === 'poly-verify') {
        html += displayOperation('🔍 Vérification du tag', '');
        html += displayPolyBlock('Tag calculé', displayBytes(step.computedTag, Array.from({length:16}, (_,i)=>i)));
        html += displayPolyBlock('Tag attendu', displayBytes(step.expectedTag, Array.from({length:16}, (_,i)=>i)));
        
        if (step.isValid) {
            html += '<div style="background:#d4edda; border:2px solid #28a745; padding:16px; border-radius:8px; margin-top:16px; text-align:center;">';
            html += '<h3 style="color:#155724; margin-bottom:8px;">✅ Tag valide !</h3>';
            html += '<p style="color:#155724;">Le message est authentique et n\'a pas été modifié.</p>';
            html += '</div>';
        } else {
            html += '<div style="background:#f8d7da; border:2px solid #dc3545; padding:16px; border-radius:8px; margin-top:16px; text-align:center;">';
            html += '<h3 style="color:#721c24; margin-bottom:8px;">❌ Tag invalide !</h3>';
            html += '<p style="color:#721c24;">Le message a été modifié ou la clé/nonce est incorrecte.</p>';
            html += '</div>';
        }
    }
    else if (step.type === 'aead-result') {
        if (step.mode === 'encrypt') {
            html += displayOperation('✅ AEAD Terminé: Chiffrement + Authentification', '');
            html += displayPolyBlock('Message original', `<pre style="font-size:1.1rem;">"${bytesToText(step.message)}"</pre>`);
            html += displayPolyBlock('Ciphertext (hex)', `<pre style="font-size:0.95rem; word-break:break-all;">${bytesToHex(step.ciphertext)}</pre>`);
            html += displayPolyBlock('Tag Poly1305 (hex)', `<pre style="font-size:0.95rem;">${bytesToHex(step.tagBytes)}</pre>`);
            html += displayPolyBlock('Nonce (hex)', `<pre style="font-size:0.95rem;">${step.nonce}</pre>`);
            html += '<div class="info-box" style="margin-top:15px; background:#fff3cd; border-color:#ffc107;">' +
                '<strong>📤 À transmettre au destinataire:</strong><br>' +
                '• Ciphertext (données chiffrées)<br>' +
                '• Tag (pour vérification)<br>' +
                '• Nonce (doit être unique, peut être public)<br>' +
                '• AAD si utilisé (peut être public)<br><br>' +
                '<strong>⚠️ Important:</strong> La clé doit rester secrète et partagée à l\'avance entre émetteur et destinataire.</div>';
            
            const resultEl = document.getElementById('aead-result');
            resultEl.classList.remove('hidden');
            resultEl.innerHTML = `
                <h3 style="color:#28a745;">✅ AEAD Chiffrement terminé avec succès</h3>
                <div style="margin-top:15px;">
                    <p><strong>Ciphertext:</strong></p>
                    <pre style="background:#f8f9fa; padding:10px; border-radius:6px; word-break:break-all; font-size:0.9rem;">${bytesToHex(step.ciphertext)}</pre>
                </div>
                <div style="margin-top:10px;">
                    <p><strong>Tag:</strong></p>
                    <pre style="background:#f8f9fa; padding:10px; border-radius:6px; font-size:0.9rem;">${bytesToHex(step.tagBytes)}</pre>
                </div>
                <div style="margin-top:10px;">
                    <p><strong>Nonce:</strong></p>
                    <pre style="background:#f8f9fa; padding:10px; border-radius:6px; font-size:0.9rem;">${step.nonce}</pre>
                </div>
            `;
        } else {
            if (step.isValid) {
                html += displayOperation('✅ AEAD Terminé: Déchiffrement et vérification réussis', '');
                html += '<div style="background:#d4edda; border:2px solid #28a745; padding:20px; border-radius:12px; margin:20px 0; text-align:center;">';
                html += '<h3 style="color:#155724; margin-bottom:12px;">✅ Authentification réussie !</h3>';
                html += '<p style="color:#155724; margin-bottom:16px;">Le tag est valide. Le message est authentique et n\'a pas été altéré.</p>';
                html += '</div>';
                html += displayPolyBlock('Message déchiffré', `<pre style="font-size:1.2rem; font-weight:500;">"${bytesToText(step.message)}"</pre>`);
                html += displayPolyBlock('Ciphertext (hex)', `<pre style="font-size:0.9rem; word-break:break-all;">${bytesToHex(step.ciphertext)}</pre>`);
                html += '<div style="display:grid; grid-template-columns:1fr 1fr; gap:15px; margin-top:15px;">';
                html += displayPolyBlock('Tag calculé', `<pre style="font-size:0.85rem;">${bytesToHex(step.computedTag)}</pre>`);
                html += displayPolyBlock('Tag attendu', `<pre style="font-size:0.85rem;">${bytesToHex(step.expectedTag)}</pre>`);
                html += '</div>';
                
                const resultEl = document.getElementById('aead-result');
                resultEl.classList.remove('hidden');
                resultEl.innerHTML = `
                    <h3 style="color:#28a745;">✅ AEAD Déchiffrement réussi</h3>
                    <div style="background:#d4edda; padding:15px; border-radius:8px; margin-top:15px;">
                        <p style="margin:0;"><strong>Message déchiffré:</strong></p>
                        <pre style="margin:10px 0 0 0; font-size:1.1rem; background:white; padding:10px; border-radius:6px;">"${bytesToText(step.message)}"</pre>
                    </div>
                    <p style="margin-top:15px; color:#28a745;"><strong>✅ Vérification du tag réussie</strong></p>
                `;
            } else {
                html += displayOperation('❌ AEAD: Échec de la vérification', '');
                html += '<div style="background:#f8d7da; border:2px solid #dc3545; padding:20px; border-radius:12px; margin:20px 0; text-align:center;">';
                html += '<h3 style="color:#721c24; margin-bottom:12px;">❌ Authentification échouée !</h3>';
                html += '<p style="color:#721c24; margin-bottom:8px;">Le tag ne correspond pas. Causes possibles :</p>';
                html += '<ul style="color:#721c24; text-align:left; display:inline-block; margin:0;">';
                html += '<li>Le message a été modifié</li>';
                html += '<li>La clé est incorrecte</li>';
                html += '<li>Le nonce est incorrect</li>';
                html += '<li>Le tag a été altéré</li>';
                html += '<li>L\'AAD ne correspond pas</li>';
                html += '</ul>';
                html += '</div>';
                html += '<div style="display:grid; grid-template-columns:1fr 1fr; gap:15px; margin-top:15px;">';
                html += displayPolyBlock('Tag calculé', `<pre style="font-size:0.85rem; color:#dc3545;">${bytesToHex(step.computedTag)}</pre>`);
                html += displayPolyBlock('Tag attendu', `<pre style="font-size:0.85rem; color:#dc3545;">${bytesToHex(step.expectedTag)}</pre>`);
                html += '</div>';
                html += '<div style="background:#fff3cd; border:2px solid #ffc107; padding:15px; border-radius:8px; margin-top:16px;">';
                html += '<p style="margin:0; color:#856404;"><strong>⚠️ Attention:</strong> Le message déchiffré ne doit PAS être utilisé car il n\'a pas pu être authentifié.</p>';
                html += '</div>';
                
                const resultEl = document.getElementById('aead-result');
                resultEl.classList.remove('hidden');
                resultEl.innerHTML = `
                    <h3 style="color:#dc3545;">❌ AEAD Vérification échouée</h3>
                    <div style="background:#f8d7da; padding:15px; border-radius:8px; margin-top:15px; border:2px solid #dc3545;">
                        <p style="margin:0; color:#721c24;"><strong>❌ Le tag ne correspond pas</strong></p>
                        <p style="margin:10px 0 0 0; color:#721c24;">Le message ne peut pas être considéré comme authentique.</p>
                    </div>
                `;
            }
        }
    }
    
    content.innerHTML = html;
    
    document.getElementById('aead-prev').disabled = stepIndex === 0;
    document.getElementById('aead-next').disabled = stepIndex === aeadState.steps.length - 1;
}

// Navigation dans les opérations du Quarter Round - EXACTEMENT comme ChaCha20
function nextQROpAEAD(stepIndex) {
    const key = 'qr' + stepIndex;
    const step = aeadState.steps[stepIndex];
    if (aeadState.quarterRoundSteps[key] < step.qrSteps.length - 1) {
        aeadState.quarterRoundSteps[key]++;
        displayAEADStep(stepIndex);
    } else {
        // Terminer le QR et passer à l'étape suivante
        aeadState.quarterRoundSteps[key] = step.qrSteps.length;
        displayAEADStep(stepIndex);
    }
}

function prevQROpAEAD(stepIndex) {
    const key = 'qr' + stepIndex;
    if (aeadState.quarterRoundSteps[key] > 0) {
        aeadState.quarterRoundSteps[key]--;
        displayAEADStep(stepIndex);
    }
}

// Navigation
function nextStepAEAD() {
    if (aeadState.currentStep < aeadState.steps.length - 1) {
        aeadState.currentStep++;
        displayAEADStep(aeadState.currentStep);
    }
}

function prevStepAEAD() {
    if (aeadState.currentStep > 0) {
        aeadState.currentStep--;
        displayAEADStep(aeadState.currentStep);
    }
}

function resetAEAD() {
    aeadState = { currentStep: 0, steps: [], quarterRoundSteps: {}, mode: 'encrypt' };
    document.getElementById('aead-inputs').classList.remove('hidden');
    document.getElementById('aead-viz').classList.add('hidden');
    document.getElementById('aead-result').classList.add('hidden');
}