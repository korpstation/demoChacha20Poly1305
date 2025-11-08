// ============================================
// CHACHA20 - Logique complète
// ============================================

let chacha20State = {
    currentStep: 0,
    steps: [],
    quarterRoundSteps: {},
    mode: 'encrypt' // 'encrypt' ou 'decrypt'
};

// Normalisation de la clé texte en 32 octets
function normalizeKeyTextTo32Bytes(text) {
    const bytes = textKeyTo32Bytes(text);
    let note = '';
    if (text.length === 0) {
        note = 'Clé vide → remplie avec des zéros (32 octets).';
    } else if (text.length < 32) {
        note = `Clé répétée de ${text.length} caractères à 32 octets.`;
    } else if (text.length > 32) {
        note = 'Clé tronquée à 32 octets.';
    } else {
        note = 'Clé exactement 32 octets.';
    }
    return { keyBytes: bytes, keyHex: bytesToHex(bytes), note };
}

// Création du bloc ChaCha20 initial
function chacha20Block(keyHex, counter, nonceHex) {
    const keyBytes = hexToBytes(keyHex);
    const nonceBytes = hexToBytes(nonceHex);
    
    // Constantes "expand 32-byte k"
    const constants = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    
    // Convertir clé (32 octets = 8 mots)
    const key = [];
    for (let i = 0; i < 8; i++) {
        key.push(bytesToU32LE(keyBytes, i * 4));
    }
    
    // Compteur (1 mot)
    const ctr = counter;
    
    // Nonce (3 mots)
    const nonce = [];
    for (let i = 0; i < 3; i++) {
        nonce.push(bytesToU32LE(nonceBytes, i * 4));
    }
    
    // État initial 4x4
    return [
        ...constants,    // 0-3
        ...key,          // 4-11
        ctr,             // 12
        ...nonce         // 13-15
    ];
}

// Quarter Round avec détails des étapes
function performQuarterRoundWithSteps(state, a, b, c, d) {
    const steps = [];
    const temp = [...state];
    
    function pushOp(name, indices, beforeVals, afterVals, detail) {
        steps.push({ 
            op: name, 
            indices: indices.slice(), 
            before: {...beforeVals}, 
            after: {...afterVals}, 
            detail 
        });
    }
    
    let old;
    
    // a += b
    old = temp[a];
    temp[a] = add32(temp[a], temp[b]);
    pushOp('a += b', [a,b], { [a]: old, [b]: temp[b] }, { [a]: temp[a] }, 
        `state[${a}] = 0x${old.toString(16).padStart(8,'0')} + 0x${temp[b].toString(16).padStart(8,'0')} = 0x${temp[a].toString(16).padStart(8,'0')}`);
    
    // d ^= a
    old = temp[d];
    temp[d] ^= temp[a];
    pushOp('d ^= a', [d,a], { [d]: old, [a]: temp[a] }, { [d]: temp[d] }, 
        `state[${d}] = 0x${old.toString(16).padStart(8,'0')} ⊕ 0x${temp[a].toString(16).padStart(8,'0')} = 0x${temp[d].toString(16).padStart(8,'0')}`);
    
    // d <<< 16
    old = temp[d];
    temp[d] = rotl(temp[d], 16);
    pushOp('d <<< 16', [d], { [d]: old }, { [d]: temp[d] }, 
        `state[${d}] = rotl(0x${old.toString(16)},16) = 0x${temp[d].toString(16).padStart(8,'0')}`);
    
    // c += d
    old = temp[c];
    temp[c] = add32(temp[c], temp[d]);
    pushOp('c += d', [c,d], { [c]: old, [d]: temp[d] }, { [c]: temp[c] }, 
        `state[${c}] = 0x${old.toString(16).padStart(8,'0')} + 0x${temp[d].toString(16).padStart(8,'0')} = 0x${temp[c].toString(16).padStart(8,'0')}`);
    
    // b ^= c
    old = temp[b];
    temp[b] ^= temp[c];
    pushOp('b ^= c', [b,c], { [b]: old, [c]: temp[c] }, { [b]: temp[b] }, 
        `state[${b}] = 0x${old.toString(16).padStart(8,'0')} ⊕ 0x${temp[c].toString(16).padStart(8,'0')} = 0x${temp[b].toString(16).padStart(8,'0')}`);
    
    // b <<< 12
    old = temp[b];
    temp[b] = rotl(temp[b], 12);
    pushOp('b <<< 12', [b], { [b]: old }, { [b]: temp[b] }, 
        `state[${b}] = rotl(0x${old.toString(16)},12) = 0x${temp[b].toString(16).padStart(8,'0')}`);
    
    // a += b (2)
    old = temp[a];
    temp[a] = add32(temp[a], temp[b]);
    pushOp('a += b', [a,b], { [a]: old, [b]: temp[b] }, { [a]: temp[a] }, 
        `state[${a}] = 0x${old.toString(16).padStart(8,'0')} + 0x${temp[b].toString(16).padStart(8,'0')} = 0x${temp[a].toString(16).padStart(8,'0')}`);
    
    // d ^= a (2)
    old = temp[d];
    temp[d] ^= temp[a];
    pushOp('d ^= a', [d,a], { [d]: old, [a]: temp[a] }, { [d]: temp[d] }, 
        `state[${d}] = 0x${old.toString(16).padStart(8,'0')} ⊕ 0x${temp[a].toString(16).padStart(8,'0')} = 0x${temp[d].toString(16).padStart(8,'0')}`);
    
    // d <<< 8
    old = temp[d];
    temp[d] = rotl(temp[d], 8);
    pushOp('d <<< 8', [d], { [d]: old }, { [d]: temp[d] }, 
        `state[${d}] = rotl(0x${old.toString(16)},8) = 0x${temp[d].toString(16).padStart(8,'0')}`);
    
    // c += d (2)
    old = temp[c];
    temp[c] = add32(temp[c], temp[d]);
    pushOp('c += d', [c,d], { [c]: old, [d]: temp[d] }, { [c]: temp[c] }, 
        `state[${c}] = 0x${old.toString(16).padStart(8,'0')} + 0x${temp[d].toString(16).padStart(8,'0')} = 0x${temp[c].toString(16).padStart(8,'0')}`);
    
    // b ^= c (2)
    old = temp[b];
    temp[b] ^= temp[c];
    pushOp('b ^= c', [b,c], { [b]: old, [c]: temp[c] }, { [b]: temp[b] }, 
        `state[${b}] = 0x${old.toString(16).padStart(8,'0')} ⊕ 0x${temp[c].toString(16).padStart(8,'0')} = 0x${temp[b].toString(16).padStart(8,'0')}`);
    
    // b <<< 7
    old = temp[b];
    temp[b] = rotl(temp[b], 7);
    pushOp('b <<< 7', [b], { [b]: old }, { [b]: temp[b] }, 
        `state[${b}] = rotl(0x${old.toString(16)},7) = 0x${temp[b].toString(16).padStart(8,'0')}`);
    
    return { steps, resultState: temp };
}

// Application du Quarter Round
function applyQuarterRound(state, a, b, c, d) {
    state[a] = add32(state[a], state[b]);
    state[d] ^= state[a];
    state[d] = rotl(state[d], 16);
    state[c] = add32(state[c], state[d]);
    state[b] ^= state[c];
    state[b] = rotl(state[b], 12);
    state[a] = add32(state[a], state[b]);
    state[d] ^= state[a];
    state[d] = rotl(state[d], 8);
    state[c] = add32(state[c], state[d]);
    state[b] ^= state[c];
    state[b] = rotl(state[b], 7);
}

// Génération des étapes de visualisation ChaCha20
function generateChaCha20Steps() {
    const steps = [];
    
    // Étape 0: Configuration
    steps.push({
        title: 'Configuration initiale',
        type: 'config',
        mode: chacha20State.mode,
        keyText: chacha20State.keyText,
        keyHex: chacha20State.keyHex,
        keyExtendedNote: chacha20State.keyNote,
        nonce: chacha20State.nonce,
        counter: chacha20State.counter,
        message: chacha20State.message,
        messageText: chacha20State.messageText
    });
    
    // Étape 1: Initialisation de l'état
    const initialState = chacha20Block(chacha20State.keyHex, chacha20State.counter, chacha20State.nonce);
    steps.push({
        title: "Initialisation de l'état ChaCha20 (4×4)",
        type: 'init',
        state: [...initialState]
    });
    
    // 20 rounds = 10 double rounds
    let workingState = [...initialState];
    
    for (let round = 0; round < 10; round++) {
        // Colonnes
        const columnQRs = [[0,4,8,12], [1,5,9,13], [2,6,10,14], [3,7,11,15]];
        for (let i = 0; i < columnQRs.length; i++) {
            const [a,b,c,d] = columnQRs[i];
            const qrDetail = performQuarterRoundWithSteps(workingState, a, b, c, d);
            const stateBefore = [...workingState];
            applyQuarterRound(workingState, a, b, c, d);
            const stateAfter = [...workingState];
            
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
            const qrDetail = performQuarterRoundWithSteps(workingState, a, b, c, d);
            const stateBefore = [...workingState];
            applyQuarterRound(workingState, a, b, c, d);
            const stateAfter = [...workingState];
            
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
    
    // Étape: Addition de l'état initial (AFFICHAGE MATRICIEL)
    const stateAfterRounds = [...workingState];
    const finalState = workingState.map((v, i) => add32(v, initialState[i]));
    
    steps.push({
        title: "Addition de l'état initial à l'état après rounds",
        type: 'add-initial',
        initialState,
        stateAfterRounds,
        finalState
    });
    
    // Étape: Sérialisation en keystream
    const keystream = [];
    finalState.forEach(word => keystream.push(...u32ToBytes(word)));
    
    steps.push({
        title: "Sérialisation en flux de clé (64 octets)",
        type: 'serialize',
        finalState,
        keystream
    });
    
    // Étape: XOR avec le message
    const messageBytes = chacha20State.message;
    const result = messageBytes.map((b, i) => b ^ (keystream[i] || 0));
    
    steps.push({
        title: chacha20State.mode === 'encrypt' ? "XOR du message avec le flux de clé" : "XOR du ciphertext avec le flux de clé (déchiffrement)",
        type: 'xor',
        mode: chacha20State.mode,
        message: messageBytes,
        keystream: keystream.slice(0, messageBytes.length),
        result: result
    });
    
    chacha20State.steps = steps;
}

// Démarrer ChaCha20
function startChaCha20() {
    const modeBtn = document.querySelector('#chacha20 .mode-btn.active');
    const mode = modeBtn ? modeBtn.dataset.mode : 'encrypt';
    
    let messageInput, keyTextInput, nonce;
    
    if (mode === 'encrypt') {
        // Mode chiffrement
        messageInput = document.getElementById('chacha20-message').value || '';
        keyTextInput = document.getElementById('chacha20-key-text').value || '';
        nonce = document.getElementById('chacha20-nonce').value.trim();
        
        if (!messageInput) {
            showError('Veuillez entrer un message à chiffrer');
            return;
        }
        
        if (!keyTextInput) {
            showError('Veuillez entrer une clé');
            return;
        }
        
        // Générer le nonce si vide (optionnel pour le chiffrement)
        if (!nonce || nonce.length !== 24) {
            nonce = bytesToHex(generateRandomNonce());
        } else {
            // Valider le nonce fourni
            const nonceValidation = validateHexNonce(nonce);
            if (!nonceValidation.valid) {
                showError(nonceValidation.error);
                return;
            }
        }
        
    } else {
        // Mode déchiffrement
        const ciphertextInput = document.getElementById('chacha20-ciphertext').value || '';
        keyTextInput = document.getElementById('chacha20-key-text-decrypt').value || '';
        nonce = document.getElementById('chacha20-nonce-decrypt').value.trim();
        
        if (!ciphertextInput) {
            showError('Veuillez entrer le ciphertext à déchiffrer');
            return;
        }
        
        if (!keyTextInput) {
            showError('Veuillez entrer la clé de déchiffrement');
            return;
        }
        
        // Le nonce est OBLIGATOIRE pour le déchiffrement
        if (!nonce || nonce.length === 0) {
            showError('Le nonce est obligatoire pour le déchiffrement. Il doit être identique à celui utilisé pour le chiffrement.');
            return;
        }
        
        // Valider le nonce
        const nonceValidation = validateHexNonce(nonce);
        if (!nonceValidation.valid) {
            showError(nonceValidation.error);
            return;
        }
        
        // Valider et convertir le ciphertext
        try {
            messageInput = ciphertextInput;
        } catch (e) {
            showError('Le ciphertext doit être en hexadécimal valide');
            return;
        }
    }
    
    // Convertir le message selon le mode
    let messageBytes;
    if (mode === 'encrypt') {
        messageBytes = textToBytes(messageInput);
    } else {
        // Mode déchiffrement: le message est en hex
        try {
            messageBytes = hexToBytes(messageInput);
        } catch (e) {
            showError('Le ciphertext doit être en hexadécimal valide');
            return;
        }
    }
    
    // Normaliser la clé
    const normalized = normalizeKeyTextTo32Bytes(keyTextInput);
    
    chacha20State = {
        currentStep: 0,
        steps: [],
        quarterRoundSteps: {},
        mode: mode,
        message: messageBytes,
        messageText: messageInput,
        keyText: keyTextInput,
        keyHex: normalized.keyHex,
        keyNote: normalized.note,
        keyBytes: normalized.keyBytes,
        nonce: nonce,
        counter: 1
    };
    
    generateChaCha20Steps();
    
    document.getElementById('chacha20-inputs').classList.add('hidden');
    document.getElementById('chacha20-viz').classList.remove('hidden');
    displayChaCha20Step(0);
}

// Afficher une étape ChaCha20
function displayChaCha20Step(stepIndex) {
    const step = chacha20State.steps[stepIndex];
    const content = document.getElementById('chacha20-content');
    const titleEl = document.getElementById('chacha20-step-title');
    const progress = document.getElementById('chacha20-progress');
    
    titleEl.textContent = step.title;
    const percent = Math.round((stepIndex / (chacha20State.steps.length - 1)) * 100);
    progress.style.width = percent + '%';
    progress.textContent = percent + '%';
    
    let html = '';
    
    if (step.type === 'config') {
        html += displayOperation('🔧 Configuration', `
            <p><strong>Mode:</strong> ${step.mode === 'encrypt' ? '🔐 Chiffrement' : '🔓 Déchiffrement'}</p>
            <p><strong>${step.mode === 'encrypt' ? 'Message' : 'Ciphertext (hex)'}:</strong></p>
            <pre>${step.messageText}</pre>
            <p><strong>Clé texte fournie:</strong> "${step.keyText || '(vide)'}"</p>
            <p><strong>Clé convertie (32 octets en hex):</strong></p>
            ${displayBytes(chacha20State.keyBytes)}
            <p style="margin-top:8px; color:#555;"><em>${step.keyExtendedNote}</em></p>
            <p><strong>Nonce (12 octets en hex):</strong></p>
            ${displayBytes(hexToBytes(step.nonce))}
            <div class="info-box" style="margin-top:8px;">
                <strong>ℹ️ Rappel:</strong> ChaCha20 utilise la même opération pour chiffrer et déchiffrer (XOR avec le flux de clé).
                ${step.mode === 'decrypt' ? '<br><strong>⚠️ Important:</strong> La clé et le nonce doivent être identiques à ceux utilisés pour le chiffrement.' : ''}
            </div>
        `);
    }
    else if (step.type === 'init') {
        html += displayOperation('🎯 État initial (4×4 mots de 32 bits)', 
            '<p>Constantes "expand 32-byte k", clé, compteur, nonce</p>');
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
        const key = 'qr' + stepIndex;
        if (!chacha20State.quarterRoundSteps[key]) chacha20State.quarterRoundSteps[key] = 0;
        const opIndex = chacha20State.quarterRoundSteps[key];
        
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
                <button class="btn btn-secondary" ${opIndex === 0 ? 'disabled' : ''} onclick="prevQROp(${stepIndex})">⬅️ Op. précédente</button>
                <button class="btn btn-primary" onclick="nextQROp(${stepIndex})">${opIndex === step.qrSteps.length - 1 ? 'Terminer QR' : 'Op. suivante'} ➡️</button>
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
        
        // Résultat final
        const resultEl = document.getElementById('chacha20-result');
        resultEl.classList.remove('hidden');
        if (isEncrypt) {
            resultEl.innerHTML = `
                <h3>✅ Chiffrement ChaCha20 terminé</h3>
                <p><strong>Message original:</strong></p>
                <pre>"${bytesToText(step.message)}"</pre>
                <p><strong>Ciphertext (hex):</strong></p>
                <pre>${bytesToHex(step.result)}</pre>
                <p><strong>Nonce utilisé (conservez-le pour le déchiffrement):</strong></p>
                <pre>${chacha20State.nonce}</pre>
                <div class="info-box" style="margin-top:8px;">
                    <strong>🔐 Important:</strong> Pour déchiffrer, vous aurez besoin de:
                    <ul style="margin-top:8px;">
                        <li>La même clé ("${chacha20State.keyText}")</li>
                        <li>Le même nonce (${chacha20State.nonce})</li>
                        <li>Le ciphertext ci-dessus</li>
                    </ul>
                </div>
            `;
        } else {
            resultEl.innerHTML = `
                <h3>✅ Déchiffrement ChaCha20 terminé</h3>
                <p><strong>Ciphertext (hex):</strong></p>
                <pre>${bytesToHex(step.message)}</pre>
                <p><strong>Message déchiffré:</strong></p>
                <pre>"${bytesToText(step.result)}"</pre>
                <div class="info-box" style="margin-top:8px;">
                    <strong>🔓 Info:</strong> Le déchiffrement utilise la même opération XOR que le chiffrement.
                    La symétrie de l'opération XOR permet de retrouver le message original.
                </div>
            `;
        }
    }
    
    content.innerHTML = html;
    
    document.getElementById('chacha20-prev').disabled = stepIndex === 0;
    document.getElementById('chacha20-next').disabled = stepIndex === chacha20State.steps.length - 1;
}

// Navigation dans les opérations du Quarter Round
function nextQROp(stepIndex) {
    const key = 'qr' + stepIndex;
    const step = chacha20State.steps[stepIndex];
    if (chacha20State.quarterRoundSteps[key] < step.qrSteps.length - 1) {
        chacha20State.quarterRoundSteps[key]++;
        displayChaCha20Step(stepIndex);
    } else {
        // Terminer le QR et passer à l'étape suivante
        chacha20State.quarterRoundSteps[key] = step.qrSteps.length;
        displayChaCha20Step(stepIndex);
    }
}

function prevQROp(stepIndex) {
    const key = 'qr' + stepIndex;
    if (chacha20State.quarterRoundSteps[key] > 0) {
        chacha20State.quarterRoundSteps[key]--;
        displayChaCha20Step(stepIndex);
    }
}

// Navigation entre les étapes
function nextStepChaCha20() {
    const currentStep = chacha20State.steps[chacha20State.currentStep];
    
    if (currentStep.type === 'quarter-round') {
        const key = 'qr' + chacha20State.currentStep;
        if (chacha20State.quarterRoundSteps[key] < currentStep.qrSteps.length) {
            // Finir les opérations du QR avant de passer à l'étape suivante
            chacha20State.quarterRoundSteps[key] = currentStep.qrSteps.length;
            displayChaCha20Step(chacha20State.currentStep);
            return;
        }
    }
    
    if (chacha20State.currentStep < chacha20State.steps.length - 1) {
        chacha20State.currentStep++;
        displayChaCha20Step(chacha20State.currentStep);
    }
}

function prevStepChaCha20() {
    if (chacha20State.currentStep > 0) {
        chacha20State.currentStep--;
        const key = 'qr' + chacha20State.currentStep;
        chacha20State.quarterRoundSteps[key] = 0;
        displayChaCha20Step(chacha20State.currentStep);
    }
}

function resetChaCha20() {
    // Arrêter l'autoplay s'il est actif
    if (chacha20State.autoplayTimer) {
        clearInterval(chacha20State.autoplayTimer);
        chacha20State.autoplay = false;
        const autoBtn = document.getElementById('chacha20-auto');
        if (autoBtn) autoBtn.textContent = '▶️ Auto';
    }
    
    chacha20State = { currentStep: 0, steps: [], quarterRoundSteps: {}, mode: 'encrypt' };
    document.getElementById('chacha20-inputs').classList.remove('hidden');
    document.getElementById('chacha20-viz').classList.add('hidden');
    document.getElementById('chacha20-result').classList.add('hidden');
}

// Fonction Auto pour parcourir automatiquement les quarter rounds
function toggleChaChaAutoplay() {
    const autoBtn = document.getElementById('chacha20-auto');
    
    if (chacha20State.autoplay) {
        // Arrêter l'autoplay
        clearInterval(chacha20State.autoplayTimer);
        chacha20State.autoplay = false;
        autoBtn.textContent = '▶️ Auto';
        autoBtn.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
    } else {
        // Démarrer l'autoplay
        const qrSteps = [];
        chacha20State.steps.forEach((step, idx) => {
            if (step.type === 'quarter-round') {
                qrSteps.push(idx);
            }
        });
        
        if (qrSteps.length === 0) {
            alert('Aucun quarter-round à visualiser automatiquement.');
            return;
        }
        
        chacha20State.autoplay = true;
        autoBtn.textContent = '⏸️ Pause';
        autoBtn.style.background = 'linear-gradient(135deg, #dc3545 0%, #c82333 100%)';
        
        let qrIndex = 0;
        
        function playNextQR() {
            if (qrIndex >= qrSteps.length) {
                // Terminé
                clearInterval(chacha20State.autoplayTimer);
                chacha20State.autoplay = false;
                autoBtn.textContent = '▶️ Auto';
                autoBtn.style.background = 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)';
                
                // Aller à la dernière étape
                chacha20State.currentStep = chacha20State.steps.length - 1;
                displayChaCha20Step(chacha20State.currentStep);
                return;
            }
            
            const stepIdx = qrSteps[qrIndex];
            chacha20State.currentStep = stepIdx;
            const step = chacha20State.steps[stepIdx];
            const key = 'qr' + stepIdx;
            
            // Réinitialiser les opérations de ce QR
            chacha20State.quarterRoundSteps[key] = 0;
            
            // Parcourir toutes les opérations du QR
            let opIdx = 0;
            const opTimer = setInterval(() => {
                chacha20State.quarterRoundSteps[key] = opIdx;
                displayChaCha20Step(stepIdx);
                
                opIdx++;
                if (opIdx > step.qrSteps.length) {
                    clearInterval(opTimer);
                    qrIndex++;
                    
                    // Petite pause avant le prochain QR
                    setTimeout(() => {
                        if (chacha20State.autoplay) {
                            playNextQR();
                        }
                    }, 400);
                }
            }, 500); // 500ms entre chaque opération
        }
        
        // Démarrer
        playNextQR();
    }
}
