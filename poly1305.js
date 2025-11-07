// ============================================
// POLY1305 - Logique complète
// ============================================

let poly1305State = {
    currentStep: 0,
    steps: [],
    mode: 'tag' // 'tag' ou 'verify'
};

// Clamping de r
function clampR(r) {
    const cl = [...r];
    cl[3] &= 15;
    cl[7] &= 15;
    cl[11] &= 15;
    cl[15] &= 15;
    cl[4] &= 252;
    cl[8] &= 252;
    cl[12] &= 252;
    return cl;
}

// Génération des étapes Poly1305
function generatePoly1305Steps() {
    const steps = [];
    const mode = poly1305State.mode;
    
    // Étape 0: Configuration
    steps.push({
        title: mode === 'tag' ? 'Configuration - Calcul du tag' : 'Configuration - Vérification du tag',
        type: 'config',
        mode: mode,
        message: poly1305State.message,
        keyHex: poly1305State.keyHex,
        expectedTag: mode === 'verify' ? poly1305State.expectedTag : null
    });
    
    // Étape 1: Extraction de r et s
    const keyBytes = hexToBytes(poly1305State.keyHex);
    let r = keyBytes.slice(0, 16);
    const s = keyBytes.slice(16, 32);
    
    steps.push({
        title: 'Extraction de r et s depuis la clé (32 octets)',
        type: 'extract',
        key: keyBytes,
        r: [...r],
        s: [...s]
    });
    
    // Étape 2: Clamping de r
    const originalR = [...r];
    r = clampR(r);
    
    steps.push({
        title: 'Clamping (restriction) de r',
        type: 'clamp',
        originalR,
        clampedR: [...r]
    });
    
    // Étape 3: Découpage en blocs
    const messageBytes = poly1305State.message;
    const blocks = [];
    for (let i = 0; i < messageBytes.length; i += 16) {
        blocks.push(messageBytes.slice(i, Math.min(i + 16, messageBytes.length)));
    }
    
    steps.push({
        title: `Découpage du message en blocs de 16 octets`,
        type: 'blocks',
        message: messageBytes,
        blocks
    });
    
    // Étape 4-N: Traitement de chaque bloc
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
            title: `Traitement du bloc ${index + 1}/${blocks.length}`,
            type: 'process-block',
            blockIndex: index,
            block,
            blockNum,
            oldAcc,
            afterAdd,
            afterMul: accumulator,
            r: rBigInt,
            p
        });
    });
    
    // Étape finale: Addition de s et génération du tag
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
        title: 'Addition de s et génération du tag final',
        type: 'final',
        beforeS,
        s,
        sBigInt,
        afterAdd: accumulator,
        tag: tagBytes
    });
    
    // Si mode vérification, ajouter une étape de comparaison
    if (mode === 'verify') {
        const expectedBytes = hexToBytes(poly1305State.expectedTag);
        const isValid = tagBytes.every((b, i) => b === expectedBytes[i]);
        
        steps.push({
            title: 'Vérification du tag',
            type: 'verify',
            computedTag: tagBytes,
            expectedTag: expectedBytes,
            isValid
        });
    }
    
    poly1305State.steps = steps;
}

// Démarrer Poly1305
function startPoly1305() {
    const modeBtn = document.querySelector('#poly1305 .mode-btn.active');
    const mode = modeBtn ? modeBtn.dataset.mode : 'tag';
    
    const message = document.getElementById('poly1305-message').value || '';
    let key = document.getElementById('poly1305-key').value.trim();
    
    if (!message) {
        showError('Veuillez entrer un message');
        return;
    }
    
    // Générer une clé si vide ou invalide
    if (!key || key.length !== 64) {
        key = bytesToHex(generateRandomKey());
    }
    
    // Valider la clé
    const keyValidation = validateHexKey(key, 32);
    if (!keyValidation.valid) {
        showError(keyValidation.error);
        return;
    }
    
    poly1305State = {
        currentStep: 0,
        steps: [],
        mode: mode,
        message: textToBytes(message),
        keyHex: key
    };
    
    // Si mode vérification, récupérer le tag attendu
    if (mode === 'verify') {
        const expectedTag = document.getElementById('poly1305-tag-verify').value.trim();
        if (!expectedTag || expectedTag.length !== 32) {
            showError('Veuillez entrer un tag valide (32 caractères hexadécimaux)');
            return;
        }
        poly1305State.expectedTag = expectedTag;
    }
    
    generatePoly1305Steps();
    
    document.getElementById('poly1305-inputs').classList.add('hidden');
    document.getElementById('poly1305-viz').classList.remove('hidden');
    displayPoly1305Step(0);
}

// Afficher une étape Poly1305
function displayPoly1305Step(i) {
    const step = poly1305State.steps[i];
    const content = document.getElementById('poly1305-content');
    const titleEl = document.getElementById('poly1305-step-title');
    const progress = document.getElementById('poly1305-progress');
    
    titleEl.textContent = step.title;
    const percent = Math.round((i / (poly1305State.steps.length - 1)) * 100);
    progress.style.width = percent + '%';
    progress.textContent = percent + '%';
    
    let html = '';
    
    if (step.type === 'config') {
        html += displayOperation('📋 Configuration Poly1305', `
            <p><strong>Mode:</strong> ${step.mode === 'tag' ? 'Calcul du tag' : 'Vérification du tag'}</p>
            <p><strong>Message:</strong></p>
            <pre>"${bytesToText(step.message)}"</pre>
            <p><strong>Clé Poly1305 (32 octets en hex):</strong></p>
            ${displayBytes(hexToBytes(step.keyHex))}
            ${step.expectedTag ? `<p><strong>Tag attendu:</strong></p>${displayBytes(hexToBytes(step.expectedTag))}` : ''}
            <div class="info-box" style="margin-top:8px;">
                <strong>ℹ️ Info:</strong> Poly1305 produit un tag d'authentification de 16 octets.
            </div>
        `);
    }
    else if (step.type === 'extract') {
        html += displayOperation('🔑 Division de la clé Poly1305', 
            '<p>La clé de 32 octets est divisée en deux parties : r (16 octets) et s (16 octets)</p>');
        html += displayPolyBlock('Clé complète (32 octets)', displayBytes(step.key));
        html += '<div style="display:grid; grid-template-columns:1fr 1fr; gap:10px; margin-top:10px;">';
        html += displayPolyBlock('r (16 octets)', displayBytes(step.r, Array.from({length:16}, (_,i)=>i)));
        html += displayPolyBlock('s (16 octets)', displayBytes(step.s));
        html += '</div>';
    }
    else if (step.type === 'clamp') {
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
    else if (step.type === 'blocks') {
        html += displayOperation('📦 Découpage en blocs', 
            `<p>Le message de ${step.message.length} octets est découpé en blocs de 16 octets maximum.</p>`);
        step.blocks.forEach((blk, j) => {
            html += displayPolyBlock(`Bloc ${j + 1}/${step.blocks.length} (${blk.length} octets)`, 
                displayBytes(blk));
        });
        html += '<div class="info-box" style="margin-top:10px;">' +
            '<strong>Note:</strong> Chaque bloc reçoit un bit de padding (1 ajouté après le dernier octet).</div>';
    }
    else if (step.type === 'process-block') {
        html += displayOperation(`🔄 Traitement du bloc ${step.blockIndex + 1}`, '');
        html += displayPolyBlock(`Bloc ${step.blockIndex + 1} (hex)`, displayBytes(step.block));
        
        html += '<div class="poly-computation" style="margin-top:10px;">';
        html += '<h5>Opérations :</h5>';
        html += `<p>1. Conversion du bloc en nombre (little-endian) + padding bit :</p>`;
        html += `<pre>block_num = 0x${step.blockNum.toString(16)}</pre>`;
        html += `<p>2. Addition à l'accumulateur :</p>`;
        html += `<pre>acc = 0x${step.oldAcc.toString(16)}\nacc += 0x${step.blockNum.toString(16)}\nacc = 0x${step.afterAdd.toString(16)}</pre>`;
        html += `<p>3. Multiplication par r modulo p = 2¹³⁰ - 5 :</p>`;
        html += `<pre>acc = (0x${step.afterAdd.toString(16)} × r) mod p\nacc = 0x${step.afterMul.toString(16)}</pre>`;
        html += '</div>';
    }
    else if (step.type === 'final') {
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
        html += displayPolyBlock('Tag Poly1305 (16 octets)', displayBytes(step.tag));
        
        // Afficher le résultat
        const resultEl = document.getElementById('poly1305-result');
        resultEl.classList.remove('hidden');
        resultEl.innerHTML = `
            <h3>✅ Tag Poly1305 calculé</h3>
            <p><strong>Tag (hex):</strong></p>
            <pre>${bytesToHex(step.tag)}</pre>
            <div class="info-box" style="margin-top:8px;">
                <strong>📝 Info:</strong> Ce tag peut être utilisé pour vérifier l'intégrité et l'authenticité du message.
            </div>
        `;
    }
    else if (step.type === 'verify') {
        html += displayOperation('🔍 Vérification du tag', '');
        html += displayPolyBlock('Tag calculé', displayBytes(step.computedTag));
        html += displayPolyBlock('Tag attendu', displayBytes(step.expectedTag));
        
        if (step.isValid) {
            html += '<div style="background:#d4edda; border:2px solid #28a745; padding:16px; border-radius:8px; margin-top:16px; text-align:center;">';
            html += '<h3 style="color:#155724; margin-bottom:8px;">✅ Tag valide !</h3>';
            html += '<p style="color:#155724;">Le message est authentique et n\'a pas été modifié.</p>';
            html += '</div>';
        } else {
            html += '<div style="background:#f8d7da; border:2px solid #dc3545; padding:16px; border-radius:8px; margin-top:16px; text-align:center;">';
            html += '<h3 style="color:#721c24; margin-bottom:8px;">❌ Tag invalide !</h3>';
            html += '<p style="color:#721c24;">Le message a été modifié ou la clé est incorrecte.</p>';
            html += '</div>';
        }
        
        // Afficher le résultat
        const resultEl = document.getElementById('poly1305-result');
        resultEl.classList.remove('hidden');
        resultEl.innerHTML = `
            <h3>${step.isValid ? '✅ Vérification réussie' : '❌ Vérification échouée'}</h3>
            <p><strong>Tag calculé:</strong> ${bytesToHex(step.computedTag)}</p>
            <p><strong>Tag attendu:</strong> ${bytesToHex(step.expectedTag)}</p>
            <p><strong>Résultat:</strong> ${step.isValid ? 'Les tags correspondent' : 'Les tags ne correspondent pas'}</p>
        `;
    }
    
    content.innerHTML = html;
    
    document.getElementById('poly1305-prev').disabled = i === 0;
    document.getElementById('poly1305-next').disabled = i === poly1305State.steps.length - 1;
}

// Navigation
function nextStepPoly1305() {
    if (poly1305State.currentStep < poly1305State.steps.length - 1) {
        poly1305State.currentStep++;
        displayPoly1305Step(poly1305State.currentStep);
    }
}

function prevStepPoly1305() {
    if (poly1305State.currentStep > 0) {
        poly1305State.currentStep--;
        displayPoly1305Step(poly1305State.currentStep);
    }
}

function resetPoly1305() {
    poly1305State = { currentStep: 0, steps: [], mode: 'tag' };
    document.getElementById('poly1305-inputs').classList.remove('hidden');
    document.getElementById('poly1305-viz').classList.add('hidden');
    document.getElementById('poly1305-result').classList.add('hidden');
}
