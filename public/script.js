// Tab switching
document.querySelectorAll('.tab-button').forEach(button => {
    button.addEventListener('click', () => {
        const tabName = button.dataset.tab;
        
        // Update buttons
        document.querySelectorAll('.tab-button').forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Update content
        document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));
        document.getElementById(tabName).classList.add('active');
    });
});

// Template selection
const templates = {
    webserver: {
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['serverAuth']
    },
    codesigning: {
        keyUsage: ['digitalSignature'],
        extendedKeyUsage: ['codeSigning']
    },
    email: {
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['emailProtection']
    },
    clientauth: {
        keyUsage: ['digitalSignature', 'keyEncipherment'],
        extendedKeyUsage: ['clientAuth']
    },
    custom: {
        keyUsage: [],
        extendedKeyUsage: []
    }
};

document.querySelectorAll('.template-card').forEach(card => {
    card.addEventListener('click', () => {
        document.querySelectorAll('.template-card').forEach(c => c.classList.remove('selected'));
        card.classList.add('selected');
        
        const template = card.dataset.template;
        applyTemplate(templates[template]);
    });
});

function applyTemplate(template) {
    // Reset all checkboxes
    document.querySelectorAll('input[name="keyUsage"]').forEach(cb => cb.checked = false);
    document.querySelectorAll('input[name="extendedKeyUsage"]').forEach(cb => cb.checked = false);
    
    // Apply template
    template.keyUsage.forEach(ku => {
        const checkbox = document.querySelector(`input[name="keyUsage"][value="${ku}"]`);
        if (checkbox) checkbox.checked = true;
    });
    
    template.extendedKeyUsage.forEach(eku => {
        const checkbox = document.querySelector(`input[name="extendedKeyUsage"][value="${eku}"]`);
        if (checkbox) checkbox.checked = true;
    });
}

// Key type switching
document.getElementById('keyType').addEventListener('change', (e) => {
    const keySizeGroup = document.getElementById('keySizeGroup');
    const curveNameGroup = document.getElementById('curveNameGroup');
    
    if (e.target.value === 'ECDSA') {
        keySizeGroup.classList.add('hidden');
        curveNameGroup.classList.remove('hidden');
    } else {
        keySizeGroup.classList.remove('hidden');
        curveNameGroup.classList.add('hidden');
    }
});

// SAN Management
function addSAN() {
    const container = document.getElementById('sanContainer');
    const entry = document.createElement('div');
    entry.className = 'san-entry';
    entry.innerHTML = `
        <select class="san-type">
            <option value="DNS">DNS</option>
            <option value="IP">IP Address</option>
            <option value="email">Email</option>
            <option value="URI">URI</option>
        </select>
        <input type="text" class="san-value" placeholder="example.com">
        <button type="button" class="btn-remove btn-remove-san">Remove</button>
    `;
    container.appendChild(entry);
    
    // Attach event listener to the new remove button
    const removeBtn = entry.querySelector('.btn-remove-san');
    removeBtn.addEventListener('click', function() {
        removeSAN(this);
    });
}

function removeSAN(button) {
    const container = document.getElementById('sanContainer');
    if (container.children.length > 1) {
        button.parentElement.remove();
    }
}

// Custom EKU Management
const customEKUs = [];

function addCustomEKU() {
    const input = document.getElementById('customEKU');
    const oid = input.value.trim();
    
    if (!oid) return;
    
    // Validate OID format: numeric components separated by dots, no leading/trailing/consecutive dots, at least two components
    if (!/^\d+(\.\d+)+$/.test(oid)) {
        showError('Invalid OID format. Use format like 1.2.3.4.5 (dot-separated numbers, at least two components)');
        return;
    }
    
    if (customEKUs.includes(oid)) {
        showError('This OID is already added');
        return;
    }
    
    customEKUs.push(oid);
    updateCustomEKUList();
    input.value = '';
}

function removeCustomEKU(oid) {
    const index = customEKUs.indexOf(oid);
    if (index > -1) {
        customEKUs.splice(index, 1);
        updateCustomEKUList();
    }
}

function updateCustomEKUList() {
    const list = document.getElementById('customEKUList');
    list.innerHTML = customEKUs.map(oid => `
        <div class="custom-eku-item" data-oid="${oid}">
            <code>${oid}</code>
            <button type="button" class="btn-remove btn-remove-eku">Remove</button>
        </div>
    `).join('');
    
    // Attach event listeners to remove buttons
    list.querySelectorAll('.btn-remove-eku').forEach(btn => {
        btn.addEventListener('click', function() {
            const oid = this.closest('.custom-eku-item').dataset.oid;
            removeCustomEKU(oid);
        });
    });
}

// Form submission
document.getElementById('csrForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    // Collect form data
    const formData = {
        keyType: document.getElementById('keyType').value,
        keySize: document.getElementById('keySize').value,
        curveName: document.getElementById('curveName').value,
        commonName: document.getElementById('commonName').value,
        organization: document.getElementById('organization').value,
        organizationalUnit: document.getElementById('organizationalUnit').value,
        locality: document.getElementById('locality').value,
        state: document.getElementById('state').value,
        country: document.getElementById('country').value.toUpperCase(),
        email: document.getElementById('email').value,
        password: document.getElementById('password').value
    };
    
    // Collect SANs
    formData.subjectAltNames = [];
    document.querySelectorAll('.san-entry').forEach(entry => {
        const type = entry.querySelector('.san-type').value;
        const value = entry.querySelector('.san-value').value.trim();
        if (value) {
            formData.subjectAltNames.push({ type, value });
        }
    });
    
    // Collect Key Usage
    formData.keyUsage = [];
    document.querySelectorAll('input[name="keyUsage"]:checked').forEach(cb => {
        formData.keyUsage.push(cb.value);
    });
    
    // Collect Extended Key Usage
    formData.extendedKeyUsage = [];
    document.querySelectorAll('input[name="extendedKeyUsage"]:checked').forEach(cb => {
        formData.extendedKeyUsage.push(cb.value);
    });
    
    // Add custom EKUs
    formData.extendedKeyUsage.push(...customEKUs);
    
    try {
        // Show loading
        const submitBtn = e.target.querySelector('button[type="submit"]');
        const originalText = submitBtn.textContent;
        submitBtn.textContent = 'Generating...';
        submitBtn.disabled = true;
        
        const response = await fetch('/api/generate', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(formData)
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to generate CSR');
        }
        
        // Display results
        document.getElementById('csrOutput').value = data.csr;
        document.getElementById('privateKeyOutput').value = data.privateKey;
        document.getElementById('resultSection').classList.remove('hidden');
        
        // Scroll to results
        document.getElementById('resultSection').scrollIntoView({ behavior: 'smooth' });
        
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
        
    } catch (error) {
        showError(error.message);
        const submitBtn = e.target.querySelector('button[type="submit"]');
        submitBtn.textContent = 'Generate CSR';
        submitBtn.disabled = false;
    }
});

// Download functions
function downloadCSR() {
    const csr = document.getElementById('csrOutput').value;
    const cn = document.getElementById('commonName').value || 'certificate';
    download(csr, `${sanitizeFilename(cn)}.csr`, 'application/x-pem-file');
}

function downloadPrivateKey() {
    const key = document.getElementById('privateKeyOutput').value;
    const cn = document.getElementById('commonName').value || 'certificate';
    download(key, `${sanitizeFilename(cn)}.key`, 'application/x-pem-file');
}

function download(content, filename, contentType) {
    const blob = new Blob([content], { type: contentType });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
}

function sanitizeFilename(name) {
    return name.replaceAll(/[^a-z0-9]/gi, '_').toLowerCase();
}

function copyToClipboard(elementId, buttonElement) {
    const element = document.getElementById(elementId);
    if (!element) {
        showError('Unable to find the text to copy. Please copy it manually (Ctrl/Cmd+C).');
        return;
    }
    const text = element.value;
    
    // Use modern Clipboard API (supported in all modern browsers)
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        navigator.clipboard.writeText(text).then(() => {
            showCopyFeedback(buttonElement);
        }).catch(() => {
            showError('Your browser blocked automatic copying. Please copy the text manually (select it and press Ctrl/Cmd+C).');
        });
    } else {
        showError('Your browser does not support automatic copying. Please copy the text manually (select it and press Ctrl/Cmd+C).');
    }
}

function showCopyFeedback(buttonElement) {
    if (buttonElement) {
        const originalText = buttonElement.textContent;
        buttonElement.textContent = 'Copied!';
        setTimeout(() => {
            buttonElement.textContent = originalText;
        }, 2000);
    }
}

function showError(message) {
    // Create or update error message element
    let errorDiv = document.getElementById('global-error');
    if (!errorDiv) {
        errorDiv = document.createElement('div');
        errorDiv.id = 'global-error';
        errorDiv.className = 'error-box';
        errorDiv.style.position = 'fixed';
        errorDiv.style.top = '20px';
        errorDiv.style.right = '20px';
        errorDiv.style.zIndex = '1000';
        errorDiv.style.maxWidth = '400px';
        document.body.appendChild(errorDiv);
    }
    errorDiv.innerHTML = `<strong>Error:</strong> ${message}`;
    errorDiv.style.display = 'block';
    
    setTimeout(() => {
        errorDiv.style.display = 'none';
    }, 5000);
}

// CSR Analyzer
async function analyzeCSR() {
    const csrInput = document.getElementById('csrInput').value.trim();
    
    if (!csrInput) {
        showError('Please paste a CSR to analyze');
        return;
    }
    
    try {
        const response = await fetch('/api/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ csr: csrInput })
        });
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to analyze CSR');
        }
        
        displayAnalysis(data);
        
    } catch (error) {
        const resultDiv = document.getElementById('analysisResult');
        resultDiv.classList.remove('hidden');
        document.getElementById('analysisContent').innerHTML = `
            <div class="error-box">
                <strong>Error:</strong> ${error.message}
            </div>
        `;
    }
}

function displayAnalysis(data) {
    const resultDiv = document.getElementById('analysisResult');
    resultDiv.classList.remove('hidden');
    
    let html = '';
    
    // Verification status
    html += `<div class="${data.verified ? 'success-box' : 'error-box'}">
        <strong>Signature Verification:</strong> ${data.verified ? '✓ Valid' : '✗ Invalid'}
    </div>`;
    
    // Three-column grid for analysis sections
    html += '<div class="analysis-grid">';
    
    // Subject information
    html += `<div class="analysis-section">
        <h3>Subject Information</h3>
        <dl class="info-list">`;
    
    for (const [key, value] of Object.entries(data.subject)) {
        html += `<div class="info-item"><dt>${formatFieldName(key)}</dt><dd><code>${value}</code></dd></div>`;
    }
    
    html += `</dl></div>`;
    
    // Public Key
    html += `<div class="analysis-section">
        <h3>Public Key Information</h3>
        <dl class="info-list">
            <div class="info-item"><dt>Algorithm</dt><dd><code>${data.publicKey.type}</code></dd></div>
            <div class="info-item"><dt>Key Size</dt><dd><code>${data.publicKey.bits} bits</code></dd></div>
            <div class="info-item"><dt>Signature Algorithm</dt><dd><code>${data.signatureAlgorithm}</code></dd></div>
        </dl>
    </div>`;
    
    // Extensions
    if (Object.keys(data.extensions).length > 0) {
        html += `<div class="analysis-section">
            <h3>Extensions</h3>`;
        
        // Key Usage
        if (data.extensions.keyUsage) {
            html += `<h4>Key Usage</h4><ul>`;
            data.extensions.keyUsage.forEach(ku => {
                html += `<li>${formatFieldName(ku)}</li>`;
            });
            html += `</ul>`;
        }
        
        // Extended Key Usage
        if (data.extensions.extendedKeyUsage) {
            html += `<h4>Extended Key Usage</h4><div class="eku-list">`;
            const ekuNames = {
                '1.3.6.1.5.5.7.3.1': 'TLS Web Server Authentication',
                '1.3.6.1.5.5.7.3.2': 'TLS Web Client Authentication',
                '1.3.6.1.5.5.7.3.3': 'Code Signing',
                '1.3.6.1.5.5.7.3.4': 'Email Protection',
                '1.3.6.1.5.5.7.3.8': 'Time Stamping',
                '1.3.6.1.5.5.7.3.9': 'OCSP Signing',
                '1.3.6.1.4.1.311.10.3.3': 'Microsoft Server Gated Crypto',
                '2.16.840.1.113730.4.1': 'Netscape Server Gated Crypto'
            };
            data.extensions.extendedKeyUsage.forEach(eku => {
                const name = ekuNames[eku] || 'Custom OID';
                html += `<div class="eku-item"><span class="eku-name">${name}</span><span class="eku-oid">${eku}</span></div>`;
            });
            html += `</div>`;
        }
        
        // Subject Alternative Names
        if (data.extensions.subjectAltName) {
            html += `<h4>Subject Alternative Names</h4><ul>`;
            data.extensions.subjectAltName.forEach(san => {
                const typeNames = { 1: 'Email', 2: 'DNS', 6: 'URI', 7: 'IP' };
                html += `<li><strong>${typeNames[san.type] || 'Type ' + san.type}:</strong> <code>${san.value}</code></li>`;
            });
            html += `</ul>`;
        }
        
        html += `</div>`;
    }
    
    html += '</div>'; // Close analysis-grid
    
    document.getElementById('analysisContent').innerHTML = html;
    resultDiv.scrollIntoView({ behavior: 'smooth' });
}

function formatFieldName(name) {
    // Convert camelCase or snake_case to Title Case
    return name
        .replaceAll(/([A-Z])/g, ' $1')
        .replaceAll('_', ' ')
        .replace(/^./, str => str.toUpperCase())
        .trim();
}

// Initialize with web server template selected
const webserverCard = document.querySelector('.template-card[data-template="webserver"]');
if (webserverCard) {
    webserverCard.classList.add('selected');
    applyTemplate(templates.webserver);
}

// Event listeners for buttons (removed from inline onclick handlers for better separation of concerns)
document.getElementById('addSanBtn').addEventListener('click', addSAN);
document.getElementById('addCustomEkuBtn').addEventListener('click', addCustomEKU);
document.getElementById('downloadCsrBtn').addEventListener('click', downloadCSR);
document.getElementById('downloadKeyBtn').addEventListener('click', downloadPrivateKey);
document.getElementById('copyCsrBtn').addEventListener('click', function() {
    copyToClipboard('csrOutput', this);
});
document.getElementById('copyKeyBtn').addEventListener('click', function() {
    copyToClipboard('privateKeyOutput', this);
});
document.getElementById('analyzeCsrBtn').addEventListener('click', analyzeCSR);

// Attach event listener to the initial SAN remove button
document.querySelectorAll('#sanContainer .btn-remove-san').forEach(btn => {
    btn.addEventListener('click', function() {
        removeSAN(this);
    });
});

// Theme toggle functionality
function initTheme() {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme) {
        document.documentElement.dataset.theme = savedTheme;
        updateThemeIcon(savedTheme);
    }
    // Default is dark (no data-theme attribute = dark mode from CSS :root)
}

function toggleTheme() {
    const currentTheme = document.documentElement.dataset.theme;
    const newTheme = currentTheme === 'light' ? null : 'light';
    
    if (newTheme) {
        document.documentElement.dataset.theme = newTheme;
        localStorage.setItem('theme', newTheme);
    } else {
        delete document.documentElement.dataset.theme;
        localStorage.setItem('theme', 'dark');
    }
    updateThemeIcon(newTheme || 'dark');
}

function updateThemeIcon(theme) {
    const icon = document.querySelector('.theme-icon');
    if (icon) {
        icon.textContent = theme === 'light' ? '🌙' : '☀️';
    }
}

// Initialize theme and attach toggle listener
initTheme();
document.getElementById('themeToggle').addEventListener('click', toggleTheme);
