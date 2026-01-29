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
        <button type="button" class="btn-remove" onclick="removeSAN(this)">Remove</button>
    `;
    container.appendChild(entry);
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
    
    // Validate OID format
    if (!/^[0-9\.]+$/.test(oid)) {
        showError('Invalid OID format. Use format like 1.2.3.4.5');
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
        <div class="custom-eku-item">
            <code>${oid}</code>
            <button type="button" class="btn-remove" onclick="removeCustomEKU('${oid}')">Remove</button>
        </div>
    `).join('');
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
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function sanitizeFilename(name) {
    return name.replace(/[^a-z0-9]/gi, '_').toLowerCase();
}

function copyToClipboard(elementId, buttonElement) {
    const element = document.getElementById(elementId);
    const text = element.value;
    
    // Use modern Clipboard API
    if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
            showCopyFeedback(buttonElement);
        }).catch(err => {
            // Try fallback
            fallbackCopy(element, buttonElement);
        });
    } else {
        fallbackCopy(element, buttonElement);
    }
}

function fallbackCopy(element, buttonElement) {
    try {
        element.select();
        const success = document.execCommand('copy');
        if (success) {
            showCopyFeedback(buttonElement);
        } else {
            showError('Failed to copy. Please copy manually.');
        }
    } catch (err) {
        showError('Failed to copy. Please copy manually.');
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
        alert('Please paste a CSR to analyze');
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
    
    // Subject information
    html += `<div class="analysis-section">
        <h3>Subject Information</h3>
        <table class="analysis-table">
            <tr><th>Field</th><th>Value</th></tr>`;
    
    for (const [key, value] of Object.entries(data.subject)) {
        html += `<tr><td>${formatFieldName(key)}</td><td><code>${value}</code></td></tr>`;
    }
    
    html += `</table></div>`;
    
    // Public Key
    html += `<div class="analysis-section">
        <h3>Public Key Information</h3>
        <table class="analysis-table">
            <tr><td>Algorithm</td><td><code>${data.publicKey.type}</code></td></tr>
            <tr><td>Key Size</td><td><code>${data.publicKey.bits} bits</code></td></tr>
            <tr><td>Signature Algorithm</td><td><code>${data.signatureAlgorithm}</code></td></tr>
        </table>
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
            html += `<h4>Extended Key Usage</h4><pre>${JSON.stringify(data.extensions.extendedKeyUsage, null, 2)}</pre>`;
        }
        
        // Subject Alternative Names
        if (data.extensions.subjectAltName) {
            html += `<h4>Subject Alternative Names</h4><ul>`;
            data.extensions.subjectAltName.forEach(san => {
                const typeNames = { 1: 'Email', 2: 'DNS', 6: 'URI', 7: 'IP' };
                html += `<li>${typeNames[san.type] || 'Type ' + san.type}: <code>${san.value}</code></li>`;
            });
            html += `</ul>`;
        }
        
        html += `</div>`;
    }
    
    document.getElementById('analysisContent').innerHTML = html;
    resultDiv.scrollIntoView({ behavior: 'smooth' });
}

function formatFieldName(name) {
    // Convert camelCase or snake_case to Title Case
    return name
        .replace(/([A-Z])/g, ' $1')
        .replace(/_/g, ' ')
        .replace(/^./, str => str.toUpperCase())
        .trim();
}

// Initialize with web server template selected
document.querySelector('.template-card[data-template="webserver"]').click();
