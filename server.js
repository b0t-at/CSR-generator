const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const crypto = require('node:crypto');
const x509 = require('@peculiar/x509');

// Set crypto provider for @peculiar/x509
x509.cryptoProvider.set(crypto.webcrypto);

// ============================================================================
// Validation Helper Functions
// ============================================================================

function validateCommonName(commonName) {
  if (!commonName?.trim()) {
    return { valid: false, error: 'Common Name (CN) is required' };
  }
  if (commonName.length > 64) {
    return { valid: false, error: 'Common Name must be 64 characters or less' };
  }
  return { valid: true };
}

function validateCountry(country) {
  if (country && !/^[A-Z]{2}$/.test(country)) {
    return { valid: false, error: 'Country must be a 2-letter uppercase ISO code (e.g., US, GB)' };
  }
  return { valid: true };
}

function validatePassword(password) {
  if (!password) return { valid: true };
  
  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters long' };
  }
  
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumber = /\d/.test(password);
  const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
  
  const strengthCount = [hasUpperCase, hasLowerCase, hasNumber, hasSpecialChar].filter(Boolean).length;
  if (strengthCount < 3) {
    return { 
      valid: false, 
      error: 'Password must contain at least 3 of: uppercase letters, lowercase letters, numbers, special characters' 
    };
  }
  return { valid: true };
}

function validateEmail(email) {
  if (!email) return { valid: true };
  // Limit length to prevent ReDoS and use atomic-like pattern
  if (email.length > 254) {
    return { valid: false, error: 'Email address too long' };
  }
  // Simple email validation: local@domain format with length limits
  const atIndex = email.indexOf('@');
  if (atIndex < 1 || atIndex > 64) {
    return { valid: false, error: 'Invalid email address format' };
  }
  const local = email.slice(0, atIndex);
  const domain = email.slice(atIndex + 1);
  if (!local || !domain || domain.indexOf('.') < 1 || /\s/.test(email)) {
    return { valid: false, error: 'Invalid email address format' };
  }
  return { valid: true };
}

function validateDNSName(value) {
  if (value.length > 253 || value.length < 1) {
    return false;
  }
  const labels = value.split('.');
  for (const label of labels) {
    if (label.length === 0 || label.length > 63) {
      return false;
    }
    // Allow wildcard only as first character of first label
    if (label === '*' && labels.indexOf(label) === 0) {
      continue;
    }
    if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(label) && !/^[a-zA-Z0-9]$/.test(label)) {
      return false;
    }
  }
  return true;
}

function validateIPAddress(value) {
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
  const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
  return ipv4.test(value) || ipv6.test(value);
}

function validateEmailFormat(value) {
  if (value.length > 254) return false;
  const atIndex = value.indexOf('@');
  if (atIndex < 1) return false;
  const domain = value.slice(atIndex + 1);
  return domain && domain.indexOf('.') >= 1 && !/\s/.test(value);
}

function validateURI(value) {
  try {
    new URL(value);
    return true;
  } catch {
    return false;
  }
}

function validateSAN(san) {
  const value = san.value.trim();
  
  if (san.type === 'DNS' && !validateDNSName(value)) {
    return { valid: false, error: `Invalid DNS name in SAN: ${value}` };
  }
  if (san.type === 'IP' && !validateIPAddress(value)) {
    return { valid: false, error: `Invalid IP address in SAN: ${value}` };
  }
  if (san.type === 'email' && !validateEmailFormat(value)) {
    return { valid: false, error: `Invalid email in SAN: ${value}` };
  }
  if (san.type === 'URI' && !validateURI(value)) {
    return { valid: false, error: `Invalid URI in SAN: ${value}` };
  }
  return { valid: true };
}

// ============================================================================
// Key Generation Helper Functions
// ============================================================================

async function generateKeyPair(keyType, keySize, curveName) {
  if (keyType === 'ECDSA') {
    const curveMap = {
      'prime256v1': 'P-256', 'secp384r1': 'P-384', 'secp521r1': 'P-521',
      'P-256': 'P-256', 'P-384': 'P-384', 'P-521': 'P-521'
    };
    const curve = curveMap[curveName] || 'P-256';
    
    const keys = await crypto.webcrypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: curve },
      true,
      ['sign', 'verify']
    );
    return { keys, signingAlgorithm: { name: 'ECDSA', namedCurve: curve, hash: 'SHA-256' } };
  }
  
  // RSA
  const bits = Number.parseInt(keySize) || 2048;
  const keys = await crypto.webcrypto.subtle.generateKey(
    {
      name: 'RSASSA-PKCS1-v1_5',
      modulusLength: bits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['sign', 'verify']
  );
  return { keys, signingAlgorithm: { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' } };
}

// ============================================================================
// CSR Building Helper Functions
// ============================================================================

function buildSubjectDN({ country, state, locality, organization, organizationalUnit, commonName, email }) {
  const subjectParts = [];
  if (country) subjectParts.push(`C=${country}`);
  if (state) subjectParts.push(`ST=${state}`);
  if (locality) subjectParts.push(`L=${locality}`);
  if (organization) subjectParts.push(`O=${organization}`);
  if (organizationalUnit) subjectParts.push(`OU=${organizationalUnit}`);
  subjectParts.push(`CN=${commonName}`);
  if (email) subjectParts.push(`E=${email}`);
  return subjectParts.join(', ');
}

function buildKeyUsageExtension(keyUsage) {
  const flagMap = {
    'digitalSignature': x509.KeyUsageFlags.digitalSignature,
    'nonRepudiation': x509.KeyUsageFlags.nonRepudiation,
    'keyEncipherment': x509.KeyUsageFlags.keyEncipherment,
    'dataEncipherment': x509.KeyUsageFlags.dataEncipherment,
    'keyAgreement': x509.KeyUsageFlags.keyAgreement,
    'keyCertSign': x509.KeyUsageFlags.keyCertSign,
    'cRLSign': x509.KeyUsageFlags.cRLSign,
    'encipherOnly': x509.KeyUsageFlags.encipherOnly,
    'decipherOnly': x509.KeyUsageFlags.decipherOnly
  };
  
  let flags = 0;
  for (const usage of keyUsage) {
    if (flagMap[usage]) flags |= flagMap[usage];
  }
  return new x509.KeyUsagesExtension(flags, true);
}

function buildExtendedKeyUsageExtension(extendedKeyUsage) {
  const ekuMap = {
    'serverAuth': '1.3.6.1.5.5.7.3.1',
    'clientAuth': '1.3.6.1.5.5.7.3.2',
    'codeSigning': '1.3.6.1.5.5.7.3.3',
    'emailProtection': '1.3.6.1.5.5.7.3.4',
    'timeStamping': '1.3.6.1.5.5.7.3.8',
    'OCSPSigning': '1.3.6.1.5.5.7.3.9'
  };
  
  const ekuOids = extendedKeyUsage.map(eku => {
    if (eku.startsWith('1.') || eku.startsWith('2.')) return eku;
    return ekuMap[eku] || eku;
  });
  return new x509.ExtendedKeyUsageExtension(ekuOids, false);
}

function buildSANExtension(validSANs) {
  const typeMap = { 'DNS': 'dns', 'IP': 'ip', 'email': 'email', 'URI': 'url' };
  const sanEntries = validSANs.map(san => ({
    type: typeMap[san.type] || 'dns',
    value: san.value.trim()
  }));
  return new x509.SubjectAlternativeNameExtension(sanEntries, false);
}

async function exportKeysToPem(keys, password) {
  const privateKeyPkcs8 = await crypto.webcrypto.subtle.exportKey('pkcs8', keys.privateKey);
  const publicKeySpki = await crypto.webcrypto.subtle.exportKey('spki', keys.publicKey);
  
  let privateKeyPem = '-----BEGIN PRIVATE KEY-----\n' +
    Buffer.from(privateKeyPkcs8).toString('base64').match(/.{1,64}/g).join('\n') +
    '\n-----END PRIVATE KEY-----';
  
  const publicKeyPem = '-----BEGIN PUBLIC KEY-----\n' +
    Buffer.from(publicKeySpki).toString('base64').match(/.{1,64}/g).join('\n') +
    '\n-----END PUBLIC KEY-----';
  
  if (password) {
    const keyObject = crypto.createPrivateKey({
      key: Buffer.from(privateKeyPkcs8),
      format: 'der',
      type: 'pkcs8'
    });
    privateKeyPem = keyObject.export({
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: password
    });
  }
  
  return { privateKeyPem, publicKeyPem };
}

// ============================================================================
// CSR Analysis Helper Functions
// ============================================================================

function parseSubjectDN(subjectName) {
  const subject = {};
  const keyMap = {
    'CN': 'commonName', 'O': 'organizationName', 'OU': 'organizationalUnitName',
    'L': 'localityName', 'ST': 'stateOrProvinceName', 'C': 'countryName', 'E': 'emailAddress'
  };
  
  const dnParts = subjectName.split(',').map(p => p.trim());
  for (const part of dnParts) {
    const [key, ...valueParts] = part.split('=');
    const value = valueParts.join('=');
    const normalizedKey = keyMap[key.trim()] || key.trim();
    if (value) subject[normalizedKey] = value.trim();
  }
  return subject;
}

function extractPublicKeyInfo(publicKeyAlgorithm) {
  if (publicKeyAlgorithm.name === 'RSASSA-PKCS1-v1_5' || publicKeyAlgorithm.name === 'RSA-PSS') {
    return { type: 'RSA', bits: publicKeyAlgorithm.modulusLength || 0 };
  }
  if (publicKeyAlgorithm.name === 'ECDSA') {
    const curveMap = { 'P-256': 256, 'P-384': 384, 'P-521': 521 };
    return {
      type: 'ECDSA',
      curve: publicKeyAlgorithm.namedCurve,
      bits: curveMap[publicKeyAlgorithm.namedCurve] || 0
    };
  }
  return { type: 'Unknown', bits: 0 };
}

function extractKeyUsageFromExtension(ext) {
  const usages = [];
  const flagMap = [
    ['digitalSignature', x509.KeyUsageFlags.digitalSignature],
    ['nonRepudiation', x509.KeyUsageFlags.nonRepudiation],
    ['keyEncipherment', x509.KeyUsageFlags.keyEncipherment],
    ['dataEncipherment', x509.KeyUsageFlags.dataEncipherment],
    ['keyAgreement', x509.KeyUsageFlags.keyAgreement],
    ['keyCertSign', x509.KeyUsageFlags.keyCertSign],
    ['cRLSign', x509.KeyUsageFlags.cRLSign],
    ['encipherOnly', x509.KeyUsageFlags.encipherOnly],
    ['decipherOnly', x509.KeyUsageFlags.decipherOnly]
  ];
  
  for (const [name, flag] of flagMap) {
    if (ext.usages & flag) usages.push(name);
  }
  return usages;
}

function extractExtensions(csrExtensions) {
  const extensions = {};
  
  for (const ext of csrExtensions) {
    if (ext instanceof x509.KeyUsagesExtension) {
      extensions.keyUsage = extractKeyUsageFromExtension(ext);
    } else if (ext instanceof x509.ExtendedKeyUsageExtension) {
      extensions.extendedKeyUsage = ext.usages;
    } else if (ext instanceof x509.SubjectAlternativeNameExtension) {
      extensions.subjectAltName = ext.names.items.map(name => ({
        type: name.type,
        value: name.value
      }));
    } else {
      extensions[ext.type] = { critical: ext.critical, value: ext.value };
    }
  }
  return extensions;
}

const app = express();
const PORT = process.env.PORT || 3000;

// Trust proxy if behind reverse proxy (e.g., nginx, load balancer)
app.set('trust proxy', 1);

// Rate limiting to prevent abuse
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Stricter rate limit for generation endpoints
const generateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 20, // Limit each IP to 20 CSR generations per windowMs
  message: 'Too many CSR generation requests, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
// Configure CORS to only allow same-origin or specific trusted origins
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : false,
  credentials: true
};
app.use(cors(corsOptions));

app.use(express.json({ limit: '500kb' }));
app.use(express.static('public'));

// Apply rate limiting to API routes
app.use('/api', apiLimiter);

// CSR Generation endpoint
app.post('/api/generate', generateLimiter, async (req, res) => {
  try {
    const {
      keyType, keySize, commonName, organization, organizationalUnit,
      locality, state, country, email, subjectAltNames, keyUsage, extendedKeyUsage, password
    } = req.body;

    // Validate inputs using helper functions
    const validations = [
      validateCommonName(commonName),
      validateCountry(country),
      validatePassword(password),
      validateEmail(email)
    ];
    
    for (const validation of validations) {
      if (!validation.valid) {
        return res.status(400).json({ error: validation.error });
      }
    }

    // Validate SANs
    const validSANs = (subjectAltNames || []).filter(san => san.value?.trim());
    for (const san of validSANs) {
      const sanValidation = validateSAN(san);
      if (!sanValidation.valid) {
        return res.status(400).json({ error: sanValidation.error });
      }
    }

    // Generate key pair
    const { keys, signingAlgorithm } = await generateKeyPair(keyType, keySize, req.body.curveName);
    
    // Build subject DN
    const subjectDN = buildSubjectDN({ country, state, locality, organization, organizationalUnit, commonName, email });
    
    // Build extensions
    const csrExtensions = [];
    if (keyUsage?.length > 0) {
      csrExtensions.push(buildKeyUsageExtension(keyUsage));
    }
    if (extendedKeyUsage?.length > 0) {
      csrExtensions.push(buildExtendedKeyUsageExtension(extendedKeyUsage));
    }
    if (validSANs.length > 0) {
      csrExtensions.push(buildSANExtension(validSANs));
    }
    
    // Create CSR
    const csr = await x509.Pkcs10CertificateRequestGenerator.create({
      name: subjectDN,
      keys: keys,
      signingAlgorithm: signingAlgorithm,
      extensions: csrExtensions
    });
    
    const csrPem = csr.toString('pem');
    const { privateKeyPem, publicKeyPem } = await exportKeysToPem(keys, password);
    
    res.json({ success: true, csr: csrPem, privateKey: privateKeyPem, publicKey: publicKeyPem });

  } catch (error) {
    console.error('CSR Generation Error:', error);
    const isDev = process.env.NODE_ENV === 'development';
    res.status(500).json({ 
      error: 'Failed to generate CSR',
      ...(isDev && { details: error.message })
    });
  }
});

// CSR Analysis endpoint
app.post('/api/analyze', async (req, res) => {
  try {
    const { csr } = req.body;

    if (!csr) {
      return res.status(400).json({ error: 'CSR is required' });
    }

    // Parse CSR using @peculiar/x509
    const csrObj = new x509.Pkcs10CertificateRequest(csr);
    
    // Extract subject, public key info, and extensions using helper functions
    const subject = parseSubjectDN(csrObj.subject);
    const keyInfo = extractPublicKeyInfo(csrObj.publicKey.algorithm);
    const extensions = extractExtensions(csrObj.extensions);

    // Verify signature
    let verified = false;
    try {
      verified = await csrObj.verify();
    } catch {
      verified = false;
    }

    res.json({
      success: true,
      subject,
      publicKey: keyInfo,
      extensions,
      signatureAlgorithm: csrObj.signatureAlgorithm?.name || 'Unknown',
      verified,
      pem: csr
    });

  } catch (error) {
    console.error('CSR Analysis Error:', error);
    const isDev = process.env.NODE_ENV === 'development';
    res.status(500).json({ 
      error: 'Failed to analyze CSR',
      ...(isDev && { details: error.message })
    });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.1.0' });
});

app.listen(PORT, () => {
  console.log(`CSR Generator server running on port ${PORT}`);
  console.log(`Access the application at http://localhost:${PORT}`);
});
