const express = require('express');
const forge = require('node-forge');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

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
      keyType,
      keySize,
      commonName,
      organization,
      organizationalUnit,
      locality,
      state,
      country,
      email,
      subjectAltNames,
      keyUsage,
      extendedKeyUsage,
      customExtensions,
      password
    } = req.body;

    // Validate required fields
    if (!commonName || !commonName.trim()) {
      return res.status(400).json({ error: 'Common Name (CN) is required' });
    }
    
    if (commonName.length > 64) {
      return res.status(400).json({ error: 'Common Name must be 64 characters or less' });
    }
    
    if (country && !/^[A-Z]{2}$/.test(country)) {
      return res.status(400).json({ error: 'Country must be a 2-letter uppercase ISO code (e.g., US, GB)' });
    }
    
    // Enhanced password validation
    if (password) {
      if (password.length < 8) {
        return res.status(400).json({ error: 'Password must be at least 8 characters long' });
      }
      // Check for basic password strength
      const hasUpperCase = /[A-Z]/.test(password);
      const hasLowerCase = /[a-z]/.test(password);
      const hasNumber = /[0-9]/.test(password);
      const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);
      
      const strengthCount = [hasUpperCase, hasLowerCase, hasNumber, hasSpecialChar].filter(Boolean).length;
      if (strengthCount < 3) {
        return res.status(400).json({ 
          error: 'Password must contain at least 3 of: uppercase letters, lowercase letters, numbers, special characters' 
        });
      }
    }
    
    // Validate email format if provided
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ error: 'Invalid email address format' });
    }

    // Generate key pair
    let keys;
    if (keyType === 'ECDSA') {
      return res.status(400).json({ 
        error: 'ECDSA key generation is not currently supported. Please use RSA.'
      });
    } else {
      const bits = parseInt(keySize) || 2048;
      keys = forge.pki.rsa.generateKeyPair({ bits });
    }

    // Create CSR
    const csr = forge.pki.createCertificationRequest();
    csr.publicKey = keys.publicKey;

    // Set subject
    const subject = [];
    if (country) subject.push({ name: 'countryName', value: country });
    if (state) subject.push({ name: 'stateOrProvinceName', value: state });
    if (locality) subject.push({ name: 'localityName', value: locality });
    if (organization) subject.push({ name: 'organizationName', value: organization });
    if (organizationalUnit) subject.push({ name: 'organizationalUnitName', value: organizationalUnit });
    subject.push({ name: 'commonName', value: commonName });
    if (email) subject.push({ name: 'emailAddress', value: email });
    
    csr.setSubject(subject);

    // Add extensions
    const extensions = [];

    // Key Usage
    if (keyUsage && keyUsage.length > 0) {
      const keyUsageExt = {
        name: 'keyUsage',
        critical: true,
        digitalSignature: keyUsage.includes('digitalSignature'),
        nonRepudiation: keyUsage.includes('nonRepudiation'),
        keyEncipherment: keyUsage.includes('keyEncipherment'),
        dataEncipherment: keyUsage.includes('dataEncipherment'),
        keyAgreement: keyUsage.includes('keyAgreement'),
        keyCertSign: keyUsage.includes('keyCertSign'),
        cRLSign: keyUsage.includes('cRLSign'),
        encipherOnly: keyUsage.includes('encipherOnly'),
        decipherOnly: keyUsage.includes('decipherOnly')
      };
      extensions.push(keyUsageExt);
    }

    // Extended Key Usage
    if (extendedKeyUsage && extendedKeyUsage.length > 0) {
      // Map EKU selections to OIDs
      const ekuOids = extendedKeyUsage.map(eku => {
        if (eku.startsWith('1.') || eku.startsWith('2.')) {
          return eku; // Custom OID
        }
        // Map common names to OIDs
        const ekuMap = {
          'serverAuth': '1.3.6.1.5.5.7.3.1',
          'clientAuth': '1.3.6.1.5.5.7.3.2',
          'codeSigning': '1.3.6.1.5.5.7.3.3',
          'emailProtection': '1.3.6.1.5.5.7.3.4',
          'timeStamping': '1.3.6.1.5.5.7.3.8',
          'OCSPSigning': '1.3.6.1.5.5.7.3.9'
        };
        return ekuMap[eku] || eku;
      });
      
      // Add proper EKU extension with mapped OIDs
      const ekuExt = {
        name: 'extKeyUsage',
        critical: false
      };
      
      // Add each EKU purpose
      ekuOids.forEach((oid, index) => {
        const purposeMap = {
          '1.3.6.1.5.5.7.3.1': 'serverAuth',
          '1.3.6.1.5.5.7.3.2': 'clientAuth',
          '1.3.6.1.5.5.7.3.3': 'codeSigning',
          '1.3.6.1.5.5.7.3.4': 'emailProtection',
          '1.3.6.1.5.5.7.3.8': 'timeStamping',
          '1.3.6.1.5.5.7.3.9': 'OCSPSigning'
        };
        const purpose = purposeMap[oid];
        if (purpose) {
          ekuExt[purpose] = true;
        }
      });
      
      extensions.push(ekuExt);
    }

    // Subject Alternative Names
    if (subjectAltNames && subjectAltNames.length > 0) {
      const validSANs = subjectAltNames.filter(san => san.value && san.value.trim());
      if (validSANs.length > 0) {
        // Validate SAN values based on type
        for (const san of validSANs) {
          const value = san.value.trim();
          if (san.type === 'DNS') {
            // Basic DNS validation
            if (!/^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?)*$/.test(value)) {
              return res.status(400).json({ error: `Invalid DNS name in SAN: ${value}` });
            }
          } else if (san.type === 'IP') {
            // Basic IPv4/IPv6 validation
            const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/;
            const ipv6 = /^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;
            if (!ipv4.test(value) && !ipv6.test(value)) {
              return res.status(400).json({ error: `Invalid IP address in SAN: ${value}` });
            }
          } else if (san.type === 'email') {
            // Validate email
            if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) {
              return res.status(400).json({ error: `Invalid email in SAN: ${value}` });
            }
          } else if (san.type === 'URI') {
            // Basic URI validation
            try {
              new URL(value);
            } catch {
              return res.status(400).json({ error: `Invalid URI in SAN: ${value}` });
            }
          }
        }
        
        const sanExt = {
          name: 'subjectAltName',
          altNames: validSANs.map(san => {
            if (san.type === 'DNS') {
              return { type: 2, value: san.value.trim() };
            } else if (san.type === 'IP') {
              return { type: 7, ip: san.value.trim() };
            } else if (san.type === 'email') {
              return { type: 1, value: san.value.trim() };
            } else if (san.type === 'URI') {
              return { type: 6, value: san.value.trim() };
            }
            return { type: 2, value: san.value.trim() };
          })
        };
        extensions.push(sanExt);
      }
    }

    // Custom Extensions
    if (customExtensions && customExtensions.length > 0) {
      for (const ext of customExtensions) {
        if (ext.oid && ext.value) {
          // Validate OID format - must be dot-separated numbers, at least two components
          if (!/^[0-9]+(\.[0-9]+)+$/.test(ext.oid)) {
            return res.status(400).json({ 
              error: `Invalid OID format: ${ext.oid}. Must be dot-separated numbers (e.g., "1.2.840.113549").` 
            });
          }
          extensions.push({
            id: ext.oid,
            critical: ext.critical || false,
            value: ext.value
          });
        }
      }
    }

    csr.setAttributes([{
      name: 'extensionRequest',
      extensions: extensions
    }]);

    // Sign CSR
    csr.sign(keys.privateKey, forge.md.sha256.create());

    // Convert to PEM
    const csrPem = forge.pki.certificationRequestToPem(csr);
    let privateKeyPem;

    if (password) {
      // Encrypt private key with password
      privateKeyPem = forge.pki.encryptRsaPrivateKey(keys.privateKey, password, {
        algorithm: 'aes256'
      });
    } else {
      privateKeyPem = forge.pki.privateKeyToPem(keys.privateKey);
    }

    res.json({
      success: true,
      csr: csrPem,
      privateKey: privateKeyPem,
      publicKey: forge.pki.publicKeyToPem(keys.publicKey)
    });

  } catch (error) {
    console.error('CSR Generation Error:', error);
    // Don't expose internal error details to client in production
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

    // Parse CSR
    const csrObj = forge.pki.certificationRequestFromPem(csr);
    
    // Extract subject
    const subject = {};
    csrObj.subject.attributes.forEach(attr => {
      subject[attr.name] = attr.value;
    });

    // Extract public key info
    const publicKey = csrObj.publicKey;
    const keyInfo = {
      type: publicKey.n ? 'RSA' : 'Unknown',
      bits: publicKey.n ? publicKey.n.bitLength() : 0
    };

    // Extract extensions
    const extensions = {};
    const attrs = csrObj.getAttribute({ name: 'extensionRequest' });
    
    if (attrs && attrs.extensions) {
      attrs.extensions.forEach(ext => {
        if (ext.name === 'keyUsage') {
          extensions.keyUsage = [];
          if (ext.digitalSignature) extensions.keyUsage.push('digitalSignature');
          if (ext.nonRepudiation) extensions.keyUsage.push('nonRepudiation');
          if (ext.keyEncipherment) extensions.keyUsage.push('keyEncipherment');
          if (ext.dataEncipherment) extensions.keyUsage.push('dataEncipherment');
          if (ext.keyAgreement) extensions.keyUsage.push('keyAgreement');
          if (ext.keyCertSign) extensions.keyUsage.push('keyCertSign');
          if (ext.cRLSign) extensions.keyUsage.push('cRLSign');
          if (ext.encipherOnly) extensions.keyUsage.push('encipherOnly');
          if (ext.decipherOnly) extensions.keyUsage.push('decipherOnly');
        } else if (ext.name === 'extKeyUsage') {
          extensions.extendedKeyUsage = ext;
        } else if (ext.name === 'subjectAltName') {
          extensions.subjectAltName = ext.altNames.map(san => ({
            type: san.type,
            value: san.value || san.ip
          }));
        } else {
          extensions[ext.name || ext.id] = ext;
        }
      });
    }

    // Verify signature
    const verified = csrObj.verify();

    res.json({
      success: true,
      subject,
      publicKey: keyInfo,
      extensions,
      signatureAlgorithm: 'sha256WithRSAEncryption',
      verified,
      pem: csr
    });

  } catch (error) {
    console.error('CSR Analysis Error:', error);
    // Don't expose internal error details to client in production
    const isDev = process.env.NODE_ENV === 'development';
    res.status(500).json({ 
      error: 'Failed to analyze CSR',
      ...(isDev && { details: error.message })
    });
  }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0' });
});

app.listen(PORT, () => {
  console.log(`CSR Generator server running on port ${PORT}`);
  console.log(`Access the application at http://localhost:${PORT}`);
});
