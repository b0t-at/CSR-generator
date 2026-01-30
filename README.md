# 🔐 CSR Generator

A simple yet powerful web-based Certificate Signing Request (CSR) generation tool with maximum adjustability and flexibility.

## Features

### 🎯 Core Capabilities
- **Multiple Templates**: Pre-configured templates for common use cases:
  - 🌐 Web Server (SSL/TLS)
  - 📝 Code Signing
  - 📧 Email Protection (S/MIME)
  - 👤 Client Authentication
  - ⚙️ Custom (full control)

- **Key Generation**:
  - RSA keys (2048, 3072, 4096 bits)
  - ECDSA/Elliptic Curve support (p256, p384, p521)
  - Password-protected private keys (AES-256 encryption; minimum 8 characters with complexity requirements, but 16+ characters or a long passphrase strongly recommended)

- **Complete X.509 Field Support**:
  - Common Name (CN)
  - Organization (O)
  - Organizational Unit (OU)
  - Locality/City (L)
  - State/Province (ST)
  - Country (C)
  - Email Address
  - Subject Alternative Names (SAN) - DNS, IP, Email, URI

### 🔑 Key Usage Configuration
Full control over certificate key usage with all standard options:
- Digital Signature
- Non-Repudiation
- Key Encipherment
- Data Encipherment
- Key Agreement
- Certificate Sign
- CRL Sign
- Encipher Only
- Decipher Only

### 🎫 Extended Key Usage (EKU) Support
Comprehensive EKU database with predefined OIDs:
- **TLS Web Server Authentication** (1.3.6.1.5.5.7.3.1)
- **TLS Web Client Authentication** (1.3.6.1.5.5.7.3.2)
- **Code Signing** (1.3.6.1.5.5.7.3.3)
- **Email Protection** (1.3.6.1.5.5.7.3.4)
- **Time Stamping** (1.3.6.1.5.5.7.3.8)
- **OCSP Signing** (1.3.6.1.5.5.7.3.9)
- **Document Signing** (1.3.6.1.4.1.311.10.3.12)
- **Smart Card Logon** (1.3.6.1.4.1.311.20.2.2)
- **IP Security IKE** (1.3.6.1.5.5.7.3.17)
- **Custom OIDs** - Add any custom OID you need

### 🔍 CSR Analyzer
Built-in CSR decoder and analyzer:
- Parse and display all CSR fields
- Show public key information
- Display all extensions (Key Usage, EKU, SAN, etc.)
- Verify CSR signature
- Human-readable output

### 💾 Download & Export
- Download CSR file
- Download private key file (optionally password-protected)
- Copy to clipboard functionality
- PEM format output

## Quick Start

### Using Docker (Recommended)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/b0t-at/CSR-generator.git
   cd CSR-generator
   ```

2. **Build and run with Docker Compose**:
   ```bash
   docker-compose up -d
   ```

3. **Access the application**:
   Open your browser to `http://localhost:3000`

### Manual Installation

1. **Prerequisites**:
   - Node.js 18 or higher
   - npm or yarn

2. **Install dependencies**:
   ```bash
   npm install
   ```

3. **Start the server**:
   ```bash
   npm start
   ```

4. **Access the application**:
   Open your browser to `http://localhost:3000`

## Usage Guide

### Generating a CSR

1. **Select a Template**: Click on one of the pre-defined templates or choose "Custom" for full control
2. **Configure Key**: Choose RSA or ECDSA and select the key size/curve
3. **Enter Subject Information**: Fill in the certificate subject fields (CN is required)
4. **Add SANs** (optional): Add Subject Alternative Names for multi-domain certificates
5. **Select Key Usage**: Choose the appropriate key usage flags for your certificate
6. **Select EKU**: Pick Extended Key Usage values or add custom OIDs
7. **Click Generate**: The CSR and private key will be generated and displayed
8. **Download**: Download both the CSR and private key files

### Analyzing a CSR

1. Switch to the "CSR Analyzer" tab
2. Paste your CSR in PEM format
3. Click "Analyze CSR"
4. View all decoded information including subject, key info, and extensions

## API Documentation

### Generate CSR
**POST** `/api/generate`

Request body:
```json
{
  "keyType": "RSA",
  "keySize": "2048",
  "commonName": "example.com",
  "organization": "Acme Corp",
  "country": "US",
  "keyUsage": ["digitalSignature", "keyEncipherment"],
  "extendedKeyUsage": ["serverAuth"],
  "subjectAltNames": [
    {"type": "DNS", "value": "www.example.com"},
    {"type": "DNS", "value": "mail.example.com"}
  ],
  "password": "optional-private-key-password"
}
```

Response:
```json
{
  "success": true,
  "csr": "-----BEGIN CERTIFICATE REQUEST-----...",
  "privateKey": "-----BEGIN ENCRYPTED PRIVATE KEY-----...",
  "publicKey": "-----BEGIN PUBLIC KEY-----..."
}
```

### Analyze CSR
**POST** `/api/analyze`

Request body:
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----..."
}
```

Response:
```json
{
  "success": true,
  "subject": {
    "commonName": "example.com",
    "organizationName": "Acme Corp"
  },
  "publicKey": {
    "type": "RSA",
    "bits": 2048
  },
  "extensions": {
    "keyUsage": ["digitalSignature", "keyEncipherment"],
    "subjectAltName": [...]
  },
  "verified": true
}
```

## Security Considerations

### Best Practices
- ✅ Always use strong passwords (minimum 8 characters with complexity, but 16+ characters or passphrases strongly recommended) for private key encryption
- ✅ Use minimum 2048-bit RSA keys (4096 recommended for high security)
- ✅ Store private keys securely and never share them
- ✅ Use appropriate key usage and EKU values for your use case
- ✅ Validate CSRs before submitting to a Certificate Authority

### Security Features
- Private keys are generated server-side with secure random number generation
- Optional password protection using AES-256 encryption (minimum 8 characters with complexity requirements)
- Rate limiting to prevent abuse:
  - 100 API requests per 15 minutes for all endpoints (general API limit)
  - 20 CSR generation requests per 15 minutes (stricter limit for `/api/generate` endpoint)
- Restricted CORS configuration (configurable via ALLOWED_ORIGINS environment variable)
- No data persistence - CSRs and keys are never stored on the server
- All processing is done in-memory and discarded after response
- Comprehensive input validation (CN length, country codes, email format, password strength, OID format, SAN validation)

## Technical Details

### Technology Stack
- **Backend**: Node.js with Express
- **CSR Generation**: node-forge (OpenSSL-compatible)
- **Frontend**: Vanilla JavaScript, HTML5, CSS3
- **Container**: Docker with Alpine Linux

### Standards Compliance
- RFC 5280 - Internet X.509 Public Key Infrastructure
- RFC 2986 - PKCS #10: Certification Request Syntax
- PKCS #8 - Private-Key Information Syntax

### Supported Key Algorithms
- RSA (2048, 3072, 4096 bits)
- ECDSA (p256, p384, p521)

### Supported Extensions
- Key Usage (RFC 5280 §4.2.1.3)
- Extended Key Usage (RFC 5280 §4.2.1.12)
- Subject Alternative Name (RFC 5280 §4.2.1.6)
- Custom extensions (OID-based)

## Development

### Project Structure
```
CSR-generator/
├── server.js              # Express server and API endpoints
├── package.json           # Node.js dependencies
├── Dockerfile            # Docker container definition
├── docker-compose.yml    # Docker Compose configuration
├── public/
│   ├── index.html        # Main UI
│   ├── styles.css        # Styling
│   └── script.js         # Frontend logic
└── README.md
```

### Running in Development Mode
```bash
npm install
npm run dev
```

This uses nodemon for auto-reloading on code changes.

## Docker Deployment

### Build Custom Image
```bash
docker build -t csr-generator .
```

### Run Container
```bash
docker run -d -p 3000:3000 --name csr-generator csr-generator
```

### Environment Variables
- `PORT` - Server port (default: 3000)
- `NODE_ENV` - Environment mode (production/development)

## Troubleshooting

### Common Issues

**Q: CSR generation fails**
- Ensure Common Name (CN) is provided
- Check that OIDs are in valid format (e.g., 1.2.3.4)
- Verify that key size is supported

**Q: Private key encryption fails**
- Ensure password is provided if encryption is desired
- Check that password meets minimum length requirements

**Q: CSR analysis fails**
- Verify CSR is in valid PEM format
- Ensure CSR includes proper headers (-----BEGIN CERTIFICATE REQUEST-----)

## Contributing

Contributions are welcome! Please feel free to submit issues or pull requests.

## License

MIT License - See LICENSE file for details

## References

- [RFC 5280 - X.509 Certificate Standard](https://tools.ietf.org/html/rfc5280)
- [RFC 2986 - PKCS #10](https://tools.ietf.org/html/rfc2986)
- [IANA Extended Key Usage Registry](https://www.iana.org/assignments/extended-key-usages/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)

## Acknowledgments

- Inspired by various CSR generation tools in the community
- Built with security and usability in mind
- Special thanks to the node-forge project for cryptographic operations
