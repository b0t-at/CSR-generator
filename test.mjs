/**
 * Basic test suite for CSR Generator
 * Runs server health check and CSR generation tests
 */

import http from 'node:http';
import { spawn } from 'node:child_process';

const PORT = 3001; // Use different port for testing
let serverProcess;
let passed = 0;
let failed = 0;

function getLogPrefix(type) {
  if (type === 'pass') return '✓';
  if (type === 'fail') return '✗';
  return '•';
}

function log(message, type = 'info') {
  console.log(`${getLogPrefix(type)} ${message}`);
}

function request(options, body = null) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(data) });
        } catch {
          resolve({ status: res.statusCode, data });
        }
      });
    });
    req.on('error', reject);
    if (body) req.write(JSON.stringify(body));
    req.end();
  });
}

async function waitForServer(maxAttempts = 30) {
  for (let i = 0; i < maxAttempts; i++) {
    try {
      await request({ hostname: 'localhost', port: PORT, path: '/api/health', method: 'GET' });
      return true;
    } catch {
      await new Promise(r => setTimeout(r, 200));
    }
  }
  return false;
}

async function testHealthEndpoint() {
  const { status, data } = await request({
    hostname: 'localhost', port: PORT, path: '/api/health', method: 'GET'
  });
  
  if (status === 200 && data.status === 'ok') {
    log('Health endpoint returns OK', 'pass');
    passed++;
  } else {
    log('Health endpoint failed', 'fail');
    failed++;
  }
}

async function testRSAGeneration() {
  const { status, data } = await request({
    hostname: 'localhost', port: PORT, path: '/api/generate', method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    commonName: 'test.example.com',
    keyType: 'RSA',
    keySize: 2048
  });
  
  if (status === 200 && data.success && data.csr && data.privateKey) {
    log('RSA CSR generation works', 'pass');
    passed++;
  } else {
    log(`RSA CSR generation failed: ${JSON.stringify(data)}`, 'fail');
    failed++;
  }
}

async function testECDSAGeneration() {
  const { status, data } = await request({
    hostname: 'localhost', port: PORT, path: '/api/generate', method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    commonName: 'test.example.com',
    keyType: 'ECDSA',
    curveName: 'P-256'
  });
  
  if (status === 200 && data.success && data.csr && data.privateKey) {
    log('ECDSA CSR generation works', 'pass');
    passed++;
  } else {
    log(`ECDSA CSR generation failed: ${JSON.stringify(data)}`, 'fail');
    failed++;
  }
}

async function testCSRAnalysis() {
  // First generate a CSR
  const genResponse = await request({
    hostname: 'localhost', port: PORT, path: '/api/generate', method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, {
    commonName: 'analysis.test.com',
    organization: 'Test Org',
    keyType: 'RSA',
    keySize: 2048
  });
  
  if (!genResponse.data.csr) {
    log('CSR Analysis failed - could not generate CSR', 'fail');
    failed++;
    return;
  }
  
  // Now analyze it
  const { status, data } = await request({
    hostname: 'localhost', port: PORT, path: '/api/analyze', method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, { csr: genResponse.data.csr });
  
  if (status === 200 && data.success && data.subject?.commonName === 'analysis.test.com') {
    log('CSR analysis works', 'pass');
    passed++;
  } else {
    log(`CSR analysis failed: ${JSON.stringify(data)}`, 'fail');
    failed++;
  }
}

async function testValidation() {
  // Test missing common name
  const { status, data } = await request({
    hostname: 'localhost', port: PORT, path: '/api/generate', method: 'POST',
    headers: { 'Content-Type': 'application/json' }
  }, { keyType: 'RSA', keySize: 2048 });
  
  if (status === 400 && data.error) {
    log('Validation rejects missing common name', 'pass');
    passed++;
  } else {
    log('Validation should reject missing common name', 'fail');
    failed++;
  }
}

async function runTests() {
  console.log('\n=== CSR Generator Test Suite ===\n');
  
  // Start server
  console.log('Starting test server...');
  serverProcess = spawn('node', ['server.js'], {
    env: { ...process.env, PORT: PORT.toString() },
    stdio: ['ignore', 'pipe', 'pipe']
  });
  
  serverProcess.stderr.on('data', (data) => {
    const msg = data.toString();
    if (!msg.includes('running on port')) {
      console.error('Server error:', msg);
    }
  });
  
  const serverReady = await waitForServer();
  if (!serverReady) {
    console.error('Failed to start server');
    process.exit(1);
  }
  console.log('Server started\n');
  
  try {
    await testHealthEndpoint();
    await testRSAGeneration();
    await testECDSAGeneration();
    await testCSRAnalysis();
    await testValidation();
  } catch (error) {
    console.error('Test error:', error);
    failed++;
  }
  
  // Cleanup
  serverProcess.kill();
  
  console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
  process.exit(failed > 0 ? 1 : 0);
}

await runTests();
