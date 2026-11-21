import { generatePoDKeypair, createDelegationToken } from '../packages/client/dist/index.js';
import { PoDVerifier } from '../packages/middleware/dist/index.js';

console.log('====================================================');
console.log('🧪 RUNNING OPEN-POD PROTOCOL END-TO-END TEST SUITE');
console.log('====================================================\n');

async function runTests() {
  let passed = 0;
  let failed = 0;

  function assert(condition, message) {
    if (condition) {
      console.log(`  ✅ [PASS] ${message}`);
      passed++;
    } else {
      console.error(`  ❌ [FAIL] ${message}`);
      failed++;
    }
  }

  // TEST 1: Keypair Generation
  console.log('1. Testing Ed25519 WebCrypto Key Generation...');
  const keypair = await generatePoDKeypair();
  assert(keypair.publicKey && keypair.privateKey, 'Keypair generated successfully');
  assert(keypair.publicKeyBase64Url.length > 30, `Public key serialized: ${keypair.publicKeyBase64Url.slice(0, 16)}...`);

  // TEST 2: Token Signing & Verification
  console.log('\n2. Testing Token Signing & Verification...');
  const verifier = new PoDVerifier();
  const targetOrigin = 'https://api.aerobook.com';
  
  const token = await createDelegationToken(keypair, {
    targetOrigin,
    scope: 'query:flights',
    rateLimit: 5,
    ttlSeconds: 30
  });
  assert(token.split('.').length === 3, 'Token has valid 3-part JWT structure');

  const result1 = await verifier.verifyToken(token, { expectedOrigin: targetOrigin });
  assert(result1.valid === true, 'Valid token verified with zero errors');
  assert(result1.claims?.iss === keypair.publicKeyBase64Url, 'Claims match delegator public key');
  assert(result1.claims?.scp === 'query:flights', 'Claims match declared action scope');

  // TEST 3: Audience Mismatch (Domain Hijack Prevention)
  console.log('\n3. Testing Audience Mismatch (Cross-Origin Replay)...');
  const result2 = await verifier.verifyToken(token, { expectedOrigin: 'https://evil-bank.com' });
  assert(result2.valid === false, 'Blocked cross-origin replay attempt');
  assert(result2.statusCode === 403, `Correct status code returned (403): ${result2.error}`);

  // TEST 4: Replay Attack Prevention (Nonce Reuse)
  console.log('\n4. Testing Replay Attack Detection...');
  const result3 = await verifier.verifyToken(token, { expectedOrigin: targetOrigin });
  assert(result3.valid === false, 'Blocked replay of identical nonce (jti)');
  assert(result3.statusCode === 409, `Correct status code returned (409): ${result3.error}`);

  // TEST 5: Signature Tampering Detection
  console.log('\n5. Testing Signature Tampering Detection...');
  const freshToken = await createDelegationToken(keypair, { targetOrigin });
  const parts = freshToken.split('.');
  // Mutate real byte in signature (index 10)
  const mutatedChar = parts[2][10] === 'X' ? 'Y' : 'X';
  const tamperedSig = parts[2].slice(0, 10) + mutatedChar + parts[2].slice(11);
  const tamperedToken = `${parts[0]}.${parts[1]}.${tamperedSig}`;

  const result4 = await verifier.verifyToken(tamperedToken, { expectedOrigin: targetOrigin });
  assert(result4.valid === false, 'Tampered signature detected and rejected');
  assert(result4.statusCode === 403, `Rejected with signature failure: ${result4.error}`);

  // TEST 6: Rate Limiting Enforcement
  console.log('\n6. Testing Rate Limiting (Sliding Window)...');
  const rateLimitKeypair = await generatePoDKeypair();
  const limit = 3;
  let blockedOnRateLimit = false;

  for (let i = 1; i <= 5; i++) {
    const t = await createDelegationToken(rateLimitKeypair, { targetOrigin, rateLimit: limit });
    const res = await verifier.verifyToken(t, { expectedOrigin: targetOrigin });
    if (!res.valid && res.statusCode === 429) {
      blockedOnRateLimit = true;
      assert(true, `Request #${i} successfully blocked: ${res.error}`);
      break;
    } else {
      console.log(`     Request #${i}: Allowed (Count: ${i}/${limit})`);
    }
  }
  assert(blockedOnRateLimit, 'Rate limit strictly enforced against excessive agent requests');

  console.log('\n====================================================');
  console.log(`📊 TEST SUITE SUMMARY: ${passed} PASSED | ${failed} FAILED`);
  console.log('====================================================\n');

  if (failed > 0) {
    process.exit(1);
  }
}

runTests().catch(err => {
  console.error('Fatal error in tests:', err);
  process.exit(1);
});
