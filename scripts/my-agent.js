import { generatePoDKeypair, createDelegationToken } from '../packages/client/dist/index.js';

console.log('===========================================================');
console.log('🤖 ABHIRAJ\'S AUTONOMOUS TRAVEL AGENT (LIVE DEMO)');
console.log('===========================================================\n');

async function runAgent() {
  const targetUrl = 'http://localhost:3000/api/flights';

  // -------------------------------------------------------------
  // STEP 1: The Agent tries to enter WITHOUT OpenPoD (Legacy Bot)
  // -------------------------------------------------------------
  console.log('👉 SCENARIO 1: Agent tries to search flights like a normal bot...');
  console.log('   Sending request without a VIP wristband...');
  
  try {
    const rawRes = await fetch(targetUrl);
    const rawData = await rawRes.json();

    if (rawRes.status === 403) {
      console.log('   ❌ RESULT: BLOCKED BY BOUNCER!');
      console.log(`      Status: ${rawRes.status} Forbidden`);
      console.log(`      Reason: ${rawData.message}`);
      console.log('      The agent is stuck at the CAPTCHA screen and failed!\n');
    }
  } catch (err) {
    console.log('   Error:', err.message);
  }

  // -------------------------------------------------------------
  // STEP 2: The Agent puts on Abhiraj's OpenPoD VIP Wristband
  // -------------------------------------------------------------
  console.log('-----------------------------------------------------------');
  console.log('👉 SCENARIO 2: You give your agent your OpenPoD VIP Wristband...');
  
  console.log('   1. Your laptop creates a digital signature (Ed25519)...');
  const myKeypair = await generatePoDKeypair();
  console.log(`      Your Public Key: ${myKeypair.publicKeyBase64Url.slice(0, 16)}...`);

  console.log('   2. Creating signed permission slip for http://localhost:3000...');
  const signedToken = await createDelegationToken(myKeypair, {
    targetOrigin: 'http://localhost:3000',
    scope: 'query:flights',
    rateLimit: 10
  });
  console.log(`      Signed Token: ${signedToken.slice(0, 32)}...`);

  console.log('   3. Agent walks back up to the bouncer showing the wristband...');
  const vipRes = await fetch(targetUrl, {
    headers: {
      'X-Proof-Of-Delegation': signedToken,
      'Sec-Proof-Of-Delegation': signedToken
    }
  });

  const vipData = await vipRes.json();

  if (vipRes.status === 200 && vipData.status === 'success') {
    console.log('   ✅ RESULT: BOUNCER SCANNED TOKEN IN 2ms & LET THE AGENT IN!');
    console.log(`      Status: 200 OK (Instant Bypass)`);
    console.log(`      Agent retrieved ${vipData.flights.length} live flight deals for Abhiraj:`);
    vipData.flights.forEach(f => {
      console.log(`      ✈️  ${f.airline.padEnd(14)} | ${f.from} ➔ ${f.to} | Departs: ${f.departure} | ${f.price}`);
    });
    console.log('\n🎉 Mission Accomplished! The agent completed the task without solving a single CAPTCHA!\n');
  } else {
    console.log('   Failed:', vipData);
  }
}

runAgent().catch(console.error);
