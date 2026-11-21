// OpenPoD Interactive Client Controller

const legacyConsole = document.getElementById('legacyConsole');
const podConsole = document.getElementById('podConsole');
const attackConsole = document.getElementById('attackConsole');
const eventStream = document.getElementById('eventStream');

const statTotal = document.getElementById('statTotal');
const statAllowed = document.getElementById('statAllowed');
const statBlocked = document.getElementById('statBlocked');
const statRevoked = document.getElementById('statRevoked');

function appendLog(element, text, className = '') {
  const line = document.createElement('div');
  line.className = `log-line ${className}`;
  const time = new Date().toLocaleTimeString();
  line.innerHTML = `<span style="color:#64748b;">[${time}]</span> ${text}`;
  element.appendChild(line);
  element.scrollTop = element.scrollHeight;
}

// 1. LEGACY AGENT TEST (Without PoD Header)
document.getElementById('runLegacyBtn').addEventListener('click', async () => {
  legacyConsole.innerHTML = '';
  appendLog(legacyConsole, 'Dispatching autonomous scraper (Puppeteer/cURL)...', 'line-cyan');
  appendLog(legacyConsole, 'HTTP GET /api/flights (No PoD Headers attached)...');

  try {
    const res = await fetch('/api/flights');
    const data = await res.json();

    if (res.status === 403) {
      appendLog(legacyConsole, `STATUS: 403 FORBIDDEN`, 'line-red');
      appendLog(legacyConsole, `Defense: ${data.defense}`, 'line-red');
      appendLog(legacyConsole, `Reason: ${data.reason}`, 'line-red');
      appendLog(legacyConsole, `Challenge: ${data.challengeUrl}`, 'line-amber');
      appendLog(legacyConsole, '❌ AGENT BLOCKED: Cannot proceed without human manual CAPTCHA solving.', 'line-red');
    } else {
      appendLog(legacyConsole, `Unexpected status: ${res.status}`, 'line-amber');
    }
  } catch (err) {
    appendLog(legacyConsole, `Network Error: ${err.message}`, 'line-red');
  }
  updateStats();
});

// 2. AUTHORIZED POD AGENT TEST (With Hardware Ed25519 PoD Header)
document.getElementById('runPodBtn').addEventListener('click', async () => {
  podConsole.innerHTML = '';
  appendLog(podConsole, 'Reading local hardware key (WebCrypto Ed25519)...', 'line-cyan');
  
  const startTime = performance.now();
  // Request local signed token from demo helper
  const tokenRes = await fetch('/api/demo/generate-token', { method: 'POST' });
  const { token, publicKey } = await tokenRes.json();
  const signTime = (performance.now() - startTime).toFixed(1);

  appendLog(podConsole, `Key Fingerprint: ${publicKey.slice(0, 14)}...`, 'line-cyan');
  appendLog(podConsole, `Token Signed in ${signTime} ms (Ed25519)`, 'line-green');
  appendLog(podConsole, `Attaching Header: Sec-Proof-Of-Delegation: ${token.slice(0, 24)}...`);

  // Dispatch request with PoD header
  const reqStart = performance.now();
  const res = await fetch('/api/flights', {
    headers: {
      'Sec-Proof-Of-Delegation': token,
      'X-Proof-Of-Delegation': token
    }
  });
  const data = await res.json();
  const totalLatency = (performance.now() - reqStart).toFixed(1);

  if (res.status === 200 && data.status === 'success') {
    appendLog(podConsole, `STATUS: 200 OK (Instant Bypass in ${totalLatency} ms)`, 'line-green');
    appendLog(podConsole, `Server Verification: Passed (${data.latencyMs} ms)`, 'line-green');
    appendLog(podConsole, `Scope: ${data.scope} | Delegator Key: Verified`, 'line-green');
    appendLog(podConsole, `✅ INVENTORY LOADED: Found ${data.flights.length} flights!`, 'line-green');
    data.flights.slice(0, 2).forEach(f => {
      appendLog(podConsole, `   ✈️ ${f.id} (${f.airline}) ${f.from}->${f.to} : ${f.price}`);
    });
  } else {
    appendLog(podConsole, `Failed: ${data.message || res.statusText}`, 'line-red');
  }
  updateStats();
});

// 3. MALICIOUS ATTACK SIMULATOR (Rate-limit flood & key revocation)
document.getElementById('runAttackBtn').addEventListener('click', async () => {
  attackConsole.innerHTML = '';
  appendLog(attackConsole, '⚠️ Generating attacker key for high-frequency burst...', 'line-amber');
  
  appendLog(attackConsole, 'Flooding /api/flights with 10 rapid concurrent requests...', 'line-cyan');

  let allowedCount = 0;
  let blockedCount = 0;
  let revoked = false;

  for (let i = 1; i <= 10; i++) {
    try {
      // Attacker signs a fresh token with new nonce on each request to bypass replay detection
      const tokenRes = await fetch('/api/demo/generate-token', { method: 'POST' });
      const { token } = await tokenRes.json();

      const res = await fetch('/api/flights', {
        headers: {
          'Sec-Proof-Of-Delegation': token,
          'X-Proof-Of-Delegation': token
        }
      });
      const data = await res.json();

      if (res.status === 200) {
        allowedCount++;
        appendLog(attackConsole, `Req #${i}: 200 OK (Allowed under quota)`, 'line-green');
      } else if (res.status === 429) {
        blockedCount++;
        if (data.message && data.message.includes('revoked')) {
          revoked = true;
          appendLog(attackConsole, `Req #${i}: 429 KEY REVOKED & BURNED (5-min ban)`, 'line-red');
        } else {
          appendLog(attackConsole, `Req #${i}: 429 Rate Limit Exceeded`, 'line-amber');
        }
      } else {
        appendLog(attackConsole, `Req #${i}: Status ${res.status}`, 'line-amber');
      }
    } catch (e) {
      appendLog(attackConsole, `Req #${i}: Error ${e.message}`, 'line-red');
    }
    // Small 80ms delay between rapid requests
    await new Promise(r => setTimeout(r, 80));
  }

  appendLog(attackConsole, `\nSummary: ${allowedCount} Allowed | ${blockedCount} Blocked`, 'line-cyan');
  if (revoked) {
    appendLog(attackConsole, `🛡️ ATTACK DEFUSED: System automatically burned the attacker's public key.`, 'line-red');
  }
  updateStats();
});

// Reset Stats
document.getElementById('resetStatsBtn').addEventListener('click', async () => {
  await fetch('/api/reset-stats', { method: 'POST' });
  updateStats();
  legacyConsole.innerHTML = '<div class="console-placeholder">// Console reset. Ready for testing.</div>';
  podConsole.innerHTML = '<div class="console-placeholder">// Console reset. Ready for testing.</div>';
  attackConsole.innerHTML = '<div class="console-placeholder">// Console reset. Ready for testing.</div>';
});

// Telemetry Poller
async function updateStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();

    statTotal.textContent = data.totalRequests;
    statAllowed.textContent = data.allowedAgents;
    statBlocked.textContent = data.blockedBots;
    statRevoked.textContent = data.revokedAttackers;

    // Render event stream
    eventStream.innerHTML = '';
    data.recentEvents.forEach(evt => {
      const row = document.createElement('div');
      row.className = 'event-row';
      const tagClass = evt.type === 'ALLOWED' ? 'tag-green' : (evt.type === 'REVOKED' ? 'tag-red' : 'tag-amber');
      row.innerHTML = `
        <div style="display:flex; align-items:center; gap:8px;">
          <span class="event-tag ${tagClass}">${evt.type}</span>
          <span>${evt.message}</span>
        </div>
        <span style="color:#64748b;">${evt.timestamp}</span>
      `;
      eventStream.appendChild(row);
    });
  } catch (err) {
    console.error('Failed to update stats:', err);
  }
}

// Initial fetch and poll every 2 seconds
updateStats();
setInterval(updateStats, 2000);
