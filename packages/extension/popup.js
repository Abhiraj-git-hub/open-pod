// Helper to convert buffer to base64url
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function getOrInitKeypair() {
  const stored = await chrome.storage.local.get(['pod_public_key_b64', 'pod_private_key_jwk']);
  if (stored.pod_public_key_b64 && stored.pod_private_key_jwk) {
    return {
      publicKeyB64: stored.pod_public_key_b64,
      privateKeyJwk: stored.pod_private_key_jwk
    };
  }

  // Generate new Ed25519 keypair
  const keyPair = await crypto.subtle.generateKey('Ed25519', true, ['sign', 'verify']);
  const rawPub = await crypto.subtle.exportKey('raw', keyPair.publicKey);
  const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
  const pubB64 = bufferToBase64Url(rawPub);

  await chrome.storage.local.set({
    pod_public_key_b64: pubB64,
    pod_private_key_jwk: privJwk,
    pod_rate_limit: 10
  });

  return { publicKeyB64: pubB64, privateKeyJwk: privJwk };
}

document.addEventListener('DOMContentLoaded', async () => {
  const keyDisplay = document.getElementById('keyFingerprint');
  const slider = document.getElementById('rateSlider');
  const limitLabel = document.getElementById('limitLabel');
  const testBtn = document.getElementById('generateTokenBtn');
  const logList = document.getElementById('logList');

  const { publicKeyB64 } = await getOrInitKeypair();
  keyDisplay.textContent = `${publicKeyB64.slice(0, 12)}...${publicKeyB64.slice(-10)}`;

  const stored = await chrome.storage.local.get('pod_rate_limit');
  if (stored.pod_rate_limit) {
    slider.value = stored.pod_rate_limit;
    limitLabel.textContent = `${stored.pod_rate_limit} req / min`;
  }

  slider.addEventListener('input', async (e) => {
    const val = e.target.value;
    limitLabel.textContent = `${val} req / min`;
    await chrome.storage.local.set({ pod_rate_limit: Number(val) });
  });

  testBtn.addEventListener('click', async () => {
    const log = document.createElement('div');
    log.className = 'log-item';
    const now = new Date().toLocaleTimeString();
    log.innerHTML = `<span>Token Signed (${slider.value}/m)</span><span class="success">${now}</span>`;
    logList.prepend(log);
  });
});
