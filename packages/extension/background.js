// OpenPoD Background Service Worker
function bufferToBase64Url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function jsonToBase64Url(obj) {
  return bufferToBase64Url(new TextEncoder().encode(JSON.stringify(obj)));
}

async function signToken(targetOrigin, scope = 'agent:action') {
  const stored = await chrome.storage.local.get(['pod_public_key_b64', 'pod_private_key_jwk', 'pod_rate_limit']);
  if (!stored.pod_private_key_jwk) {
    throw new Error('PoD keypair not initialized');
  }

  const privateKey = await crypto.subtle.importKey(
    'jwk',
    stored.pod_private_key_jwk,
    { name: 'Ed25519' },
    false,
    ['sign']
  );

  const now = Math.floor(Date.now() / 1000);
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = bufferToBase64Url(nonceBytes);

  const header = { alg: 'EdDSA', crv: 'Ed25519', typ: 'PoD+jwt' };
  const payload = {
    iss: stored.pod_public_key_b64,
    aud: targetOrigin,
    iat: now,
    exp: now + 60,
    jti: nonce,
    lim: stored.pod_rate_limit || 10,
    scp: scope
  };

  const headerB64 = jsonToBase64Url(header);
  const payloadB64 = jsonToBase64Url(payload);
  const message = new TextEncoder().encode(`${headerB64}.${payloadB64}`);

  const sigBuffer = await crypto.subtle.sign('Ed25519', privateKey, message);
  const sigB64 = bufferToBase64Url(sigBuffer);

  return `${headerB64}.${payloadB64}.${sigB64}`;
}

// Listen for messages from content scripts or agents
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === 'GET_POD_TOKEN') {
    signToken(request.targetOrigin, request.scope)
      .then(token => sendResponse({ success: true, token }))
      .catch(err => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open for async response
  }
});
