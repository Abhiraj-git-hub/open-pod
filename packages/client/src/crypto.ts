import { PoDClaims, PoDHeader, PoDKeypair, DelegationOptions } from './types.js';

// Cross-environment SubtleCrypto accessor (Browser & Node.js)
const subtle = typeof window !== 'undefined' && window.crypto?.subtle 
  ? window.crypto.subtle 
  : globalThis.crypto?.subtle;

if (!subtle) {
  throw new Error('WebCrypto subtle is not supported in this environment');
}

/**
 * Encodes an ArrayBuffer or Uint8Array to a Base64URL string
 */
export function bufferToBase64Url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64url');
  }
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a Base64URL string to Uint8Array
 */
export function base64UrlToBuffer(base64url: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(base64url, 'base64url'));
  }
  let base64 = base64url.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) {
    base64 += '=';
  }
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encodes a JSON object to Base64URL
 */
export function jsonToBase64Url(obj: any): string {
  const jsonStr = JSON.stringify(obj);
  const encoder = new TextEncoder();
  return bufferToBase64Url(encoder.encode(jsonStr));
}

/**
 * Generates an Ed25519 cryptographic keypair in browser hardware / WebCrypto
 */
export async function generatePoDKeypair(): Promise<PoDKeypair> {
  const keyPair = (await subtle.generateKey(
    'Ed25519',
    true, // extractable
    ['sign', 'verify']
  )) as CryptoKeyPair;

  // Export raw public key bytes (32 bytes)
  const rawPublicKey = await subtle.exportKey('raw', keyPair.publicKey);
  const publicKeyBase64Url = bufferToBase64Url(rawPublicKey);

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
    publicKeyBase64Url
  };
}

/**
 * Creates and cryptographically signs a Proof-of-Delegation (PoD) token
 */
export async function createDelegationToken(
  keypair: PoDKeypair,
  options: DelegationOptions
): Promise<string> {
  const now = Math.floor(Date.now() / 1000);
  const ttl = Math.min(options.ttlSeconds || 60, 60); // Maximum 60 seconds

  const header: PoDHeader = {
    alg: 'EdDSA',
    crv: 'Ed25519',
    typ: 'PoD+jwt'
  };

  // Generate cryptographically random 16-byte nonce
  const nonceBytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(nonceBytes);
  const nonce = bufferToBase64Url(nonceBytes);

  const payload: PoDClaims = {
    iss: keypair.publicKeyBase64Url,
    aud: options.targetOrigin,
    iat: now,
    exp: now + ttl,
    jti: nonce,
    lim: options.rateLimit || 10,
    scp: options.scope || 'agent:action'
  };

  const headerB64 = jsonToBase64Url(header);
  const payloadB64 = jsonToBase64Url(payload);
  const messageToSign = `${headerB64}.${payloadB64}`;

  const encoder = new TextEncoder();
  const signatureBuffer = await subtle.sign(
    'Ed25519',
    keypair.privateKey,
    encoder.encode(messageToSign)
  );

  const signatureB64 = bufferToBase64Url(signatureBuffer);

  return `${headerB64}.${payloadB64}.${signatureB64}`;
}
