export interface PoDClaims {
  iss: string;       // Base64URL-encoded Ed25519 public key
  aud: string;       // Fully qualified target origin (e.g. https://api.airline.com)
  iat: number;       // Issued at (seconds)
  exp: number;       // Expiration time (seconds, max 60s from iat)
  jti: string;       // Cryptographic nonce / UUID
  lim: number;       // Declared rate limit (e.g. 10 requests / minute)
  scp: string;       // Scope (e.g. "search:flights")
}

export interface PoDHeader {
  alg: 'EdDSA';
  crv: 'Ed25519';
  typ: 'PoD+jwt';
}

export interface PoDKeypair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
  publicKeyBase64Url: string;
}

export interface DelegationOptions {
  targetOrigin: string;
  scope?: string;
  rateLimit?: number;
  ttlSeconds?: number;
}
