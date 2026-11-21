import { PoDClaims, VerificationResult, PoDGuardOptions } from './types.js';
import { PoDRateLimiter } from './rate-limiter.js';

const subtle = globalThis.crypto?.subtle;

if (!subtle) {
  throw new Error('WebCrypto subtle is required on the server for PoD verification');
}

export class PoDVerifier {
  private replayCache: Map<string, number> = new Map(); // jti -> expiresAt
  private rateLimiter: PoDRateLimiter;

  constructor() {
    this.rateLimiter = new PoDRateLimiter();
    // Periodically clean replay cache
    const timer = setInterval(() => this.cleanReplayCache(), 30000);
    if (timer && typeof timer.unref === 'function') {
      timer.unref();
    }
  }

  getRateLimiter(): PoDRateLimiter {
    return this.rateLimiter;
  }

  private cleanReplayCache() {
    const now = Math.floor(Date.now() / 1000);
    for (const [jti, exp] of this.replayCache.entries()) {
      if (now > exp) {
        this.replayCache.delete(jti);
      }
    }
  }

  /**
   * Decodes Base64URL string to Uint8Array
   */
  private base64UrlToBuffer(base64url: string): Uint8Array {
    return new Uint8Array(Buffer.from(base64url, 'base64url'));
  }

  /**
   * Verifies a raw Sec-Proof-Of-Delegation token
   */
  async verifyToken(token: string, options: PoDGuardOptions = {}): Promise<VerificationResult> {
    if (!token || typeof token !== 'string') {
      return { valid: false, error: 'Missing or malformed token', statusCode: 400 };
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
      return { valid: false, error: 'Invalid token structure. Expected 3 segments', statusCode: 400 };
    }

    const [headerB64, payloadB64, signatureB64] = parts;

    // 1. Decode Header
    let header: any;
    try {
      const headerStr = Buffer.from(headerB64, 'base64url').toString('utf8');
      header = JSON.parse(headerStr);
    } catch {
      return { valid: false, error: 'Corrupt token header', statusCode: 400 };
    }

    if (header.alg !== 'EdDSA' || header.crv !== 'Ed25519') {
      return { valid: false, error: `Unsupported algorithm: ${header.alg}`, statusCode: 400 };
    }

    // 2. Decode Payload
    let payload: PoDClaims;
    try {
      const payloadStr = Buffer.from(payloadB64, 'base64url').toString('utf8');
      payload = JSON.parse(payloadStr);
    } catch {
      return { valid: false, error: 'Corrupt token payload', statusCode: 400 };
    }

    const now = Math.floor(Date.now() / 1000);

    // 3. Temporal Validity
    if (now < payload.iat - 5) {
      return { valid: false, error: 'Token issued in the future (clock skew)', statusCode: 401 };
    }
    if (now > payload.exp) {
      return { valid: false, error: 'Token expired', statusCode: 401 };
    }
    if (payload.exp - payload.iat > 60) {
      return { valid: false, error: 'Token TTL exceeds maximum 60-second limit', statusCode: 401 };
    }

    // 4. Origin Matching (Audience)
    if (options.expectedOrigin && payload.aud !== options.expectedOrigin) {
      return { 
        valid: false, 
        error: `Audience mismatch. Token bound to: ${payload.aud}, expected: ${options.expectedOrigin}`, 
        statusCode: 403 
      };
    }

    // 5. Replay Protection (Nonce check)
    if (this.replayCache.has(payload.jti)) {
      return { valid: false, error: 'Replay detected! Nonce (jti) already used', statusCode: 409 };
    }
    this.replayCache.set(payload.jti, payload.exp);

    // 6. Cryptographic Signature Verification
    try {
      const rawPublicKey = this.base64UrlToBuffer(payload.iss);
      const publicKey = await subtle.importKey(
        'raw',
        rawPublicKey as unknown as BufferSource,
        { name: 'Ed25519' },
        true,
        ['verify']
      );

      const message = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
      const rawSignature = this.base64UrlToBuffer(signatureB64);

      const isValid = await subtle.verify(
        'Ed25519',
        publicKey,
        rawSignature as unknown as BufferSource,
        message
      );

      if (!isValid) {
        return { valid: false, error: 'Cryptographic signature verification failed', statusCode: 403 };
      }
    } catch (err: any) {
      return { valid: false, error: `Signature verification error: ${err.message}`, statusCode: 403 };
    }

    // 7. Rate Limit & Key Revocation Check
    const effectiveLimit = Math.min(payload.lim || 10, options.maxServerLimit || 20);
    const rateCheck = this.rateLimiter.checkAndRecord(payload.iss, effectiveLimit);

    if (rateCheck.revoked) {
      return { 
        valid: false, 
        error: 'Key revoked due to severe rate-limit violation / abuse', 
        statusCode: 429 
      };
    }

    if (!rateCheck.allowed) {
      return { 
        valid: false, 
        error: `Rate limit exceeded. Declared max: ${effectiveLimit} req/min`, 
        statusCode: 429 
      };
    }

    // All checks passed!
    return {
      valid: true,
      claims: payload
    };
  }
}
