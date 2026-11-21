export * from './types.js';
export * from './verifier.js';
export * from './rate-limiter.js';

import { PoDVerifier } from './verifier.js';
import { PoDGuardOptions } from './types.js';

const defaultVerifier = new PoDVerifier();

/**
 * Express / Connect compatible middleware for Proof-of-Delegation
 */
export function podGuard(options: PoDGuardOptions = {}) {
  const verifier = new PoDVerifier();

  return async (req: any, res: any, next: any) => {
    // Check both standard Sec- header (from Extension/Proxy) and X- header (from in-page Web Client)
    const podHeader = (req.headers['sec-proof-of-delegation'] || req.headers['x-proof-of-delegation']) as string;

    // 1. If no PoD header is provided, flag as unverified (fallback to standard anti-bot/CAPTCHA)
    if (!podHeader) {
      req.pod = { verified: false, reason: 'No Sec-Proof-Of-Delegation header' };
      if (options.onBlock) options.onBlock('Missing header');
      return next();
    }

    // 2. Perform cryptographic verification
    const expectedOrigin = options.expectedOrigin || `${req.protocol}://${req.get('host')}`;
    const result = await verifier.verifyToken(podHeader, {
      ...options,
      expectedOrigin
    });

    if (result.valid && result.claims) {
      req.pod = {
        verified: true,
        claims: result.claims,
        issuer: result.claims.iss,
        scope: result.claims.scp
      };
      if (options.onBypass) options.onBypass(result.claims);
      return next();
    }

    // Verification failed
    req.pod = {
      verified: false,
      reason: result.error,
      statusCode: result.statusCode
    };

    if (options.onBlock) options.onBlock(result.error || 'Verification failed');

    // If rate-limited or revoked, halt request immediately
    if (result.statusCode === 429) {
      return res.status(429).json({
        status: 'error',
        code: 'POD_RATE_LIMIT_EXCEEDED',
        message: result.error
      });
    }

    return next();
  };
}

export { defaultVerifier };
