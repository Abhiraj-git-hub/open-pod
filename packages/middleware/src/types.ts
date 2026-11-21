export interface PoDClaims {
  iss: string;       // Base64URL-encoded Ed25519 public key
  aud: string;       // Target origin
  iat: number;       // Issued at (seconds)
  exp: number;       // Expiration time (seconds)
  jti: string;       // Cryptographic nonce
  lim: number;       // Declared rate limit
  scp: string;       // Scope
}

export interface VerificationResult {
  valid: boolean;
  claims?: PoDClaims;
  error?: string;
  statusCode?: number;
}

export interface PoDGuardOptions {
  expectedOrigin?: string;
  maxServerLimit?: number;      // Maximum allowed requests per minute (e.g. 15)
  requiredScope?: string;       // Required scope (optional)
  onBypass?: (claims: PoDClaims) => void;
  onBlock?: (reason: string) => void;
}
