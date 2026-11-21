/**
 * Memory-backed Sliding Window Rate Limiter & Key Revocation Tracker
 */
export class PoDRateLimiter {
  private keyWindows: Map<string, number[]> = new Map();
  private revokedKeys: Map<string, number> = new Map(); // key -> revocation expiry
  private cleanupInterval: any;

  constructor() {
    // Clean up expired records every 60 seconds
    this.cleanupInterval = setInterval(() => this.cleanup(), 60000);
    if (this.cleanupInterval && typeof this.cleanupInterval.unref === 'function') {
      this.cleanupInterval.unref();
    }
  }

  /**
   * Checks if an issuer key is currently revoked / blacklisted
   */
  isRevoked(iss: string): boolean {
    const expiry = this.revokedKeys.get(iss);
    if (!expiry) return false;
    if (Date.now() > expiry) {
      this.revokedKeys.delete(iss);
      return false;
    }
    return true;
  }

  /**
   * Tracks request and evaluates rate limit
   * Returns: { allowed: boolean, currentCount: number, revoked: boolean }
   */
  checkAndRecord(iss: string, limit: number): { allowed: boolean; currentCount: number; revoked: boolean } {
    if (this.isRevoked(iss)) {
      return { allowed: false, currentCount: -1, revoked: true };
    }

    const now = Date.now();
    const windowStart = now - 60000; // 60-second sliding window

    let timestamps = this.keyWindows.get(iss) || [];
    // Filter out timestamps older than 60s
    timestamps = timestamps.filter(t => t > windowStart);

    const currentCount = timestamps.length + 1;

    // Check if limit exceeded
    if (currentCount > limit) {
      // If someone sends more than 2x their limit, revoke the key for 5 minutes
      if (currentCount > limit * 2) {
        this.revokedKeys.set(iss, now + 300000); // 5-minute ban
        this.keyWindows.delete(iss);
        return { allowed: false, currentCount, revoked: true };
      }
      return { allowed: false, currentCount, revoked: false };
    }

    timestamps.push(now);
    this.keyWindows.set(iss, timestamps);
    return { allowed: true, currentCount, revoked: false };
  }

  private cleanup() {
    const now = Date.now();
    const windowStart = now - 60000;

    for (const [key, timestamps] of this.keyWindows.entries()) {
      const active = timestamps.filter(t => t > windowStart);
      if (active.length === 0) {
        this.keyWindows.delete(key);
      } else {
        this.keyWindows.set(key, active);
      }
    }

    for (const [key, expiry] of this.revokedKeys.entries()) {
      if (now > expiry) {
        this.revokedKeys.delete(key);
      }
    }
  }
}
