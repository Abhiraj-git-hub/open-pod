export * from './types.js';
export * from './crypto.js';

import { generatePoDKeypair, createDelegationToken } from './crypto.js';
import { DelegationOptions, PoDKeypair } from './types.js';

/**
 * OpenPoD Client class for autonomous browser agents
 */
export class OpenPoDClient {
  private keypair: PoDKeypair | null = null;

  async initialize(): Promise<PoDKeypair> {
    if (!this.keypair) {
      this.keypair = await generatePoDKeypair();
    }
    return this.keypair;
  }

  getKeypair(): PoDKeypair | null {
    return this.keypair;
  }

  async createHeader(options: DelegationOptions): Promise<{ 'Sec-Proof-Of-Delegation': string }> {
    if (!this.keypair) {
      await this.initialize();
    }
    const token = await createDelegationToken(this.keypair!, options);
    return {
      'Sec-Proof-Of-Delegation': token
    };
  }
}
