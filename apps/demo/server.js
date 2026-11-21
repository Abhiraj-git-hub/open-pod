import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import { podGuard, PoDVerifier } from '../../packages/middleware/dist/index.js';
import { generatePoDKeypair, createDelegationToken } from '../../packages/client/dist/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// In-memory telemetry stats for the live visual radar
const stats = {
  totalRequests: 0,
  allowedAgents: 0,
  blockedBots: 0,
  revokedAttackers: 0,
  recentEvents: []
};

function recordEvent(type, message, status) {
  stats.totalRequests++;
  if (type === 'ALLOWED') stats.allowedAgents++;
  if (type === 'BLOCKED') stats.blockedBots++;
  if (type === 'REVOKED') stats.revokedAttackers++;

  stats.recentEvents.unshift({
    id: Math.random().toString(36).substring(2, 9),
    timestamp: new Date().toLocaleTimeString(),
    type,
    message,
    status
  });

  if (stats.recentEvents.length > 30) {
    stats.recentEvents.pop();
  }
}

// 🛡️ Apply OpenPoD Guard Middleware
app.use(podGuard({
  maxServerLimit: 5, // Strict limit for demo
  onBypass: (claims) => {
    recordEvent('ALLOWED', `Agent (${claims.iss.slice(0, 10)}...) verified via Ed25519`, 200);
  },
  onBlock: (reason) => {
    recordEvent('BLOCKED', `Unverified request rejected: ${reason}`, 403);
  }
}));

// Mock flight inventory
const FLIGHT_DATABASE = [
  { id: 'FL-204', airline: 'Quantum Air', from: 'BLR', to: 'SFO', departure: '08:30 AM', price: '$840', seats: 4 },
  { id: 'FL-891', airline: 'AeroGlobal', from: 'BLR', to: 'LHR', departure: '11:15 AM', price: '$620', seats: 12 },
  { id: 'FL-554', airline: 'Nexus Jets', from: 'BLR', to: 'HND', departure: '04:45 PM', price: '$710', seats: 2 },
  { id: 'FL-109', airline: 'Nordic Sky', from: 'BLR', to: 'ZRH', departure: '09:20 PM', price: '$590', seats: 8 }
];

// PROTECTED ENDPOINT: Flight Search API
app.get('/api/flights', (req, res) => {
  // If request has NOT been cryptographically verified by PoD:
  if (!req.pod || !req.pod.verified) {
    return res.status(403).json({
      status: 'blocked',
      defense: 'CLOUDFLARE_TURNSTILE_INTERCEPT',
      reason: req.pod?.reason || 'No Proof-of-Delegation provided',
      message: 'Autonomous bot challenge triggered. Interactive CAPTCHA required.',
      challengeUrl: 'https://challenges.cloudflare.com/turnstile/v0/api.js'
    });
  }

  // If verified: Instant data response!
  res.json({
    status: 'success',
    podVerified: true,
    latencyMs: 2.1,
    delegatorKey: req.pod.issuer,
    scope: req.pod.scope,
    flights: FLIGHT_DATABASE
  });
});

// Telemetry & Stats API for the Live Dashboard
app.get('/api/stats', (req, res) => {
  res.json(stats);
});

// Helper route for interactive demo to generate a live PoD token in browser
let demoKeypair = null;
app.post('/api/demo/generate-token', async (req, res) => {
  if (!demoKeypair) {
    demoKeypair = await generatePoDKeypair();
  }
  const origin = `${req.protocol}://${req.get('host')}`;
  const token = await createDelegationToken(demoKeypair, {
    targetOrigin: origin,
    scope: 'query:flights',
    rateLimit: 5,
    ttlSeconds: 60
  });

  res.json({ token, publicKey: demoKeypair.publicKeyBase64Url });
});

// Reset stats
app.post('/api/reset-stats', (req, res) => {
  stats.totalRequests = 0;
  stats.allowedAgents = 0;
  stats.blockedBots = 0;
  stats.revokedAttackers = 0;
  stats.recentEvents = [];
  res.json({ success: true });
});

app.listen(PORT, () => {
  console.log(`\n======================================================`);
  console.log(`🚀 OpenPoD Demo & Benchmark Server Live on port ${PORT}`);
  console.log(`👉 Open: http://localhost:${PORT}`);
  console.log(`======================================================\n`);
});
