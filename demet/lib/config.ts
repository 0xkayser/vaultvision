/**
 * DeMet Configuration
 * 
 * Genesis set of memetals and their initial configuration.
 */

import { Memetal, MetalTicker } from './types';

export const GENESIS_METALS: MetalTicker[] = [
  'GOLD',
  'SILVER',
  'PLATINUM',
  'COPPER',
  'URANIUM',
];

export const METAL_CONFIG: Record<MetalTicker, Omit<Memetal, 'price' | 'marketCap' | 'supply' | 'reserve' | 'momentum' | 'status' | 'recentActivity' | 'volume24h' | 'holders'>> = {
  GOLD: {
    ticker: 'GOLD',
    name: 'Gold',
    symbol: '$GOLD',
    lore: 'The classic. The standard. The meme.',
    description: 'The original memetal. What else needs to be said?',
  },
  SILVER: {
    ticker: 'SILVER',
    name: 'Silver',
    symbol: '$SILVER',
    lore: 'Gold\'s rebellious younger sibling.',
    description: 'For those who prefer the underdog narrative.',
  },
  PLATINUM: {
    ticker: 'PLATINUM',
    name: 'Platinum',
    symbol: '$PLATINUM',
    lore: 'Rare. Precious. Overpriced.',
    description: 'The premium memetal for premium degens.',
  },
  COPPER: {
    ticker: 'COPPER',
    name: 'Copper',
    symbol: '$COPPER',
    lore: 'The people\'s metal. The infrastructure play.',
    description: 'Not flashy, but essential. Like good code.',
  },
  URANIUM: {
    ticker: 'URANIUM',
    name: 'Uranium',
    symbol: '$URANIUM',
    lore: 'Radioactive. Volatile. Unpredictable.',
    description: 'For the truly degenerate. Handle with care.',
  },
};

export const METAL_COLORS: Record<MetalTicker, string> = {
  GOLD: '#d4af37',
  SILVER: '#c0c0c0',
  PLATINUM: '#e5e4e2',
  COPPER: '#b87333',
  URANIUM: '#00ff41',
};

export const METAL_ACCENTS: Record<MetalTicker, { bg: string; text: string; border: string }> = {
  GOLD: {
    bg: 'rgba(212, 175, 55, 0.1)',
    text: '#d4af37',
    border: 'rgba(212, 175, 55, 0.3)',
  },
  SILVER: {
    bg: 'rgba(192, 192, 192, 0.1)',
    text: '#c0c0c0',
    border: 'rgba(192, 192, 192, 0.3)',
  },
  PLATINUM: {
    bg: 'rgba(229, 228, 226, 0.1)',
    text: '#e5e4e2',
    border: 'rgba(229, 228, 226, 0.3)',
  },
  COPPER: {
    bg: 'rgba(184, 115, 51, 0.1)',
    text: '#b87333',
    border: 'rgba(184, 115, 51, 0.3)',
  },
  URANIUM: {
    bg: 'rgba(0, 255, 65, 0.1)',
    text: '#00ff41',
    border: 'rgba(0, 255, 65, 0.3)',
  },
};

// Mock data generators (for development)
// In production, these would fetch from on-chain sources
export function generateMockMemetal(ticker: MetalTicker): Memetal {
  const base = METAL_CONFIG[ticker];
  const now = Date.now();
  
  // Simulate bonding curve state
  const baseSupply = 1000000 + Math.random() * 5000000;
  const baseReserve = 10 + Math.random() * 100;
  const price = baseReserve / baseSupply;
  const marketCap = price * baseSupply;
  
  // Simulate momentum based on recent price movement
  const momentumRand = Math.random();
  const momentum: Memetal['momentum'] = 
    momentumRand < 0.3 ? 'Cold' :
    momentumRand < 0.6 ? 'Heating' :
    momentumRand < 0.85 ? 'Melting' : 'Overheated';
  
  const status: Memetal['status'] = 
    momentum === 'Cold' || momentum === 'Heating' ? 'Stable' :
    momentum === 'Melting' ? 'Heating' : 'Overheated';
  
  // Generate recent activity
  const recentActivity: Memetal['recentActivity'] = Array.from({ length: 10 }, (_, i) => ({
    type: Math.random() > 0.5 ? 'buy' : 'sell',
    amount: 0.1 + Math.random() * 5,
    tokens: Math.random() * 10000,
    price: price * (0.9 + Math.random() * 0.2),
    user: `${Math.random().toString(36).substring(2, 6)}...${Math.random().toString(36).substring(2, 6)}`,
    timestamp: now - (i * 60000), // Last 10 minutes
  }));
  
  return {
    ...base,
    price,
    marketCap,
    supply: baseSupply,
    reserve: baseReserve,
    momentum,
    status,
    recentActivity,
    volume24h: 50 + Math.random() * 200,
    holders: 100 + Math.floor(Math.random() * 1000),
    createdAt: now - (30 + Math.random() * 60) * 24 * 60 * 60 * 1000, // 30-90 days ago
  };
}
