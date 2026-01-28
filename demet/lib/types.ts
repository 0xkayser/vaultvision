/**
 * DeMet (MeMetals) - Core Data Models
 * 
 * These types define the structure for memetals, bonding curves,
 * and on-chain interactions.
 */

export type MetalTicker = 'GOLD' | 'SILVER' | 'PLATINUM' | 'COPPER' | 'URANIUM';

export type MomentumStatus = 'Cold' | 'Heating' | 'Melting' | 'Overheated';

export type AssetStatus = 'Stable' | 'Heating' | 'Overheated';

export interface Memetal {
  ticker: MetalTicker;
  name: string;
  symbol: string; // e.g., "$GOLD"
  
  // Price & Market Data
  price: number; // Current price in SOL
  marketCap: number; // Total market cap
  
  // Bonding Curve State
  supply: number; // Current supply
  reserve: number; // Reserve SOL in bonding curve
  
  // Status Indicators
  momentum: MomentumStatus;
  status: AssetStatus;
  
  // Metadata
  lore: string; // Short narrative description
  description: string; // Longer description
  
  // On-chain
  mintAddress?: string; // Solana mint address
  bondingCurveAddress?: string; // Bonding curve program address
  
  // Activity
  recentActivity: ActivityEvent[];
  
  // Stats
  volume24h: number;
  holders: number;
  createdAt: number; // Unix timestamp
}

export interface ActivityEvent {
  type: 'buy' | 'sell';
  amount: number; // SOL amount
  tokens: number; // Token amount
  price: number; // Price per token
  user: string; // Wallet address (truncated)
  timestamp: number;
}

export interface BondingCurveParams {
  // Simplified bonding curve model
  // Price = reserve / supply (linear)
  reserve: number;
  supply: number;
  virtualReserve?: number; // For more complex curves
  virtualSupply?: number;
}

export interface PriceHistoryPoint {
  timestamp: number;
  price: number;
  volume: number;
}

export interface ChartData {
  price: PriceHistoryPoint[];
  volume: PriceHistoryPoint[];
  marketCap: PriceHistoryPoint[];
}

export interface WalletState {
  connected: boolean;
  address: string | null;
  balance: number; // SOL balance
  holdings: Record<MetalTicker, number>; // Token holdings per metal
}

export interface BuySellParams {
  metal: MetalTicker;
  amount: number; // SOL amount (for buy) or token amount (for sell)
  type: 'buy' | 'sell';
}

export interface TransactionResult {
  success: boolean;
  signature?: string;
  error?: string;
  newBalance?: number;
  newHoldings?: Record<MetalTicker, number>;
}
