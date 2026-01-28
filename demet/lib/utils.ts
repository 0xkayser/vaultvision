/**
 * Utility Functions
 */

export function formatPrice(price: number): string {
  if (price < 0.000001) {
    return `$${price.toExponential(2)}`
  }
  if (price < 0.01) {
    return `$${price.toFixed(6)}`
  }
  if (price < 1) {
    return `$${price.toFixed(4)}`
  }
  return `$${price.toFixed(2)}`
}

export function formatMarketCap(mcap: number): string {
  if (mcap >= 1e9) {
    return `$${(mcap / 1e9).toFixed(2)}B`
  }
  if (mcap >= 1e6) {
    return `$${(mcap / 1e6).toFixed(2)}M`
  }
  if (mcap >= 1e3) {
    return `$${(mcap / 1e3).toFixed(2)}K`
  }
  return `$${mcap.toFixed(2)}`
}

export function formatVolume(volume: number): string {
  return formatMarketCap(volume)
}

export function formatNumber(num: number): string {
  if (num >= 1e9) {
    return `${(num / 1e9).toFixed(2)}B`
  }
  if (num >= 1e6) {
    return `${(num / 1e6).toFixed(2)}M`
  }
  if (num >= 1e3) {
    return `${(num / 1e3).toFixed(2)}K`
  }
  return num.toFixed(2)
}

export function truncateAddress(address: string, start = 4, end = 4): string {
  if (address.length <= start + end) return address
  return `${address.slice(0, start)}...${address.slice(-end)}`
}

export function formatTimestamp(timestamp: number): string {
  const date = new Date(timestamp)
  const now = Date.now()
  const diff = now - timestamp
  
  if (diff < 60000) {
    return 'Just now'
  }
  if (diff < 3600000) {
    return `${Math.floor(diff / 60000)}m ago`
  }
  if (diff < 86400000) {
    return `${Math.floor(diff / 3600000)}h ago`
  }
  return date.toLocaleDateString()
}
