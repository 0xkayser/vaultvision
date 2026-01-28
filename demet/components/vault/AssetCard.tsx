'use client'

import { Memetal } from '@/lib/types'
import { METAL_ACCENTS } from '@/lib/config'
import { formatPrice, formatMarketCap } from '@/lib/utils'
import { motion } from 'framer-motion'

interface AssetCardProps {
  metal: Memetal
}

export function AssetCard({ metal }: AssetCardProps) {
  const accent = METAL_ACCENTS[metal.ticker]
  const isPositive = metal.momentum === 'Melting' || metal.momentum === 'Overheated'

  return (
    <motion.div
      whileHover={{ y: -4 }}
      className="bg-vault-neutral border border-vault-border rounded-xl p-6 cursor-pointer transition-all hover:border-gold/50"
      style={{ borderColor: accent.border }}
    >
      {/* Header */}
      <div className="flex items-start justify-between mb-4">
        <div>
          <div className="flex items-center gap-2 mb-2">
            <h3 className="text-xl font-bold" style={{ color: accent.text }}>
              {metal.symbol}
            </h3>
            <span className="text-xs px-2 py-1 rounded-full bg-vault-darker text-vault-muted">
              {metal.name}
            </span>
          </div>
          <p className="text-sm text-vault-muted">{metal.lore}</p>
        </div>
      </div>

      {/* Price */}
      <div className="mb-4">
        <div className="text-sm text-vault-muted mb-1">Price</div>
        <div className="text-2xl font-bold">{formatPrice(metal.price)}</div>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 gap-4 mb-4">
        <div>
          <div className="text-xs text-vault-muted mb-1">Market Cap</div>
          <div className="text-sm font-semibold">{formatMarketCap(metal.marketCap)}</div>
        </div>
        <div>
          <div className="text-xs text-vault-muted mb-1">24h Volume</div>
          <div className="text-sm font-semibold">{formatMarketCap(metal.volume24h)}</div>
        </div>
      </div>

      {/* Momentum Indicator */}
      <div className="flex items-center justify-between pt-4 border-t border-vault-border">
        <div className="text-xs text-vault-muted">Momentum</div>
        <div
          className={`text-xs font-semibold px-2 py-1 rounded ${
            isPositive ? 'bg-emerald-500/20 text-emerald-400' : 'bg-vault-muted/20 text-vault-muted'
          }`}
        >
          {metal.momentum}
        </div>
      </div>
    </motion.div>
  )
}
