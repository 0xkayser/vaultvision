'use client'

import { Memetal } from '@/lib/types'
import { METAL_ACCENTS } from '@/lib/config'
import { formatPrice, formatMarketCap } from '@/lib/utils'

interface AssetHeaderProps {
  metal: Memetal
}

export function AssetHeader({ metal }: AssetHeaderProps) {
  const accent = METAL_ACCENTS[metal.ticker]

  return (
    <div className="bg-vault-neutral border border-vault-border rounded-xl p-6 md:p-8" style={{ borderColor: accent.border }}>
      <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-6">
        <div>
          <div className="flex items-center gap-3 mb-2">
            <h1 className="text-3xl md:text-4xl font-bold" style={{ color: accent.text }}>
              {metal.symbol}
            </h1>
            <span className="text-sm px-3 py-1 rounded-full bg-vault-darker text-vault-muted">
              {metal.name}
            </span>
          </div>
          <p className="text-vault-muted">{metal.lore}</p>
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <div>
            <div className="text-xs text-vault-muted mb-1">Price</div>
            <div className="text-xl font-bold">{formatPrice(metal.price)}</div>
          </div>
          <div>
            <div className="text-xs text-vault-muted mb-1">Market Cap</div>
            <div className="text-xl font-bold">{formatMarketCap(metal.marketCap)}</div>
          </div>
          <div className="col-span-2 md:col-span-1">
            <div className="text-xs text-vault-muted mb-1">Holders</div>
            <div className="text-xl font-bold">{metal.holders.toLocaleString()}</div>
          </div>
        </div>
      </div>
    </div>
  )
}
