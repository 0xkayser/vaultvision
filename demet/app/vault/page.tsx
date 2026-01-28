/**
 * Vault Dashboard (Main Page)
 * 
 * Purpose: Show all available memetals.
 * This is the main trading discovery surface.
 */

'use client'

import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import Link from 'next/link'
import { Memetal, MetalTicker } from '@/lib/types'
import { GENESIS_METALS, generateMockMemetal, METAL_ACCENTS } from '@/lib/config'
import { AssetCard } from '@/components/vault/AssetCard'
import { formatPrice, formatMarketCap, formatVolume } from '@/lib/utils'

export default function VaultPage() {
  const [memetals, setMemetals] = useState<Memetal[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Simulate loading
    setTimeout(() => {
      const data = GENESIS_METALS.map(ticker => generateMockMemetal(ticker))
      setMemetals(data)
      setLoading(false)
    }, 500)
  }, [])

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-vault-muted">Loading vault...</div>
      </div>
    )
  }

  return (
    <div className="min-h-screen px-6 py-12 md:py-16">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-12"
        >
          <h1 className="text-4xl md:text-5xl font-bold mb-4">The Vault</h1>
          <p className="text-vault-muted text-lg">
            All available memetals. Click any asset to explore.
          </p>
        </motion.div>

        {/* Stats Summary */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="grid grid-cols-1 md:grid-cols-3 gap-6 mb-12"
        >
          <div className="bg-vault-neutral border border-vault-border rounded-xl p-6">
            <div className="text-sm text-vault-muted mb-2">Total Market Cap</div>
            <div className="text-2xl font-bold">
              {formatMarketCap(memetals.reduce((sum, m) => sum + m.marketCap, 0))}
            </div>
          </div>
          <div className="bg-vault-neutral border border-vault-border rounded-xl p-6">
            <div className="text-sm text-vault-muted mb-2">24h Volume</div>
            <div className="text-2xl font-bold">
              {formatVolume(memetals.reduce((sum, m) => sum + m.volume24h, 0))}
            </div>
          </div>
          <div className="bg-vault-neutral border border-vault-border rounded-xl p-6">
            <div className="text-sm text-vault-muted mb-2">Active Assets</div>
            <div className="text-2xl font-bold">{memetals.length}</div>
          </div>
        </motion.div>

        {/* Asset Grid */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.2 }}
          className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"
        >
          {memetals.map((metal, index) => (
            <motion.div
              key={metal.ticker}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 * index }}
            >
              <Link href={`/asset/${metal.ticker.toLowerCase()}`}>
                <AssetCard metal={metal} />
              </Link>
            </motion.div>
          ))}
        </motion.div>
      </div>
    </div>
  )
}
