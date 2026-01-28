/**
 * Asset Page (Per Metal)
 * 
 * Purpose: Deep dive into one memetal.
 * Sections: Lore, Chart, Buy/Sell widget, Stats, Activity feed, Status indicator.
 */

'use client'

import { useState, useEffect } from 'react'
import { useParams } from 'next/navigation'
import { motion } from 'framer-motion'
import { Memetal, MetalTicker } from '@/lib/types'
import { METAL_CONFIG, generateMockMemetal, METAL_ACCENTS, METAL_COLORS } from '@/lib/config'
import { formatPrice, formatMarketCap, formatVolume } from '@/lib/utils'
import { AssetHeader } from '@/components/asset/AssetHeader'
import { AssetChart } from '@/components/asset/AssetChart'
import { BuySellWidget } from '@/components/asset/BuySellWidget'
import { ActivityFeed } from '@/components/asset/ActivityFeed'
import { AssetStats } from '@/components/asset/AssetStats'
import { StatusIndicator } from '@/components/asset/StatusIndicator'

export default function AssetPage() {
  const params = useParams()
  const ticker = (params.ticker as string).toUpperCase() as MetalTicker
  const [metal, setMetal] = useState<Memetal | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Simulate loading
    setTimeout(() => {
      const data = generateMockMemetal(ticker)
      setMetal(data)
      setLoading(false)
    }, 500)
  }, [ticker])

  if (loading || !metal) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-vault-muted">Loading asset...</div>
      </div>
    )
  }

  const accent = METAL_ACCENTS[ticker]

  return (
    <div className="min-h-screen px-6 py-12 md:py-16">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className="mb-8"
        >
          <AssetHeader metal={metal} />
        </motion.div>

        {/* Status Indicator */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className="mb-8"
        >
          <StatusIndicator status={metal.status} momentum={metal.momentum} />
        </motion.div>

        {/* Lore Section */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className="bg-vault-neutral border border-vault-border rounded-xl p-6 md:p-8 mb-8"
          style={{ borderColor: accent.border }}
        >
          <h2 className="text-xl font-semibold mb-4" style={{ color: accent.text }}>
            Lore
          </h2>
          <p className="text-vault-muted leading-relaxed mb-4">{metal.lore}</p>
          <p className="text-vault-muted leading-relaxed">{metal.description}</p>
        </motion.div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Chart - Takes 2 columns */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.3 }}
            className="lg:col-span-2"
          >
            <div className="bg-vault-neutral border border-vault-border rounded-xl p-6">
              <h3 className="text-lg font-semibold mb-4">Price Chart</h3>
              <AssetChart metal={metal} />
            </div>
          </motion.div>

          {/* Buy/Sell Widget */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 }}
          >
            <BuySellWidget metal={metal} />
          </motion.div>
        </div>

        {/* Stats Grid */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.5 }}
          className="mb-8"
        >
          <AssetStats metal={metal} />
        </motion.div>

        {/* Activity Feed */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.6 }}
        >
          <ActivityFeed activities={metal.recentActivity} />
        </motion.div>
      </div>
    </div>
  )
}
