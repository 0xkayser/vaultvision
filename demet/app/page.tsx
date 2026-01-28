/**
 * Landing / Manifesto Page
 * 
 * Purpose: Explain the concept in under 10 seconds.
 * Frame DeMet as a fun alternative to traditional commodities.
 */

import Link from 'next/link'
import { motion } from 'framer-motion'
import { GENESIS_METALS, METAL_COLORS } from '@/lib/config'

export default function LandingPage() {
  return (
    <div className="relative min-h-screen">
      {/* Hero Section */}
      <section className="relative px-6 py-24 md:py-32 lg:py-40">
        <div className="max-w-4xl mx-auto text-center">
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="text-5xl md:text-7xl font-bold mb-6 text-balance"
          >
            The Fun Version of the{' '}
            <span className="text-gold animate-shimmer">Gold Standard</span>
          </motion.h1>
          
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.1 }}
            className="text-xl md:text-2xl text-vault-muted mb-12 max-w-2xl mx-auto text-balance"
          >
            DeMet is a playful, meme-driven clone of Pump.Science, but instead of DeSci and biochemistry,
            it represents a fun, crypto-native parody of the gold & commodity monetary standard.
          </motion.p>
          
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6, delay: 0.2 }}
          >
            <Link
              href="/vault"
              className="inline-block px-8 py-4 bg-gold text-vault-dark font-semibold rounded-lg hover:bg-gold-light transition-colors text-lg"
            >
              Enter the Vault
            </Link>
          </motion.div>
        </div>
      </section>

      {/* Explanation Block */}
      <section className="px-6 py-16 md:py-24">
        <div className="max-w-3xl mx-auto">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.6 }}
            className="bg-vault-neutral border border-vault-border rounded-2xl p-8 md:p-12"
          >
            <h2 className="text-3xl font-bold mb-6">What is DeMet?</h2>
            <div className="space-y-4 text-vault-muted leading-relaxed">
              <p>
                DeMet (MeMetals) is <strong className="text-gold">NOT real gold</strong>, NOT tokenized commodities, 
                NOT ETFs, NOT backed assets. These are purely meme tokens themed around metals and raw materials.
              </p>
              <p>
                The tone is ironic-serious: "alternative to boring traditional assets."
              </p>
              <p>
                If Pump.Science is "fun decentralized science", DeMet is "fun decentralized gold standard."
              </p>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Genesis Metals Preview */}
      <section className="px-6 py-16 md:py-24">
        <div className="max-w-6xl mx-auto">
          <motion.h2
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="text-3xl font-bold text-center mb-12"
          >
            Genesis Set
          </motion.h2>
          
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {GENESIS_METALS.map((ticker, index) => (
              <motion.div
                key={ticker}
                initial={{ opacity: 0, scale: 0.9 }}
                whileInView={{ opacity: 1, scale: 1 }}
                viewport={{ once: true }}
                transition={{ duration: 0.4, delay: index * 0.1 }}
                className="bg-vault-neutral border border-vault-border rounded-xl p-6 text-center hover:border-gold transition-colors"
                style={{ borderColor: `rgba(${ticker === 'GOLD' ? '212, 175, 55' : ticker === 'SILVER' ? '192, 192, 192' : ticker === 'PLATINUM' ? '229, 228, 226' : ticker === 'COPPER' ? '184, 115, 51' : '0, 255, 65'}, 0.3)` }}
              >
                <div
                  className="text-4xl font-bold mb-2"
                  style={{ color: METAL_COLORS[ticker] }}
                >
                  ${ticker}
                </div>
                <div className="text-sm text-vault-muted capitalize">{ticker.toLowerCase()}</div>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="px-6 py-16 md:py-24">
        <div className="max-w-2xl mx-auto text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="bg-gradient-to-r from-gold/10 via-silver/10 to-copper/10 border border-vault-border rounded-2xl p-12"
          >
            <h2 className="text-3xl font-bold mb-4">Ready to Enter the Vault?</h2>
            <p className="text-vault-muted mb-8">
              Discover, trade, and explore memetals. No real metals. Pure narrative abstraction.
            </p>
            <Link
              href="/vault"
              className="inline-block px-8 py-4 bg-gold text-vault-dark font-semibold rounded-lg hover:bg-gold-light transition-colors"
            >
              Enter the Vault
            </Link>
          </motion.div>
        </div>
      </section>
    </div>
  )
}
