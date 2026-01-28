/**
 * About / Disclaimer Page
 * 
 * Purpose: Explicitly clarify no backing, no real metals, meme-only.
 * Done with humor, not legal dryness.
 */

import { motion } from 'framer-motion'
import Link from 'next/link'

export default function AboutPage() {
  return (
    <div className="min-h-screen px-6 py-12 md:py-16">
      <div className="max-w-3xl mx-auto">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
        >
          <h1 className="text-4xl md:text-5xl font-bold mb-8">About DeMet</h1>

          <div className="space-y-8">
            {/* What is DeMet */}
            <section className="bg-vault-neutral border border-vault-border rounded-xl p-6 md:p-8">
              <h2 className="text-2xl font-semibold mb-4">What is DeMet?</h2>
              <p className="text-vault-muted leading-relaxed mb-4">
                DeMet (MeMetals) is a playful, meme-driven platform inspired by Pump.Science. 
                Instead of decentralized science, we're doing decentralized gold standard. 
                But make it fun. And make it memes.
              </p>
              <p className="text-vault-muted leading-relaxed">
                We're crypto-native traders, degens, meme traders. Not institutions. Not normies.
              </p>
            </section>

            {/* Important Disclaimers */}
            <section className="bg-vault-neutral border border-gold/30 rounded-xl p-6 md:p-8">
              <h2 className="text-2xl font-semibold mb-4 text-gold">⚠️ Important Disclaimers</h2>
              <div className="space-y-4 text-vault-muted leading-relaxed">
                <p>
                  <strong className="text-gold">This is NOT real gold.</strong> Not tokenized commodities. 
                  Not ETFs. Not backed assets. These are purely meme tokens themed around metals and raw materials.
                </p>
                <p>
                  <strong className="text-gold">NO REAL-WORLD PEGS.</strong> NO PRICE TRACKING TO REAL METALS. 
                  Pure narrative abstraction.
                </p>
                <p>
                  <strong className="text-gold">This is experimental.</strong> This is risky. This is for degens only. 
                  Don't invest more than you can afford to lose. Actually, don't invest at all if you're not 
                  comfortable with losing everything.
                </p>
                <p>
                  <strong className="text-gold">We're not financial advisors.</strong> We're not even trying to be. 
                  This is a meme. Treat it like one.
                </p>
              </div>
            </section>

            {/* How It Works */}
            <section className="bg-vault-neutral border border-vault-border rounded-xl p-6 md:p-8">
              <h2 className="text-2xl font-semibold mb-4">How It Works</h2>
              <div className="space-y-4 text-vault-muted leading-relaxed">
                <p>
                  DeMet uses a bonding curve model similar to Pump.fun / Pump.Science. Each memetal has its own 
                  bonding curve. Buy tokens, the price goes up. Sell tokens, the price goes down. Simple.
                </p>
                <p>
                  The genesis set includes $GOLD, $SILVER, $PLATINUM, $COPPER, and $URANIUM. These are 
                  protocol-launched tokens. No user-created base assets in v1.
                </p>
                <p>
                  All built on Solana. Fast, cheap, and ready for degens.
                </p>
              </div>
            </section>

            {/* Tone */}
            <section className="bg-vault-neutral border border-vault-border rounded-xl p-6 md:p-8">
              <h2 className="text-2xl font-semibold mb-4">The Tone</h2>
              <p className="text-vault-muted leading-relaxed">
                Ironic-serious. "Alternative to boring traditional assets." We're not trying to replace 
                gold. We're trying to make fun of the idea that gold (or any commodity) is a "safe" investment. 
                Everything is a meme. Even gold. Especially gold.
              </p>
            </section>

            {/* CTA */}
            <div className="text-center pt-8">
              <Link
                href="/vault"
                className="inline-block px-8 py-4 bg-gold text-vault-dark font-semibold rounded-lg hover:bg-gold-light transition-colors"
              >
                Enter the Vault
              </Link>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}
