import type { Metadata } from 'next'
import './globals.css'
import { WalletProvider } from '@/components/providers/WalletProvider'
import { Navigation } from '@/components/layout/Navigation'

export const metadata: Metadata = {
  title: 'DeMet — The Fun Version of the Gold Standard',
  description: 'Meme-driven memetals. Crypto-native parody of the gold & commodity monetary standard.',
  keywords: ['crypto', 'memetals', 'solana', 'defi', 'meme tokens'],
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body>
        <WalletProvider>
          <div className="min-h-screen bg-vault-dark">
            <Navigation />
            <main className="relative">
              {children}
            </main>
          </div>
        </WalletProvider>
      </body>
    </html>
  )
}
