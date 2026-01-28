'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import { useWallet } from '@solana/wallet-adapter-react'
import { WalletMultiButton } from '@solana/wallet-adapter-react-ui'
import { motion } from 'framer-motion'

export function Navigation() {
  const pathname = usePathname()
  const { connected } = useWallet()

  const navItems = [
    { href: '/', label: 'Home' },
    { href: '/vault', label: 'Vault' },
    { href: '/about', label: 'About' },
  ]

  return (
    <nav className="sticky top-0 z-50 bg-vault-darker/80 backdrop-blur-lg border-b border-vault-border">
      <div className="max-w-7xl mx-auto px-6 py-4">
        <div className="flex items-center justify-between">
          {/* Logo */}
          <Link href="/" className="flex items-center gap-2">
            <div className="w-10 h-10 bg-gradient-to-br from-gold to-copper rounded-lg flex items-center justify-center font-bold text-vault-dark">
              DM
            </div>
            <span className="text-xl font-bold">DeMet</span>
          </Link>

          {/* Nav Links */}
          <div className="hidden md:flex items-center gap-6">
            {navItems.map((item) => {
              const isActive = pathname === item.href || (item.href !== '/' && pathname?.startsWith(item.href))
              return (
                <Link
                  key={item.href}
                  href={item.href}
                  className={`text-sm font-medium transition-colors ${
                    isActive
                      ? 'text-gold'
                      : 'text-vault-muted hover:text-white'
                  }`}
                >
                  {item.label}
                </Link>
              )
            })}
          </div>

          {/* Wallet Button */}
          <div className="flex items-center gap-4">
            {connected && (
              <div className="hidden md:block text-sm text-vault-muted">
                Connected
              </div>
            )}
            <WalletMultiButton className="!bg-vault-neutral !text-white hover:!bg-vault-border !rounded-lg !h-10 !px-4 !text-sm !font-medium" />
          </div>
        </div>
      </div>
    </nav>
  )
}
