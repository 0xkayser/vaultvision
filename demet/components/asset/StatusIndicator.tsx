'use client'

import { AssetStatus, MomentumStatus } from '@/lib/types'

interface StatusIndicatorProps {
  status: AssetStatus
  momentum: MomentumStatus
}

export function StatusIndicator({ status, momentum }: StatusIndicatorProps) {
  const getStatusColor = () => {
    switch (status) {
      case 'Stable':
        return 'bg-vault-muted/20 text-vault-muted border-vault-border'
      case 'Heating':
        return 'bg-amber-500/20 text-amber-400 border-amber-500/30'
      case 'Overheated':
        return 'bg-rose-500/20 text-rose-400 border-rose-500/30'
      default:
        return 'bg-vault-muted/20 text-vault-muted border-vault-border'
    }
  }

  const getMomentumColor = () => {
    switch (momentum) {
      case 'Cold':
        return 'text-blue-400'
      case 'Heating':
        return 'text-amber-400'
      case 'Melting':
        return 'text-orange-400'
      case 'Overheated':
        return 'text-rose-400'
      default:
        return 'text-vault-muted'
    }
  }

  return (
    <div className="flex items-center gap-4">
      <div className={`px-4 py-2 rounded-lg border ${getStatusColor()}`}>
        <span className="text-sm font-semibold">Status: {status}</span>
      </div>
      <div className={`text-sm font-medium ${getMomentumColor()}`}>
        Momentum: {momentum}
      </div>
    </div>
  )
}
