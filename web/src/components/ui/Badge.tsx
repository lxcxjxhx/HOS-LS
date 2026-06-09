interface BadgeProps {
  children: React.ReactNode
  variant?: 'default' | 'severity' | 'status'
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'info'
  className?: string
}

export function Badge({ children, variant = 'default', severity, className = '' }: BadgeProps) {
  const base = 'inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium'
  
  let colors = 'bg-celestial-surfaceLight text-celestial-text'
  
  if (variant === 'severity' && severity) {
    switch (severity) {
      case 'critical': colors = 'bg-red-900/50 text-red-300 border border-red-800'
        break
      case 'high': colors = 'bg-celestial-star-high/20 text-celestial-star-high border border-celestial-star-high/30'
        break
      case 'medium': colors = 'bg-celestial-star-medium/20 text-celestial-star-medium border border-celestial-star-medium/30'
        break
      case 'low': colors = 'bg-celestial-star-low/20 text-celestial-star-low border border-celestial-star-low/30'
        break
      case 'info': colors = 'bg-celestial-star-safe/20 text-celestial-star-safe border border-celestial-star-safe/30'
        break
    }
  }
  
  if (variant === 'status') {
    colors = 'bg-celestial-primary/20 text-celestial-accent border border-celestial-primary/30'
  }
  
  return <span className={`${base} ${colors} ${className}`}>{children}</span>
}
