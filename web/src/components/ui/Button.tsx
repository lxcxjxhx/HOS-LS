import { forwardRef } from 'react'

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost'
  size?: 'sm' | 'md' | 'lg'
}

const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className = '', variant = 'primary', size = 'md', ...props }, ref) => {
    const base = 'inline-flex items-center justify-center rounded-md font-medium transition-colors focus:outline-none focus:ring-2 focus:ring-celestial-primary/50 disabled:pointer-events-none disabled:opacity-50'
    
    const variants = {
      primary: 'bg-celestial-primary text-white hover:bg-celestial-primaryLight',
      secondary: 'border border-celestial-border bg-celestial-surface text-celestial-text hover:bg-celestial-surfaceLight',
      danger: 'bg-celestial-alert text-white hover:bg-celestial-alertLight',
      ghost: 'text-celestial-textDim hover:bg-celestial-surfaceLight hover:text-celestial-text',
    }
    
    const sizes = {
      sm: 'h-8 px-3 text-xs',
      md: 'h-10 px-4 text-sm',
      lg: 'h-12 px-6 text-base',
    }
    
    return (
      <button
        ref={ref}
        className={`${base} ${variants[variant]} ${sizes[size]} ${className}`}
        {...props}
      />
    )
  }
)
Button.displayName = 'Button'

export { Button }
