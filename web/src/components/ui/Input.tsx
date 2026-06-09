import { forwardRef } from 'react'

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string
}

const Input = forwardRef<HTMLInputElement, InputProps>(
  ({ className = '', label, ...props }, ref) => {
    return (
      <div className="w-full">
        {label && (
          <label className="mb-1.5 block text-sm text-celestial-textDim">{label}</label>
        )}
        <input
          ref={ref}
          className={`w-full rounded-md border border-celestial-border bg-celestial-bg px-3 py-2 text-sm text-celestial-text placeholder:text-celestial-textDim focus:border-celestial-primary focus:outline-none focus:ring-1 focus:ring-celestial-primary/50 ${className}`}
          {...props}
        />
      </div>
    )
  }
)
Input.displayName = 'Input'

export { Input }
