interface CardProps {
  children: React.ReactNode
  className?: string
  title?: string
}

export function Card({ children, className = '', title }: CardProps) {
  return (
    <div className={`rounded-lg border border-celestial-border bg-celestial-surface ${className}`}>
      {title && (
        <div className="border-b border-celestial-border px-4 py-3">
          <h3 className="text-sm font-medium text-celestial-text">{title}</h3>
        </div>
      )}
      <div className="p-4">{children}</div>
    </div>
  )
}
