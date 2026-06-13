interface MainContentProps {
  children: React.ReactNode
}

export default function MainContent({ children }: MainContentProps) {
  return (
    <main className="flex-1 overflow-auto p-4">
      {children}
    </main>
  )
}
