import { Search, Bell, FolderOpen } from 'lucide-react'
import { useAppStore } from '../../stores/appStore'

export default function TopBar() {
  const { currentProject } = useAppStore()
  
  return (
    <header className="flex h-12 items-center justify-between border-b border-celestial-border bg-celestial-surface px-4">
      <div className="flex items-center gap-4">
        <button className="flex items-center gap-2 rounded-md border border-celestial-border px-3 py-1.5 text-sm text-celestial-textDim hover:text-celestial-text">
          <FolderOpen className="h-4 w-4" />
          <span>{currentProject || '选择项目'}</span>
        </button>
      </div>
      
      <div className="flex items-center gap-4">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-celestial-textDim" />
          <input
            type="text"
            placeholder="搜索资产、漏洞..."
            className="w-64 rounded-md border border-celestial-border bg-celestial-bg py-1.5 pl-8 pr-4 text-sm text-celestial-text placeholder:text-celestial-textDim focus:border-celestial-primary focus:outline-none"
          />
        </div>
        <button className="relative text-celestial-textDim hover:text-celestial-text">
          <Bell className="h-5 w-5" />
          <span className="absolute -right-1 -top-1 h-2 w-2 rounded-full bg-celestial-accent" />
        </button>
      </div>
    </header>
  )
}
