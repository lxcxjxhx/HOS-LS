import { useAppStore } from '../../stores/appStore'
import {
  Orbit,
  Shield,
  Crosshair,
  MessageSquare,
  Settings,
  Code,
  ChevronLeft,
  ChevronRight,
  ListChecks,
} from 'lucide-react'
import { NavLink } from 'react-router-dom'

const navItems = [
  { icon: Orbit, label: '星图', path: '/' },
  { icon: Shield, label: '代码审计', path: '/audit' },
  { icon: Crosshair, label: '渗透测试', path: '/pentest' },
  { icon: MessageSquare, label: 'AI 对话', path: '/chat' },
  { icon: ListChecks, label: '任务管理', path: '/sessions' },
  { icon: Code, label: 'IDE', path: '/ide' },
  { icon: Settings, label: '设置', path: '/settings' },
]

export default function Sidebar() {
  const { sidebarCollapsed, toggleSidebar } = useAppStore()
  
  return (
    <nav className={`flex flex-col bg-celestial-surface border-r border-celestial-border transition-all duration-300 ${sidebarCollapsed ? 'w-16' : 'w-56'}`}>
      {/* Logo */}
      <div className="flex h-14 items-center border-b border-celestial-border px-4">
        {!sidebarCollapsed && (
          <span className="text-lg font-bold bg-gradient-to-r from-celestial-primary to-celestial-accent bg-clip-text text-transparent">
            HOS-LS
          </span>
        )}
        {sidebarCollapsed && <span className="text-lg font-bold text-celestial-accent mx-auto">H</span>}
      </div>
      
      {/* Navigation */}
      <div className="flex flex-1 flex-col gap-1 p-2">
        {navItems.map(({ icon: Icon, label, path }) => (
          <NavLink
            key={path}
            to={path}
            className={({ isActive }) =>
              `flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors ${
                isActive
                  ? 'bg-celestial-primary/20 text-celestial-accent'
                  : 'text-celestial-textDim hover:bg-celestial-surfaceLight hover:text-celestial-text'
              }`
            }
          >
            <Icon className="h-5 w-5 flex-shrink-0" />
            {!sidebarCollapsed && <span>{label}</span>}
          </NavLink>
        ))}
      </div>
      
      {/* Collapse Toggle */}
      <button
        onClick={toggleSidebar}
        className="flex items-center justify-center border-t border-celestial-border p-3 text-celestial-textDim hover:text-celestial-text"
      >
        {sidebarCollapsed ? (
          <ChevronRight className="h-5 w-5 mx-auto" />
        ) : (
          <div className="flex items-center gap-2">
            <ChevronLeft className="h-4 w-4" />
            <span className="text-xs">收起</span>
          </div>
        )}
      </button>
    </nav>
  )
}
