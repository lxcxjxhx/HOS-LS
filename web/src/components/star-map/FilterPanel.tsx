import { useState } from 'react'
import type { FilterState } from './types'
import { SEVERITY_COLORS, SEVERITY_LABELS, NODE_TYPE_LABELS } from './types'
import { X, Search, Filter, RotateCcw } from 'lucide-react'

interface FilterPanelProps {
  filter: FilterState
  setFilter: (f: FilterState) => void
  applyFilters: () => void
  resetFilters: () => void
  onClose: () => void
  availableModules: string[]
}

export default function FilterPanel({ filter, setFilter, applyFilters, resetFilters, onClose, availableModules }: FilterPanelProps) {
  const [search, setSearch] = useState(filter.searchQuery)

  const toggleSeverity = (sev: string) => {
    const next = new Set(filter.severities)
    if (next.has(sev as any)) next.delete(sev as any)
    else next.add(sev as any)
    setFilter({ ...filter, severities: next })
  }

  const toggleNodeType = (type: string) => {
    const next = new Set(filter.nodeTypes)
    if (next.has(type)) next.delete(type)
    else next.add(type)
    setFilter({ ...filter, nodeTypes: next })
  }

  const toggleModule = (mod: string) => {
    const next = new Set(filter.modules)
    if (next.has(mod)) next.delete(mod)
    else next.add(mod)
    setFilter({ ...filter, modules: next })
  }

  const handleApply = () => {
    setFilter({ ...filter, searchQuery: search })
    applyFilters()
  }

  const handleReset = () => {
    setSearch('')
    resetFilters()
  }

  return (
    <div className="absolute top-4 right-4 z-20 w-72 rounded-lg border border-celestial-border bg-celestial-surface/95 backdrop-blur-sm shadow-2xl">
      <div className="flex items-center justify-between px-4 py-3 border-b border-celestial-border">
        <div className="flex items-center gap-2 text-celestial-text">
          <Filter size={16} />
          <span className="font-medium text-sm">过滤器</span>
        </div>
        <button onClick={onClose} className="text-celestial-textDim hover:text-celestial-text transition-colors">
          <X size={16} />
        </button>
      </div>

      <div className="p-4 space-y-4 max-h-[calc(100vh-12rem)] overflow-y-auto">
        {/* Search */}
        <div>
          <label className="text-xs text-celestial-textDim mb-1 block">搜索节点</label>
          <div className="relative">
            <Search size={14} className="absolute left-2 top-1/2 -translate-y-1/2 text-celestial-textDim" />
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="输入节点名称或ID..."
              className="w-full pl-7 pr-2 py-1.5 text-xs bg-celestial-bg border border-celestial-border rounded text-celestial-text placeholder-celestial-textDim focus:outline-none focus:border-celestial-primary"
              onKeyDown={e => e.key === 'Enter' && handleApply()}
            />
          </div>
        </div>

        {/* Severity */}
        <div>
          <label className="text-xs text-celestial-textDim mb-2 block">严重级别</label>
          <div className="space-y-1">
            {(['critical', 'high', 'medium', 'low', 'info'] as const).map(sev => (
              <label key={sev} className="flex items-center gap-2 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={filter.severities.has(sev)}
                  onChange={() => toggleSeverity(sev)}
                  className="sr-only"
                />
                <span className={`w-3 h-3 rounded-full transition-all ${filter.severities.has(sev) ? 'ring-2 ring-offset-1 ring-offset-celestial-surface' : 'opacity-40'}`}
                  style={{ backgroundColor: SEVERITY_COLORS[sev], ringColor: SEVERITY_COLORS[sev] }}
                />
                <span className="text-xs text-celestial-text group-hover:text-celestial-accent transition-colors">
                  {SEVERITY_LABELS[sev]} ({sev})
                </span>
              </label>
            ))}
          </div>
        </div>

        {/* Node Types */}
        <div>
          <label className="text-xs text-celestial-textDim mb-2 block">节点类型</label>
          <div className="space-y-1">
            {Object.entries(NODE_TYPE_LABELS).map(([type, label]) => (
              <label key={type} className="flex items-center gap-2 cursor-pointer group">
                <input
                  type="checkbox"
                  checked={filter.nodeTypes.has(type)}
                  onChange={() => toggleNodeType(type)}
                  className="sr-only"
                />
                <span className={`w-3 h-3 rounded-sm border transition-all ${filter.nodeTypes.has(type) ? 'bg-celestial-primary border-celestial-primary' : 'border-celestial-border'}`} />
                <span className="text-xs text-celestial-text group-hover:text-celestial-accent transition-colors">
                  {label}
                </span>
              </label>
            ))}
          </div>
        </div>

        {/* Modules */}
        {availableModules.length > 0 && (
          <div>
            <label className="text-xs text-celestial-textDim mb-2 block">模块</label>
            <div className="space-y-1 max-h-24 overflow-y-auto">
              {availableModules.map(mod => (
                <label key={mod} className="flex items-center gap-2 cursor-pointer group">
                  <input
                    type="checkbox"
                    checked={filter.modules.size === 0 || filter.modules.has(mod)}
                    onChange={() => toggleModule(mod)}
                    className="sr-only"
                  />
                  <span className={`w-3 h-3 rounded-sm border transition-all ${filter.modules.has(mod) ? 'bg-celestial-accent border-celestial-accent' : 'border-celestial-border'}`} />
                  <span className="text-xs text-celestial-text truncate group-hover:text-celestial-accent transition-colors">
                    {mod}
                  </span>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Buttons */}
        <div className="flex gap-2 pt-2 border-t border-celestial-border">
          <button
            onClick={handleApply}
            className="flex-1 py-1.5 px-3 text-xs font-medium bg-celestial-primary/80 hover:bg-celestial-primary text-white rounded transition-colors"
          >
            应用过滤
          </button>
          <button
            onClick={handleReset}
            className="flex items-center justify-center gap-1 py-1.5 px-3 text-xs font-medium border border-celestial-border text-celestial-textDim hover:text-celestial-text hover:border-celestial-textDim rounded transition-colors"
          >
            <RotateCcw size={12} />
            重置
          </button>
        </div>
      </div>
    </div>
  )
}
