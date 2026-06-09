import { useState, useCallback, useEffect, useMemo, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { Filter, ZoomIn, ZoomOut, Maximize2, Info, AlertTriangle, Shield, ShieldCheck, ShieldAlert, ShieldX } from 'lucide-react'
import { getStarMap } from '../services/api'
import type { StarMapNode, StarMapEdge } from '../types'
import StarMapCanvas from '../components/star-map/StarMapCanvas'
import FilterPanel from '../components/star-map/FilterPanel'
import { SEVERITY_COLORS, SEVERITY_LABELS } from '../components/star-map/types'

export default function StarMapView() {
  const navigate = useNavigate()
  const [nodes, setNodes] = useState<StarMapNode[]>([])
  const [edges, setEdges] = useState<StarMapEdge[]>([])
  const [loading, setLoading] = useState(true)
  const [apiError, setApiError] = useState<string | null>(null)
  const [showFilter, setShowFilter] = useState(false)
  const [canvasSize, setCanvasSize] = useState({ width: 0, height: 0 })
  const containerRef = useRef<HTMLDivElement>(null)

  // Measure container size
  useEffect(() => {
    const measure = () => {
      if (containerRef.current) {
        const rect = containerRef.current.getBoundingClientRect()
        setCanvasSize({ width: rect.width, height: rect.height })
      }
    }
    measure()
    window.addEventListener('resize', measure)
    return () => window.removeEventListener('resize', measure)
  }, [])

  useEffect(() => {
    getStarMap().then(res => {
      setNodes(res.data.nodes)
      setEdges(res.data.edges)
      setApiError(null)
    }).catch(() => {
      setNodes([])
      setEdges([])
      setApiError('暂无星图数据，请先导入项目并运行扫描')
    }).finally(() => setLoading(false))
  }, [])

  const handleNodeSelect = useCallback((node: StarMapNode) => {
    if (node.type === 'file' || node.type === 'module') {
      navigate(`/ide/${node.id}`)
    }
  }, [navigate])

  const stats = useMemo(() => {
    const bySeverity: Record<string, number> = {}
    nodes.forEach(n => {
      const sev = n.severity || 'info'
      bySeverity[sev] = (bySeverity[sev] || 0) + 1
    })
    return bySeverity
  }, [nodes])

  const availableModules = useMemo(() => {
    const mods = new Set<string>()
    nodes.forEach(n => {
      const mod = (n.label || '').split('/')[0] || 'root'
      mods.add(mod)
    })
    return Array.from(mods)
  }, [nodes])

  return (
    <div className="h-full flex flex-col" ref={containerRef}>
      <div className="mb-3 flex items-center justify-between shrink-0">
        <h1 className="text-lg font-bold text-celestial-text flex items-center gap-2">
          <span className="text-celestial-accent">✦</span>
          Celestial Orrery — 资产星图
        </h1>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-4 text-xs">
            <span className="text-celestial-textDim">总资产: <span className="text-celestial-text font-semibold">{nodes.length}</span></span>
            <span className="text-celestial-textDim">关联: <span className="text-celestial-text font-semibold">{edges.length}</span></span>
            {stats.critical && (
              <span className="flex items-center gap-1 text-red-400"><ShieldX size={12} /> {stats.critical}</span>
            )}
            {stats.high && (
              <span className="flex items-center gap-1 text-red-400/80"><ShieldAlert size={12} /> {stats.high}</span>
            )}
            {stats.medium && (
              <span className="flex items-center gap-1 text-orange-400"><AlertTriangle size={12} /> {stats.medium}</span>
            )}
            {stats.low && (
              <span className="flex items-center gap-1 text-blue-400"><ShieldCheck size={12} /> {stats.low}</span>
            )}
            {stats.info && (
              <span className="flex items-center gap-1 text-green-400/70"><Shield size={12} /> {stats.info}</span>
            )}
          </div>

          <div className="hidden md:flex gap-3">
            {Object.entries(SEVERITY_LABELS).map(([sev, label]) => (
              <span key={sev} className="flex items-center gap-1 text-xs text-celestial-textDim">
                <span className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
                {label}
              </span>
            ))}
          </div>

          <button
            onClick={() => setShowFilter(!showFilter)}
            className={`p-1.5 rounded border transition-colors ${showFilter ? 'border-celestial-accent text-celestial-accent' : 'border-celestial-border text-celestial-textDim hover:text-celestial-text'}`}
            title="过滤器"
          >
            <Filter size={16} />
          </button>
        </div>
      </div>

      <div className="flex-1 rounded-lg border border-celestial-border bg-celestial-bg relative overflow-hidden">
        {loading || canvasSize.width === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-celestial-textDim">
            <div className="text-center">
              <div className="animate-pulse text-2xl mb-2">✦</div>
              <p className="text-sm">星图正在生成中...</p>
            </div>
          </div>
        ) : nodes.length === 0 ? (
          <div className="absolute inset-0 flex items-center justify-center text-celestial-textDim">
            <div className="text-center">
              <ShieldX size={48} className="mx-auto mb-3 text-celestial-textDim/30" />
              <p className="text-lg mb-1">暂无星图数据</p>
              <p className="text-sm">{apiError || '请先导入项目并运行扫描以生成星图'}</p>
            </div>
          </div>
        ) : (
          <StarMapCanvas
            nodes={nodes}
            edges={edges}
            width={canvasSize.width}
            height={canvasSize.height}
            onNodeSelect={handleNodeSelect}
          />
        )}

        {!loading && (
          <div className="absolute bottom-4 left-4 z-10 flex gap-1">
            <button className="p-1.5 rounded bg-celestial-surface/80 border border-celestial-border text-celestial-textDim hover:text-celestial-text transition-colors" title="放大">
              <ZoomIn size={16} />
            </button>
            <button className="p-1.5 rounded bg-celestial-surface/80 border border-celestial-border text-celestial-textDim hover:text-celestial-text transition-colors" title="缩小">
              <ZoomOut size={16} />
            </button>
            <button className="p-1.5 rounded bg-celestial-surface/80 border border-celestial-border text-celestial-textDim hover:text-celestial-text transition-colors" title="重置视图">
              <Maximize2 size={16} />
            </button>
          </div>
        )}

        {!loading && (
          <div className="absolute bottom-4 right-4 z-10 flex items-center gap-1 text-xs text-celestial-textDim/60">
            <Info size={12} />
            <span>滚轮缩放 · 拖拽平移 · 点击选择</span>
          </div>
        )}

        {showFilter && (
          <FilterPanel
            filter={{
              severities: new Set(['critical', 'high', 'medium', 'low', 'info']),
              nodeTypes: new Set(['file', 'function', 'vulnerability', 'module']),
              modules: new Set(),
              searchQuery: '',
            }}
            setFilter={() => {}}
            applyFilters={() => {}}
            resetFilters={() => {}}
            onClose={() => setShowFilter(false)}
            availableModules={availableModules}
          />
        )}
      </div>
    </div>
  )
}
