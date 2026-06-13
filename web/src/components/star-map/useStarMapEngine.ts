import { useState, useCallback, useRef, useEffect } from 'react'
import type { StarMapNode, StarMapEdge } from '../../types'
import type {
  PositionedNode,
  PositionedEdge,
  NebulaCluster,
  SupernovaEvent,
  ZoomState,
  FilterState,
  TooltipState,
} from './types'
import { SEVERITY_COLORS } from './types'

interface UseStarMapEngineReturn {
  nodes: PositionedNode[]
  edges: PositionedEdge[]
  clusters: NebulaCluster[]
  supernovas: SupernovaEvent[]
  zoom: ZoomState
  tooltip: TooltipState
  filter: FilterState
  selectedNode: PositionedNode | null
  hoveredNode: PositionedNode | null
  setSelectedNode: (node: PositionedNode | null) => void
  setZoom: (zoom: ZoomState) => void
  setTooltip: (tooltip: TooltipState) => void
  setFilter: (filter: FilterState) => void
  handleWheel: (e: React.WheelEvent) => void
  handleMouseDown: (e: React.MouseEvent) => void
  handleMouseMove: (e: React.MouseEvent) => void
  handleMouseUp: () => void
  handleClick: (e: React.MouseEvent) => void
  handleMouseLeave: () => void
  resetView: () => void
  applyFilters: () => void
  resetFilters: () => void
}

interface EngineConfig {
  width: number
  height: number
  nodes: StarMapNode[]
  edges: StarMapEdge[]
  iterationsPerFrame?: number
  alpha?: number
  alphaDecay?: number
  alphaMin?: number
}

const REPULSION_STRENGTH = -200
const ATTRACTION_STRENGTH = 0.005
const CENTER_STRENGTH = 0.01
const COLLISION_PADDING = 8
const MIN_RADIUS = 4
const MAX_RADIUS = 20

function getSeverityRadius(severity?: string): number {
  switch (severity) {
    case 'critical': return MAX_RADIUS
    case 'high': return MAX_RADIUS - 4
    case 'medium': return MAX_RADIUS - 8
    case 'low': return MAX_RADIUS - 12
    default: return MIN_RADIUS + 2
  }
}

function getSeverityColor(severity?: string): string {
  return SEVERITY_COLORS[severity || 'info'] || SEVERITY_COLORS.info
}

function computeClusters(nodes: PositionedNode[], edges: PositionedEdge[]): NebulaCluster[] {
  const moduleMap = new Map<string, PositionedNode[]>()
  nodes.forEach(node => {
    const module = (node.label || '').split('/')[0] || 'root'
    if (!moduleMap.has(module)) moduleMap.set(module, [])
    moduleMap.get(module)!.push(node)
  })

  const clusters: NebulaCluster[] = []
  let id = 0
  moduleMap.forEach((nodes, label) => {
    if (nodes.length < 2) return
    const centerX = nodes.reduce((sum, n) => sum + n.x, 0) / nodes.length
    const centerY = nodes.reduce((sum, n) => sum + n.y, 0) / nodes.length
    const maxDist = Math.max(...nodes.map(n => Math.hypot(n.x - centerX, n.y - centerY)), 50)
    const color = nodes.some(n => n.severity === 'critical') ? 'rgba(255,34,34,0.08)'
      : nodes.some(n => n.severity === 'high') ? 'rgba(255,68,68,0.06)'
      : 'rgba(106,13,173,0.06)'
    clusters.push({
      id: `cluster-${id++}`,
      label,
      nodes,
      centerX,
      centerY,
      radius: maxDist,
      color,
      visible: true,
    })
  })
  return clusters
}

function isNodeVisible(node: StarMapNode, filter: FilterState): boolean {
  const sev = (node.severity || 'info') as string
  if (!filter.severities.has(sev as any)) return false
  if (!filter.nodeTypes.has(node.type)) return false
  if (filter.modules.size > 0) {
    const module = (node.label || '').split('/')[0] || 'root'
    if (!filter.modules.has(module)) return false
  }
  if (filter.searchQuery) {
    const q = filter.searchQuery.toLowerCase()
    if (!node.label.toLowerCase().includes(q) && !node.id.toLowerCase().includes(q)) return false
  }
  return true
}

export function useStarMapEngine(config: EngineConfig): UseStarMapEngineReturn {
  const { width, height, nodes: rawNodes, edges: rawEdges, iterationsPerFrame = 1, alpha: initAlpha = 1, alphaDecay = 0.022, alphaMin = 0.001 } = config

  const [nodes, setNodes] = useState<PositionedNode[]>([])
  const [edges, setEdges] = useState<PositionedEdge[]>([])
  const [clusters, setClusters] = useState<NebulaCluster[]>([])
  const [supernovas, setSupernovas] = useState<SupernovaEvent[]>([])
  const [zoom, setZoom] = useState<ZoomState>({ scale: 1, offsetX: width / 2, offsetY: height / 2 })
  const [tooltip, setTooltip] = useState<TooltipState>({ visible: false, x: 0, y: 0, node: null })
  const [selectedNode, setSelectedNode] = useState<PositionedNode | null>(null)
  const [hoveredNode, setHoveredNode] = useState<PositionedNode | null>(null)

  const [filter, setFilter] = useState<FilterState>({
    severities: new Set(['critical', 'high', 'medium', 'low', 'info']),
    nodeTypes: new Set(['file', 'function', 'vulnerability', 'module']),
    modules: new Set(),
    searchQuery: '',
  })

  const alphaRef = useRef(initAlpha)
  const isDragging = useRef(false)
  const dragStart = useRef({ x: 0, y: 0 })
  const nodesRef = useRef<PositionedNode[]>([])
  const canvasSizeRef = useRef({ width, height })
  const timeRef = useRef(0)

  // Initialize positions
  useEffect(() => {
    const nodeMap = new Map<string, StarMapNode>()
    rawNodes.forEach(n => nodeMap.set(n.id, n))

    const positioned: PositionedNode[] = rawNodes.map((n, i) => {
      const angle = (i / rawNodes.length) * Math.PI * 2
      const radius = 150 + Math.random() * 100
      return {
        ...n,
        x: n.x ?? Math.cos(angle) * radius,
        y: n.y ?? Math.sin(angle) * radius,
        vx: 0,
        vy: 0,
        radius: getSeverityRadius(n.severity),
        color: getSeverityColor(n.severity),
        visible: true,
        isBlackHole: n.severity === 'critical',
      }
    })

    nodesRef.current = positioned
    setNodes(positioned)

    const positionedEdges: PositionedEdge[] = rawEdges.map(e => ({
      ...e,
      sourceNode: positioned.find(n => n.id === e.source)!,
      targetNode: positioned.find(n => n.id === e.target)!,
      visible: true,
    })).filter(e => e.sourceNode && e.targetNode)
    setEdges(positionedEdges)

    alphaRef.current = 1
  }, [rawNodes, rawEdges])

  // Apply filters
  const applyFilters = useCallback(() => {
    setNodes(prev => prev.map(n => ({
      ...n,
      visible: isNodeVisible(n, filter),
    })))
    setEdges(prev => prev.map(e => ({
      ...e,
      visible: e.sourceNode.visible && e.targetNode.visible,
    })))
  }, [filter])

  const resetFilters = useCallback(() => {
    setFilter({
      severities: new Set(['critical', 'high', 'medium', 'low', 'info']),
      nodeTypes: new Set(['file', 'function', 'vulnerability', 'module']),
      modules: new Set(),
      searchQuery: '',
    })
    setNodes(prev => prev.map(n => ({ ...n, visible: true })))
    setEdges(prev => prev.map(e => ({ ...e, visible: true })))
  }, [])

  // Force-directed layout
  useEffect(() => {
    let rafId: number

    const tick = () => {
      const nodes = nodesRef.current
      if (nodes.length === 0) {
        rafId = requestAnimationFrame(tick)
        return
      }

      const alpha = alphaRef.current
      if (alpha < alphaMin) {
        rafId = requestAnimationFrame(tick)
        return
      }

      for (let iter = 0; iter < iterationsPerFrame; iter++) {
        const visibleNodes = nodes.filter(n => n.visible)
        const len = visibleNodes.length

        // Repulsion
        for (let i = 0; i < len; i++) {
          const a = visibleNodes[i]
          for (let j = i + 1; j < len; j++) {
            const b = visibleNodes[j]
            let dx = a.x - b.x
            let dy = a.y - b.y
            let dist = Math.sqrt(dx * dx + dy * dy) || 1
            let force = REPULSION_STRENGTH * alpha / dist
            a.vx! += dx * force
            a.vy! += dy * force
            b.vx! -= dx * force
            b.vy! -= dy * force
          }
        }

        // Attraction (edges)
        edges.forEach(e => {
          if (!e.visible) return
          const a = e.sourceNode
          const b = e.targetNode
          if (!a.visible || !b.visible) return
          const dx = b.x - a.x
          const dy = b.y - a.y
          const dist = Math.sqrt(dx * dx + dy * dy) || 1
          const force = ATTRACTION_STRENGTH * dist * alpha
          a.vx! += dx * force
          a.vy! += dy * force
          b.vx! -= dx * force
          b.vy! -= dy * force
        })

        // Center gravity
        visibleNodes.forEach(n => {
          n.vx! += -n.x * CENTER_STRENGTH * alpha
          n.vy! += -n.y * CENTER_STRENGTH * alpha
        })

        // Collision
        for (let i = 0; i < len; i++) {
          const a = visibleNodes[i]
          for (let j = i + 1; j < len; j++) {
            const b = visibleNodes[j]
            const dx = b.x - a.x
            const dy = b.y - a.y
            const dist = Math.sqrt(dx * dx + dy * dy) || 0.01
            const minDist = a.radius + b.radius + COLLISION_PADDING
            if (dist < minDist) {
              const overlap = (minDist - dist) / dist * 0.5
              a.vx! -= dx * overlap
              a.vy! -= dy * overlap
              b.vx! += dx * overlap
              b.vy! += dy * overlap
            }
          }
        }

        // Apply velocity
        const damping = 0.6
        visibleNodes.forEach(n => {
          n.x += n.vx! * 0.5
          n.y += n.vy! * 0.5
          n.vx! *= damping
          n.vy! *= damping
          // Boundary
          const hw = canvasSizeRef.current.width * 0.45
          const hh = canvasSizeRef.current.height * 0.45
          n.x = Math.max(-hw, Math.min(hw, n.x))
          n.y = Math.max(-hh, Math.min(hh, n.y))
        })
      }

      alphaRef.current *= (1 - alphaDecay)
      nodesRef.current = [...nodes]
      setNodes([...nodes])
      timeRef.current += 1

      rafId = requestAnimationFrame(tick)
    }

    rafId = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(rafId)
  }, [iterationsPerFrame, alphaDecay, alphaMin, edges])

  // Recompute clusters when nodes change
  useEffect(() => {
    setClusters(computeClusters(nodes.filter(n => n.visible), edges.filter(e => e.visible)))
  }, [nodes, edges])

  // Hover detection
  const findNodeAt = useCallback((mx: number, my: number): PositionedNode | null => {
    const cx = (mx - zoom.offsetX) / zoom.scale
    const cy = (my - zoom.offsetY) / zoom.scale
    for (let i = nodes.length - 1; i >= 0; i--) {
      const n = nodes[i]
      if (!n.visible) continue
      const dist = Math.hypot(cx - n.x, cy - n.y)
      if (dist <= n.radius + 4) return n
    }
    return null
  }, [nodes, zoom])

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    const delta = e.deltaY > 0 ? 0.9 : 1.1
    const newScale = Math.max(0.1, Math.min(5, zoom.scale * delta))
    const ratio = newScale / zoom.scale
    setZoom({
      scale: newScale,
      offsetX: e.clientX - (e.clientX - zoom.offsetX) * ratio,
      offsetY: e.clientY - (e.clientY - zoom.offsetY) * ratio,
    })
  }, [zoom])

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button === 0) {
      isDragging.current = true
      dragStart.current = { x: e.clientX - zoom.offsetX, y: e.clientY - zoom.offsetY }
    }
  }, [zoom])

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (isDragging.current) {
      setZoom(prev => ({
        ...prev,
        offsetX: e.clientX - dragStart.current.x,
        offsetY: e.clientY - dragStart.current.y,
      }))
    }
    const node = findNodeAt(e.clientX, e.clientY)
    setHoveredNode(node)
    if (node) {
      setTooltip({ visible: true, x: e.clientX + 12, y: e.clientY + 12, node })
    } else {
      setTooltip(prev => ({ ...prev, visible: false, node: null }))
    }
  }, [findNodeAt])

  const handleMouseUp = useCallback(() => {
    isDragging.current = false
  }, [])

  const handleClick = useCallback((e: React.MouseEvent) => {
    const node = findNodeAt(e.clientX, e.clientY)
    setSelectedNode(node)
  }, [findNodeAt])

  const handleMouseLeave = useCallback(() => {
    setTooltip(prev => ({ ...prev, visible: false, node: null }))
    setHoveredNode(null)
  }, [])

  const resetView = useCallback(() => {
    setZoom({ scale: 1, offsetX: canvasSizeRef.current.width / 2, offsetY: canvasSizeRef.current.height / 2 })
    alphaRef.current = 1
  }, [])

  return {
    nodes, edges, clusters, supernovas, zoom, tooltip, filter, selectedNode, hoveredNode,
    setSelectedNode, setZoom, setTooltip, setFilter,
    handleWheel, handleMouseDown, handleMouseMove, handleMouseUp, handleClick, handleMouseLeave,
    resetView, applyFilters, resetFilters,
  }
}

export default useStarMapEngine
