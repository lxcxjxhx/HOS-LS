import { useRef, useEffect } from 'react'
import type { StarMapNode, StarMapEdge } from '../../types'
import { useStarMapEngine } from './useStarMapEngine'

interface StarMapCanvasProps {
  nodes: StarMapNode[]
  edges: StarMapEdge[]
  width: number
  height: number
  onNodeSelect?: (node: StarMapNode) => void
}

export default function StarMapCanvas({ nodes, edges, width, height, onNodeSelect }: StarMapCanvasProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const engine = useStarMapEngine({ width, height, nodes, edges })

  useEffect(() => {
    const canvas = canvasRef.current
    if (!canvas) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    let animId: number
    const { nodes: pNodes, edges: pEdges, clusters, zoom, hoveredNode, selectedNode } = engine

    const draw = () => {
      ctx.save()
      ctx.clearRect(0, 0, width, height)

      // Background
      ctx.fillStyle = '#0D0D1A'
      ctx.fillRect(0, 0, width, height)

      // Background stars
      drawBackgroundStars(ctx, width, height)

      ctx.translate(zoom.offsetX, zoom.offsetY)
      ctx.scale(zoom.scale, zoom.scale)

      // Clusters
      clusters.forEach(cluster => {
        if (!cluster.visible) return
        const gradient = ctx.createRadialGradient(cluster.centerX, cluster.centerY, 0, cluster.centerX, cluster.centerY, cluster.radius)
        gradient.addColorStop(0, cluster.color)
        gradient.addColorStop(1, 'transparent')
        ctx.fillStyle = gradient
        ctx.beginPath()
        ctx.arc(cluster.centerX, cluster.centerY, cluster.radius, 0, Math.PI * 2)
        ctx.fill()

        // Cluster label
        ctx.fillStyle = 'rgba(153,153,170,0.6)'
        ctx.font = '10px monospace'
        ctx.textAlign = 'center'
        ctx.fillText(cluster.label, cluster.centerX, cluster.centerY - cluster.radius - 8)
      })

      // Edges
      pEdges.forEach(edge => {
        if (!edge.visible) return
        ctx.strokeStyle = 'rgba(153,153,170,0.2)'
        ctx.lineWidth = 1
        ctx.beginPath()
        ctx.moveTo(edge.sourceNode.x, edge.sourceNode.y)
        ctx.lineTo(edge.targetNode.x, edge.targetNode.y)
        ctx.stroke()
      })

      // Nodes
      const time = Date.now() / 1000
      pNodes.forEach(node => {
        if (!node.visible) return
        drawNode(ctx, node, time, hoveredNode?.id === node.id, selectedNode?.id === node.id)
      })

      ctx.restore()
      animId = requestAnimationFrame(draw)
    }

    animId = requestAnimationFrame(draw)
    return () => cancelAnimationFrame(animId)
  }, [engine, width, height])

  return (
    <canvas
      ref={canvasRef}
      width={width}
      height={height}
      className="absolute inset-0 cursor-grab active:cursor-grabbing"
      style={{ touchAction: 'none' }}
      onWheel={engine.handleWheel}
      onMouseDown={engine.handleMouseDown}
      onMouseMove={engine.handleMouseMove}
      onMouseUp={engine.handleMouseUp}
      onMouseLeave={engine.handleMouseLeave}
      onClick={(e) => {
        engine.handleClick(e)
        if (engine.selectedNode && onNodeSelect) {
          onNodeSelect(engine.selectedNode)
        }
      }}
    />
  )
}

// Background star field
const bgStars = Array.from({ length: 200 }, () => ({
  x: Math.random(),
  y: Math.random(),
  r: Math.random() * 1 + 0.3,
  a: Math.random() * 0.5 + 0.1,
}))

function drawBackgroundStars(ctx: CanvasRenderingContext2D, width: number, height: number) {
  bgStars.forEach(star => {
    ctx.fillStyle = `rgba(255,255,255,${star.a})`
    ctx.beginPath()
    ctx.arc(star.x * width, star.y * height, star.r, 0, Math.PI * 2)
    ctx.fill()
  })
}

function drawNode(
  ctx: CanvasRenderingContext2D,
  node: any,
  time: number,
  isHovered: boolean,
  isSelected: boolean
) {
  const { x, y, radius, color, label, severity, isBlackHole } = node
  const pulseFactor = severity === 'critical' ? 1 + Math.sin(time * 4) * 0.15 : 1
  const r = radius * pulseFactor * (isHovered ? 1.3 : 1)

  // Black hole effect
  if (isBlackHole) {
    // Glow aura
    const glow = ctx.createRadialGradient(x, y, r, x, y, r * 3)
    glow.addColorStop(0, 'rgba(255,34,34,0.3)')
    glow.addColorStop(0.5, 'rgba(255,34,34,0.1)')
    glow.addColorStop(1, 'transparent')
    ctx.fillStyle = glow
    ctx.beginPath()
    ctx.arc(x, y, r * 3, 0, Math.PI * 2)
    ctx.fill()

    // Rotating ring
    ctx.save()
    ctx.translate(x, y)
    ctx.rotate(time * 0.5)
    ctx.strokeStyle = 'rgba(255,68,68,0.5)'
    ctx.lineWidth = 1.5
    ctx.beginPath()
    ctx.ellipse(0, 0, r * 1.8, r * 0.6, 0, 0, Math.PI * 2)
    ctx.stroke()
    ctx.restore()
  }

  // Selection ring
  if (isSelected) {
    ctx.strokeStyle = '#FFFFFF'
    ctx.lineWidth = 2
    ctx.beginPath()
    ctx.arc(x, y, r + 4, 0, Math.PI * 2)
    ctx.stroke()
  }

  // Node body
  const gradient = ctx.createRadialGradient(x - r * 0.3, y - r * 0.3, 0, x, y, r)
  gradient.addColorStop(0, 'rgba(255,255,255,0.8)')
  gradient.addColorStop(0.3, color)
  gradient.addColorStop(1, color + '88')
  ctx.fillStyle = gradient
  ctx.beginPath()
  ctx.arc(x, y, r, 0, Math.PI * 2)
  ctx.fill()

  // Hover glow
  if (isHovered) {
    ctx.shadowColor = color
    ctx.shadowBlur = 15
    ctx.beginPath()
    ctx.arc(x, y, r, 0, Math.PI * 2)
    ctx.fill()
    ctx.shadowBlur = 0
  }

  // Label
  ctx.fillStyle = isHovered ? '#FFFFFF' : '#9999AA'
  ctx.font = isHovered ? '11px monospace' : '10px monospace'
  ctx.textAlign = 'center'
  ctx.fillText(label, x, y + r + 14)
}
