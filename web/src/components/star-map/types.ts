import type { Severity, StarMapNode, StarMapEdge } from '../../types'

export interface PositionedNode extends StarMapNode {
  x: number
  y: number
  vx?: number
  vy?: number
  radius: number
  color: string
  visible: boolean
  isBlackHole?: boolean
}

export interface PositionedEdge extends StarMapEdge {
  sourceNode: PositionedNode
  targetNode: PositionedNode
  visible: boolean
}

export interface NebulaCluster {
  id: string
  label: string
  nodes: PositionedNode[]
  centerX: number
  centerY: number
  radius: number
  color: string
  visible: boolean
}

export interface SupernovaEvent {
  nodeId: string
  x: number
  y: number
  startTime: number
  duration: number
}

export interface ZoomState {
  scale: number
  offsetX: number
  offsetY: number
}

export interface FilterState {
  severities: Set<Severity | 'info'>
  nodeTypes: Set<string>
  modules: Set<string>
  searchQuery: string
}

export interface TooltipState {
  visible: boolean
  x: number
  y: number
  node: PositionedNode | null
}

export type LayoutForce = 'repulsion' | 'attraction' | 'center' | 'collision'

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#FF2222',
  high: '#FF4444',
  medium: '#FF8C00',
  low: '#4488FF',
  info: '#8888AA',
}

export const SEVERITY_LABELS: Record<string, string> = {
  critical: '严重',
  high: '高危',
  medium: '中危',
  low: '低危',
  info: '信息',
}

export const NODE_TYPE_LABELS: Record<string, string> = {
  file: '文件',
  function: '函数',
  vulnerability: '漏洞',
  module: '模块',
}

export const RELATION_LABELS: Record<string, string> = {
  imports: '导入',
  calls: '调用',
  inherits: '继承',
  contains: '包含',
  depends: '依赖',
}
