export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type TaskStatus = 'pending' | 'running' | 'completed' | 'failed' | 'cancelled'
export type MessageType = 'user' | 'assistant' | 'system'

export interface HealthResponse {
  status: 'healthy' | 'degraded' | 'unhealthy'
  version: string
  build_time?: string
  components: Record<string, string>
}

export interface TaskInfo {
  task_id: string
  type: string
  status: TaskStatus
  progress: number
  message?: string
  created_at: string
  updated_at: string
  result?: Record<string, unknown>
  error?: string
}

export interface Finding {
  id: string
  rule_id: string
  severity: Severity
  confidence: number
  title: string
  description: string
  file_path: string
  line_number?: number
  code_snippet?: string
  cwe_id?: string
  cve_ids: string[]
  fix_suggestion?: string
  attack_chain?: string[]
  created_at?: string
}

export interface Session {
  session_id: string
  name: string
  type: string
  status: TaskStatus
  created_at: string
  updated_at: string
  metadata: Record<string, unknown>
}

export interface StarMapNode {
  id: string
  label: string
  type: string
  severity?: Severity
  metadata: Record<string, unknown>
  x?: number
  y?: number
}

export interface StarMapEdge {
  id: string
  source: string
  target: string
  relation: string
  metadata: Record<string, unknown>
}

export interface StarMapData {
  nodes: StarMapNode[]
  edges: StarMapEdge[]
  total_nodes: number
  total_edges: number
}

export interface ChatMessage {
  role: MessageType
  content: string
  timestamp: string
  metadata?: Record<string, unknown>
}

export interface ChatRequest {
  message: string
  session_id?: string
  context?: Record<string, unknown>
}

export interface ScanRequest {
  target: string
  mode?: string
  rules?: string[]
  max_workers?: number
}

export interface PentestRequest {
  target: string
  mode?: 'recon' | 'scan' | 'full' | 'exploit'
  tools?: string[]
  depth?: number
}
