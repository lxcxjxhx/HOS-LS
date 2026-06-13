import axios from 'axios'
import type {
  HealthResponse,
  Finding,
  Session,
  TaskInfo,
  StarMapData,
  ChatMessage,
  ChatRequest,
  ScanRequest,
  PentestRequest,
} from '../types'

const API_BASE = import.meta.env.VITE_API_BASE || '/api'

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

// Health
export const getHealth = () => api.get<HealthResponse>('/health')

// Scan
export const startScan = (req: ScanRequest) => api.post('/scan', req)

// Findings
export const getFindings = (params?: Record<string, string>) =>
  api.get<Finding[]>('/findings', { params })
export const getFinding = (id: string) => api.get<Finding>(`/findings/${id}`)

// Pentest
export const startPentest = (req: PentestRequest) => api.post('/pentest', req)
export const startRecon = (req: PentestRequest) => api.post('/recon', req)

// Chat (SSE)
export const sendChatMessage = async (
  req: ChatRequest,
  onChunk: (text: string) => void,
) => {
  const response = await fetch(`${API_BASE}/chat`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  })
  
  const reader = response.body?.getReader()
  if (!reader) return
  
  const decoder = new TextDecoder()
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    const text = decoder.decode(value)
    onChunk(text)
  }
}

// Star Map
export const getStarMap = (params?: Record<string, string>) =>
  api.get<StarMapData>('/star-map', { params })

// Sessions
export const getSessions = () => api.get<Session[]>('/sessions')
export const getSession = (id: string) => api.get<Session>(`/sessions/${id}`)

// Tasks
export const getTaskStatus = (id: string) => api.get<TaskInfo>(`/tasks/${id}/status`)
export const cancelTask = (id: string) => api.post(`/tasks/${id}/cancel`)

// WebSocket
export const createWebSocket = (clientId: string) => {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return new WebSocket(`${proto}//${host}/ws/${clientId}`)
}

export default api
