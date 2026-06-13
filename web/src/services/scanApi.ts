import axios from 'axios'
import type { Severity } from '../types'

const API_BASE = import.meta.env.VITE_API_BASE || '/api'

const api = axios.create({
  baseURL: API_BASE,
  timeout: 30000,
  headers: { 'Content-Type': 'application/json' },
})

export interface ScanRequest {
  target_path?: string
  scan_type?: string  // 'full' | 'quick' | 'custom'
  rules?: string[]
}

export interface ScanTask {
  task_id: string
  status: string
  progress: number
  message: string
  files_scanned?: number
  total_files?: number
  current_file?: string
}

export interface ScanSummary {
  task_id: string
  total_findings: number
  severity_counts: Record<Severity, number>
  files_scanned: number
  scan_duration?: number
}

export interface Finding {
  id: string
  rule_id: string
  severity: Severity
  category: string
  file: string
  line: number
  message: string
  confidence: number
  details?: string
}

export const scanApi = {
  startScan: (req: ScanRequest) => api.post<ScanTask>('/scan', req),
  getScanStatus: (taskId: string) => api.get<ScanTask>(`/scan/${taskId}`),
  getFindings: (taskId: string) => api.get<{ findings: Finding[] }>(`/scan/${taskId}/findings`),
  getSummary: (taskId: string) => api.get<ScanSummary>(`/scan/${taskId}/summary`),
  cancelScan: (taskId: string) => api.post(`/scan/${taskId}/cancel`),
  listTasks: () => api.get<{ tasks: ScanTask[] }>('/tasks'),
}

export default api
