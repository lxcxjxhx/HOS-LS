import { useState, useEffect, useMemo, useCallback } from 'react'
import { Button } from '../components/ui/Button'
import { Card } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Input } from '../components/ui/Input'
import {
  Search, Play, Pause, Square, RotateCcw, Eye,
  ChevronDown, ChevronUp, Clock, CheckCircle, XCircle,
  FileText, MessageSquare, Crosshair,
  Shield, BarChart3, Layers, RefreshCw, AlertTriangle
} from 'lucide-react'
import type { TaskStatus } from '../types'

const API_BASE = import.meta.env.VITE_API_BASE || '/api'

/* ─── types ─── */
interface SessionRecord {
  id: string
  name: string
  type: string
  status: TaskStatus | string
  created_at: string
  updated_at: string
  metadata: Record<string, unknown>
}

interface TaskEntry {
  task_id: string
  type: string
  status: TaskStatus | string
  progress: number
  message: string
  created_at: string
  updated_at: string
  expanded?: boolean
}

const STATUS_CONFIG: Record<string, { label: string; color: string; icon: typeof Clock; badgeType: 'default' | 'status' }> = {
  pending: { label: '等待中', color: 'text-celestial-textDim', icon: Clock, badgeType: 'default' },
  running: { label: '运行中', color: 'text-celestial-accent', icon: Play, badgeType: 'status' },
  completed: { label: '已完成', color: 'text-celestial-star-safe', icon: CheckCircle, badgeType: 'default' },
  failed: { label: '已失败', color: 'text-celestial-alert', icon: XCircle, badgeType: 'default' },
  cancelled: { label: '已取消', color: 'text-celestial-textDim', icon: Square, badgeType: 'default' },
}

const TYPE_CONFIG: Record<string, { label: string; icon: typeof FileText; color: string }> = {
  scan: { label: '扫描', icon: Shield, color: 'text-celestial-primary' },
  pentest: { label: '渗透', icon: Crosshair, color: 'text-celestial-alert' },
  chat: { label: '对话', icon: MessageSquare, color: 'text-celestial-accent' },
}

export default function SessionsView() {
  const [sessions, setSessions] = useState<SessionRecord[]>([])
  const [tasks, setTasks] = useState<TaskEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [apiError, setApiError] = useState<string | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [typeFilter, setTypeFilter] = useState<'all' | string>('all')
  const [statusFilter, setStatusFilter] = useState<'all' | TaskStatus>('all')
  const [sortBy, setSortBy] = useState<'created' | 'name'>('created')
  const [expandedTasks, setExpandedTasks] = useState<Record<string, boolean>>({})
  const [selectedSession, setSelectedSession] = useState<string | null>(null)

  const loadData = useCallback(() => {
    setLoading(true)
    Promise.all([
      fetch(`${API_BASE}/sessions`).then(res => res.ok ? res.json() : Promise.reject('Failed to load sessions')),
      fetch(`${API_BASE}/tasks`).then(res => res.ok ? res.json() : Promise.reject('Failed to load tasks')),
    ])
      .then(([sessionsData, tasksData]) => {
        setSessions(sessionsData || [])
        setTasks(tasksData || [])
        setApiError(null)
      })
      .catch((err) => {
        setApiError(err.message || '无法加载会话和任务数据')
        setSessions([])
        setTasks([])
      })
      .finally(() => setLoading(false))
  }, [])

  useEffect(() => {
    loadData()
  }, [loadData])

  /* filtered sessions */
  const filteredSessions = useMemo(() => {
    return sessions
      .filter(s => typeFilter === 'all' || s.type === typeFilter)
      .filter(s => statusFilter === 'all' || s.status === statusFilter)
      .filter(s => searchQuery === '' || s.name.toLowerCase().includes(searchQuery.toLowerCase()))
      .sort((a, b) => {
        if (sortBy === 'name') return a.name.localeCompare(b.name)
        return (b.created_at || '').localeCompare(a.created_at || '')
      })
  }, [sessions, searchQuery, typeFilter, statusFilter, sortBy])

  /* grouped tasks by session (approximate — tasks are independent) */
  const tasksBySession = useMemo(() => {
    const map: Record<string, TaskEntry[]> = {}
    tasks.forEach(t => {
      // Use task_id as key for individual task display
      if (!map[t.task_id]) map[t.task_id] = []
      map[t.task_id].push(t)
    })
    return map
  }, [tasks])

  const toggleTask = (id: string) => {
    setExpandedTasks(prev => ({ ...prev, [id]: !prev[id] }))
  }

  const statusIcon = (status: string) => {
    const config = STATUS_CONFIG[status]
    if (!config) return <Clock className="h-4 w-4 text-celestial-textDim" />
    const Icon = config.icon
    return <Icon className={`h-4 w-4 ${config.color}`} />
  }

  const handleCancelTask = async (taskId: string) => {
    try {
      await fetch(`${API_BASE}/tasks/cancel`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ task_id: taskId, reason: '用户取消' }),
      })
      loadData()
    } catch { /* ignore */ }
  }

  /* task status counts */
  const statusCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    sessions.forEach(s => {
      const status = s.status as string
      counts[status] = (counts[status] || 0) + 1
    })
    return counts
  }, [sessions])

  if (loading) {
    return (
      <div className="h-full flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold text-celestial-text">会话与任务管理</h1>
        </div>
        <div className="flex-1 flex items-center justify-center text-celestial-textDim">
          加载中...
        </div>
      </div>
    )
  }

  return (
    <div className="h-full flex flex-col gap-4">
      {/* header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-celestial-text">会话与任务管理</h1>
          <Badge variant="status">{sessions.length} 个会话</Badge>
          <Badge variant="status">{tasks.length} 个任务</Badge>
        </div>
        <div className="flex gap-2">
          <Button variant="ghost" size="sm" onClick={loadData}><RefreshCw className="mr-1 h-3 w-3" />刷新</Button>
        </div>
      </div>

      {/* api error */}
      {apiError && (
        <Card className="border-celestial-alert/30 bg-celestial-alert/5">
          <div className="flex items-center gap-2 text-sm">
            <AlertTriangle className="h-4 w-4 text-celestial-alert" />
            <span className="text-celestial-text">{apiError}</span>
          </div>
        </Card>
      )}

      {/* session list */}
      <Card title="会话列表">
        <div className="space-y-3">
          {/* toolbar */}
          <div className="flex gap-2 items-center">
            <div className="flex-1 relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-celestial-textDim" />
              <Input placeholder="搜索会话名称..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="pl-9" />
            </div>
            <select value={typeFilter} onChange={e => setTypeFilter(e.target.value as typeof typeFilter)} className="rounded-md border border-celestial-border bg-celestial-bg px-3 py-2 text-sm text-celestial-text">
              <option value="all">全部类型</option>
              <option value="scan">扫描</option>
              <option value="pentest">渗透</option>
              <option value="chat">对话</option>
            </select>
            <select value={statusFilter} onChange={e => setStatusFilter(e.target.value as typeof statusFilter)} className="rounded-md border border-celestial-border bg-celestial-bg px-3 py-2 text-sm text-celestial-text">
              <option value="all">全部状态</option>
              <option value="pending">等待中</option>
              <option value="running">运行中</option>
              <option value="completed">已完成</option>
              <option value="failed">已失败</option>
              <option value="cancelled">已取消</option>
            </select>
            <select value={sortBy} onChange={e => setSortBy(e.target.value as typeof sortBy)} className="rounded-md border border-celestial-border bg-celestial-bg px-3 py-2 text-sm text-celestial-text">
              <option value="created">按时间排序</option>
              <option value="name">按名称排序</option>
            </select>
          </div>

          {/* table */}
          <div className="overflow-auto rounded-md border border-celestial-border">
            <table className="w-full text-sm">
              <thead className="bg-celestial-surfaceLight text-celestial-textDim">
                <tr>
                  <th className="text-left px-3 py-2 font-medium">名称</th>
                  <th className="text-left px-3 py-2 font-medium">类型</th>
                  <th className="text-left px-3 py-2 font-medium">状态</th>
                  <th className="text-left px-3 py-2 font-medium">创建时间</th>
                  <th className="text-left px-3 py-2 font-medium">更新时间</th>
                  <th className="text-left px-3 py-2 font-medium">操作</th>
                </tr>
              </thead>
              <tbody>
                {filteredSessions.map(s => {
                  const Icon = TYPE_CONFIG[s.type]?.icon || FileText
                  return (
                    <tr key={s.id} className={`border-t border-celestial-border/50 hover:bg-celestial-surfaceLight/50 cursor-pointer transition-colors ${selectedSession === s.id ? 'bg-celestial-primary/5' : ''}`} onClick={() => setSelectedSession(selectedSession === s.id ? null : s.id)}>
                      <td className="px-3 py-2 text-celestial-text font-medium">{s.name}</td>
                      <td className="px-3 py-2"><span className={`flex items-center gap-1 ${TYPE_CONFIG[s.type]?.color || 'text-celestial-textDim'}`}><Icon className="h-3.5 w-3.5" />{TYPE_CONFIG[s.type]?.label || s.type}</span></td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">
                          {statusIcon(s.status)}
                          <span className={STATUS_CONFIG[s.status]?.color || 'text-celestial-textDim'}>{STATUS_CONFIG[s.status]?.label || s.status}</span>
                        </div>
                      </td>
                      <td className="px-3 py-2 text-celestial-textDim text-xs">{s.created_at ? new Date(s.created_at).toLocaleString('zh-CN') : '—'}</td>
                      <td className="px-3 py-2 text-celestial-textDim text-xs">{s.updated_at ? new Date(s.updated_at).toLocaleString('zh-CN') : '—'}</td>
                      <td className="px-3 py-2">
                        <div className="flex gap-1">
                          {s.status === 'running' && <Button variant="ghost" size="sm" title="暂停"><Pause className="h-3 w-3" /></Button>}
                          {(s.status === 'pending' || s.status === 'running') && <Button variant="ghost" size="sm" title="取消"><Square className="h-3 w-3" /></Button>}
                          {s.status === 'failed' && <Button variant="ghost" size="sm" title="重试" onClick={(e) => { e.stopPropagation(); loadData() }}><RotateCcw className="h-3 w-3" /></Button>}
                          <Button variant="ghost" size="sm" title="查看"><Eye className="h-3 w-3" /></Button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
                {filteredSessions.length === 0 && !apiError && (
                  <tr><td colSpan={6} className="text-center py-8 text-celestial-textDim">
                    <Search className="h-8 w-8 mx-auto mb-2 opacity-30" />
                    无匹配的会话
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </Card>

      {/* tasks list */}
      {tasks.length > 0 && (
        <Card title="任务列表">
          <div className="space-y-2">
            {tasks.map(task => {
              const isRunning = task.status === 'running'
              return (
                <div key={task.task_id} className="rounded-lg border border-celestial-border overflow-hidden">
                  <div className="flex items-center gap-3 px-4 py-3 bg-celestial-surface hover:bg-celestial-surfaceLight transition-colors cursor-pointer" onClick={() => toggleTask(task.task_id)}>
                    {statusIcon(task.status)}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-celestial-text font-medium">{task.task_id.slice(0, 12)}...</span>
                        <span className={`text-xs ${isRunning ? 'text-celestial-accent animate-pulse' : 'text-celestial-textDim'}`}>
                          {task.status === 'running' ? '● 运行中' : ''}
                        </span>
                      </div>
                      <div className="text-xs text-celestial-textDim truncate">{task.message}</div>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-celestial-textDim flex-shrink-0">
                      {isRunning && (
                        <span className="text-celestial-accent">{task.progress}%</span>
                      )}
                      <span>{task.created_at ? new Date(task.created_at).toLocaleTimeString('zh-CN') : '—'}</span>
                      {expandedTasks[task.task_id] ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                    </div>
                  </div>
                  {expandedTasks[task.task_id] && (
                    <div className="border-t border-celestial-border bg-celestial-bg px-4 py-3">
                      <div className="grid grid-cols-3 gap-4 mb-3">
                        <div>
                          <div className="text-xs text-celestial-textDim mb-1">任务 ID</div>
                          <div className="text-sm text-celestial-text font-medium font-mono">{task.task_id}</div>
                        </div>
                        <div>
                          <div className="text-xs text-celestial-textDim mb-1">进度</div>
                          <div className="text-sm text-celestial-text font-medium">{task.progress}%</div>
                        </div>
                        <div>
                          <div className="text-xs text-celestial-textDim mb-1">状态</div>
                          <div className="text-sm text-celestial-text font-medium">{STATUS_CONFIG[task.status]?.label || task.status}</div>
                        </div>
                      </div>
                      <div className="text-sm text-celestial-textDim mb-3">{task.message}</div>
                      {task.status === 'running' && (
                        <Button variant="danger" size="sm" onClick={(e) => { e.stopPropagation(); handleCancelTask(task.task_id) }}><Square className="mr-1 h-3 w-3" />取消任务</Button>
                      )}
                      {task.status === 'completed' && (
                        <div className="flex gap-2">
                          <Button variant="secondary" size="sm"><BarChart3 className="mr-1 h-3 w-3" />查看报告</Button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </Card>
      )}

      {!selectedSession && sessions.length === 0 && (
        <Card title="任务概览">
          <div className="grid grid-cols-5 gap-3">
            {(['pending', 'running', 'completed', 'failed', 'cancelled'] as string[]).map(status => {
              const count = statusCounts[status] || 0
              const config = STATUS_CONFIG[status]
              if (!config) return null
              const Icon = config.icon
              return (
                <Card key={status} className="text-center py-3">
                  <Icon className={`h-5 w-5 mx-auto mb-1 ${config.color}`} />
                  <div className="text-xl font-bold text-celestial-text">{count}</div>
                  <Badge variant={config.badgeType as any}>{config.label}</Badge>
                </Card>
              )
            })}
          </div>
          <div className="mt-4 flex items-center gap-2 text-sm text-celestial-textDim">
            <Layers className="h-4 w-4" />
            尚无会话数据，请先运行扫描或渗透测试
          </div>
        </Card>
      )}
    </div>
  )
}
