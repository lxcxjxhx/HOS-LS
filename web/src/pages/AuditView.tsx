import { useState, useEffect, useCallback, useRef } from 'react'
import { Button } from '../components/ui/Button'
import { Card } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import { Input } from '../components/ui/Input'
import {
  FolderOpen, Play, Upload, X, GitBranch, FileText,
  ChevronDown, ChevronUp, Pause, Square, Search,
  Download, FileCode, Clock, AlertTriangle, AlertCircle,
  Info, CheckCircle, Settings, Eye
} from 'lucide-react'
import type { Severity } from '../types'
import { useAppStore } from '../stores/appStore'
import { scanApi, type ScanTask, type Finding as ApiFinding } from '../services/scanApi'

/* ─── default rule categories (sent to backend, backend decides which to apply) ─── */
const DEFAULT_RULE_CATEGORIES = [
  { id: 'injection', label: '注入漏洞 (Injection)' },
  { id: 'auth', label: '认证与授权 (Auth)' },
  { id: 'crypto', label: '加密弱点 (Crypto)' },
  { id: 'config', label: '配置错误 (Config)' },
  { id: 'xss', label: '跨站脚本 (XSS)' },
  { id: 'ssrf', label: '服务端请求伪造 (SSRF)' },
  { id: 'rce', label: '远程代码执行 (RCE)' },
  { id: 'deserialization', label: '反序列化 (Deserialization)' },
]

type ImportTab = 'git' | 'local' | 'upload'
type ScanStatus = 'idle' | 'configuring' | 'scanning' | 'paused' | 'completed' | 'cancelled' | 'error'

export default function AuditView() {
  const setCurrentProject = useAppStore(s => s.setCurrentProject)

  /* ── import modal ── */
  const [importOpen, setImportOpen] = useState(false)
  const [importTab, setImportTab] = useState<ImportTab>('git')
  const [gitUrl, setGitUrl] = useState('')
  const [localPath, setLocalPath] = useState('')
  const [dragOver, setDragOver] = useState(false)
  const [projectName, setProjectName] = useState<string | null>(null)

  /* ── scan config ── */
  const [configOpen, setConfigOpen] = useState(false)
  const [scanMode, setScanMode] = useState('auto')
  const [selectedRules, setSelectedRules] = useState<string[]>(DEFAULT_RULE_CATEGORIES.map(r => r.id))
  const [aiModel, setAiModel] = useState('claude-sonnet')
  const [maxWorkers, setMaxWorkers] = useState(4)
  const [includePatterns, setIncludePatterns] = useState('*.py,*.js,*.ts,*.go,*.java')
  const [excludePatterns, setExcludePatterns] = useState('node_modules,*.test.*,*.spec.*')
  const [advancedOpen, setAdvancedOpen] = useState(false)

  /* ── scan state ── */
  const [scanStatus, setScanStatus] = useState<ScanStatus>('idle')
  const [progress, setProgress] = useState(0)
  const [filesScanned, setFilesScanned] = useState(0)
  const [totalFiles, setTotalFiles] = useState(0)
  const [currentFile, setCurrentFile] = useState('')
  const [vulnsFound, setVulnsFound] = useState(0)
  const [eta, setEta] = useState('')

  /* ── real API state ── */
  const [currentTaskId, setCurrentTaskId] = useState<string | null>(null)
  const [apiError, setApiError] = useState<string | null>(null)
  const [findings, setFindings] = useState<ApiFinding[]>([])
  const wsRef = useRef<WebSocket | null>(null)

  /* ── results ── */
  const [searchQuery, setSearchQuery] = useState('')
  const [severityFilter, setSeverityFilter] = useState<Severity | 'all'>('all')
  const [sortBy, setSortBy] = useState<'severity' | 'confidence' | 'file'>('severity')
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('desc')

  /* ── polling interval ref ── */
  const pollingRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const clearPolling = useCallback(() => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current)
      pollingRef.current = null
    }
  }, [])

  /* ── stop polling & WS when scan is not active ── */
  useEffect(() => {
    if (scanStatus !== 'scanning') {
      clearPolling()
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [scanStatus, clearPolling])

  /* ── fetch findings helper ── */
  const fetchFindings = useCallback(async (taskId: string) => {
    try {
      const fRes = await scanApi.getFindings(taskId)
      const findingsData = (fRes.data as { findings: ApiFinding[] }).findings || []
      setFindings(findingsData)
      setVulnsFound(findingsData.length)
    } catch {
      setApiError('获取扫描结果失败')
    }
  }, [])

  /* ── poll scan status ── */
  const startPolling = useCallback((taskId: string) => {
    clearPolling()
    pollingRef.current = setInterval(async () => {
      try {
        const { data } = await scanApi.getScanStatus(taskId)
        const status = (data as ScanTask).status
        const prog = (data as ScanTask).progress ?? 0
        const scanned = (data as ScanTask).files_scanned ?? 0
        const total = (data as ScanTask).total_files ?? 0
        const curFile = (data as ScanTask).current_file ?? ''

        setProgress(prog)
        setFilesScanned(scanned)
        setTotalFiles(total)
        setCurrentFile(curFile)

        if (status === 'completed' || status === 'done') {
          clearPolling()
          setScanStatus('completed')
          await fetchFindings(taskId)
        } else if (status === 'cancelled') {
          clearPolling()
          setScanStatus('cancelled')
          setProgress(0)
        } else if (status === 'failed' || status === 'error') {
          clearPolling()
          setScanStatus('error')
        }
      } catch {
        clearPolling()
        setScanStatus('error')
        setApiError('无法连接扫描服务')
      }
    }, 1000)
  }, [clearPolling, fetchFindings])

  /* ── WebSocket connection ── */
  const connectWebSocket = useCallback((taskId: string) => {
    try {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const host = window.location.host
      const ws = new WebSocket(`${proto}//${host}/ws`)
      wsRef.current = ws

      ws.onopen = () => {
        ws.send(JSON.stringify({ type: 'subscribe', channel: `scan/${taskId}` }))
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === 'scan_progress') {
            setProgress(msg.progress ?? 0)
            setFilesScanned(msg.files_scanned ?? 0)
            setTotalFiles(msg.total_files ?? 0)
            setCurrentFile(msg.current_file ?? '')
          } else if (msg.type === 'scan_complete') {
            setScanStatus('completed')
            setProgress(100)
            setVulnsFound(msg.findings_count ?? 0)
            clearPolling()
            fetchFindings(taskId)
          }
        } catch { /* ignore parse errors */ }
      }

      ws.onerror = () => {
        wsRef.current = null
      }

      ws.onclose = () => {
        wsRef.current = null
      }
    } catch {
      // WebSocket not supported
    }
  }, [clearPolling, fetchFindings])

  const handleImport = useCallback(async () => {
    const name = importTab === 'git' ? gitUrl.split('/').pop()?.replace('.git', '') || 'project'
      : importTab === 'local' ? localPath.split(/[\\/]/).pop() || 'local-project'
      : 'uploaded-project'
    setProjectName(name)
    setCurrentProject(name)
    setImportOpen(false)

    try {
      const targetPath = importTab === 'local' ? localPath : importTab === 'git' ? gitUrl : undefined
      const res = await scanApi.startScan({
        target_path: targetPath,
        scan_type: 'full',
        rules: selectedRules,
      })
      const task = res.data as ScanTask
      setCurrentTaskId(task.task_id)
      setScanStatus('scanning')
      setProgress(0)
      setFilesScanned(0)
      setVulnsFound(0)
      setApiError(null)
      startPolling(task.task_id)
      connectWebSocket(task.task_id)
    } catch (e: any) {
      setApiError(`启动扫描失败: ${e?.message ?? '未知错误'}`)
      setScanStatus('idle')
    }
  }, [importTab, gitUrl, localPath, setCurrentProject, selectedRules, startPolling, connectWebSocket])

  const handleStartScan = useCallback(async () => {
    if (!currentTaskId) {
      try {
        const res = await scanApi.startScan({
          scan_type: 'full',
          rules: selectedRules,
        })
        const task = res.data as ScanTask
        setCurrentTaskId(task.task_id)
        setScanStatus('scanning')
        setProgress(0)
        setFilesScanned(0)
        setVulnsFound(0)
        startPolling(task.task_id)
        connectWebSocket(task.task_id)
      } catch {
        setApiError('启动扫描失败')
      }
    } else {
      // resume existing task
      setScanStatus('scanning')
      startPolling(currentTaskId)
      connectWebSocket(currentTaskId)
    }
  }, [currentTaskId, selectedRules, startPolling, connectWebSocket])

  const handlePause = useCallback(() => {
    setScanStatus(s => s === 'scanning' ? 'paused' : s === 'paused' ? 'scanning' : s)
  }, [])

  const handleCancel = useCallback(async () => {
    if (currentTaskId) {
      try {
        await scanApi.cancelScan(currentTaskId)
      } catch { /* ignore */ }
    }
    setScanStatus('cancelled')
    setProgress(0)
    clearPolling()
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }
  }, [currentTaskId, clearPolling])

  const toggleRule = (id: string) => {
    setSelectedRules(prev => prev.includes(id) ? prev.filter(r => r !== id) : [...prev, id])
  }

  /* filtered / sorted findings */
  const filtered = findings
    .filter(f => severityFilter === 'all' || f.severity === severityFilter)
    .filter(f => searchQuery === '' || f.message.toLowerCase().includes(searchQuery.toLowerCase()) || f.file.toLowerCase().includes(searchQuery.toLowerCase()))
    .sort((a, b) => {
      const sevOrder: Record<Severity, number> = { critical: 5, high: 4, medium: 3, low: 2, info: 1 }
      if (sortBy === 'severity') return sortDir === 'desc' ? sevOrder[b.severity] - sevOrder[a.severity] : sevOrder[a.severity] - sevOrder[b.severity]
      if (sortBy === 'confidence') return sortDir === 'desc' ? b.confidence - a.confidence : a.confidence - b.confidence
      return sortDir === 'desc' ? b.file.localeCompare(a.file) : a.file.localeCompare(b.file)
    })

  const severityCounts = findings.reduce((acc, f) => { acc[f.severity] = (acc[f.severity] || 0) + 1; return acc }, {} as Record<Severity, number>)

  const severityIcon = (s: Severity) => {
    switch (s) {
      case 'critical': return <AlertCircle className="h-4 w-4" />
      case 'high': return <AlertTriangle className="h-4 w-4" />
      case 'medium': return <Info className="h-4 w-4" />
      default: return <CheckCircle className="h-4 w-4" />
    }
  }

  /* ─── empty state ─── */
  if (!projectName && scanStatus === 'idle') {
    return (
      <div className="h-full flex flex-col gap-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold text-celestial-text">代码审计</h1>
          <Button variant="primary" size="sm" onClick={() => setImportOpen(true)}>
            <FolderOpen className="mr-2 h-4 w-4" />导入项目
          </Button>
        </div>
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center max-w-md">
            <div className="w-32 h-32 mx-auto mb-6 rounded-full bg-gradient-to-br from-celestial-primary/20 to-celestial-accent/20 flex items-center justify-center">
              <FileCode className="h-16 w-16 text-celestial-accent" />
            </div>
            <h2 className="text-xl font-bold text-celestial-text mb-2">欢迎使用代码审计</h2>
            <p className="text-celestial-textDim mb-6">导入你的项目开始安全扫描，AI 驱动的深度代码分析将帮助你发现潜在漏洞</p>
            <Button variant="primary" onClick={() => setImportOpen(true)}>
              <FolderOpen className="mr-2 h-4 w-4" />开始导入项目
            </Button>
          </div>
        </div>

        {importOpen && <ImportModal
          tab={importTab} setTab={setImportTab}
          gitUrl={gitUrl} setGitUrl={setGitUrl}
          localPath={localPath} setLocalPath={setLocalPath}
          dragOver={dragOver} setDragOver={setDragOver}
          onClose={() => setImportOpen(false)}
          onImport={handleImport}
        />}
      </div>
    )
  }

  /* ─── main view ─── */
  return (
    <div className="h-full flex flex-col gap-4">
      {/* header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <h1 className="text-xl font-bold text-celestial-text">代码审计</h1>
          {projectName && <Badge variant="status">{projectName}</Badge>}
        </div>
        <div className="flex gap-2">
          <Button variant="secondary" size="sm" onClick={() => setImportOpen(true)}>
            <FolderOpen className="mr-2 h-4 w-4" />导入项目
          </Button>
          <Button variant="primary" size="sm" onClick={handleStartScan} disabled={scanStatus === 'scanning' || scanStatus === 'idle'}>
            <Play className="mr-2 h-4 w-4" />
            {scanStatus === 'idle' ? '请先导入项目' : scanStatus === 'completed' ? '重新扫描' : '开始扫描'}
          </Button>
        </div>
      </div>

      {/* api error banner */}
      {apiError && (
        <Card className="border-celestial-alert/30 bg-celestial-alert/5">
          <div className="flex items-center gap-2 text-sm">
            <AlertTriangle className="h-4 w-4 text-celestial-alert" />
            <span className="text-celestial-text">{apiError}</span>
          </div>
        </Card>
      )}

      {/* active scan progress */}
      {(scanStatus === 'scanning' || scanStatus === 'paused') && (
        <Card title="扫描进行中" className="border-celestial-primary/30">
          <div className="space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-celestial-textDim">{currentFile}</span>
              <span className="text-celestial-accent font-bold">{progress}%</span>
            </div>
            <div className="w-full h-2 rounded-full bg-celestial-surfaceLight overflow-hidden">
              <div className="h-full rounded-full bg-gradient-to-r from-celestial-primary to-celestial-accent transition-all duration-300" style={{ width: `${progress}%` }} />
            </div>
            <div className="flex items-center justify-between text-xs text-celestial-textDim">
              <span>{filesScanned} / {totalFiles} 文件</span>
              <span>已发现 <span className="text-celestial-alert font-bold">{vulnsFound}</span> 个漏洞</span>
              <span>预计剩余 {eta}</span>
              <div className="flex gap-2">
                <Button variant="ghost" size="sm" onClick={handlePause}>
                  {scanStatus === 'paused' ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
                </Button>
                <Button variant="danger" size="sm" onClick={handleCancel}><Square className="h-3 w-3" /></Button>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* error state */}
      {scanStatus === 'error' && (
        <Card className="border-celestial-alert/30 bg-celestial-alert/5">
          <div className="flex items-center gap-2">
            <AlertCircle className="h-5 w-5 text-celestial-alert" />
            <span className="text-celestial-text font-medium">扫描出错，请稍后重试</span>
          </div>
        </Card>
      )}

      {/* completed banner */}
      {scanStatus === 'completed' && (
        <Card className="border-celestial-star-safe/30 bg-celestial-star-safe/5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-celestial-star-safe" />
              <span className="text-celestial-text font-medium">扫描完成 — 共发现 {findings.length} 个问题</span>
            </div>
            <div className="flex gap-2">
              <Button variant="secondary" size="sm"><Download className="mr-1 h-3 w-3" />HTML</Button>
              <Button variant="secondary" size="sm"><Download className="mr-1 h-3 w-3" />JSON</Button>
              <Button variant="secondary" size="sm"><Download className="mr-1 h-3 w-3" />Markdown</Button>
            </div>
          </div>
        </Card>
      )}

      {/* summary cards + results */}
      {scanStatus !== 'idle' && (
        <>
          {/* severity summary */}
          <div className="grid grid-cols-5 gap-3">
            {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map(sev => (
              <Card key={sev} className={`text-center py-3 cursor-pointer transition-colors ${severityFilter === sev ? 'ring-2 ring-celestial-primary' : ''}`} onClick={() => setSeverityFilter(severityFilter === sev ? 'all' : sev)}>
                <div className="flex items-center justify-center gap-1 mb-1">{severityIcon(sev)}<span className="text-2xl font-bold text-celestial-text">{severityCounts[sev] || 0}</span></div>
                <Badge variant="severity" severity={sev}>{sev === 'critical' ? '严重' : sev === 'high' ? '高危' : sev === 'medium' ? '中危' : sev === 'low' ? '低危' : '信息'}</Badge>
              </Card>
            ))}
          </div>

          {/* results browser */}
          <Card title="扫描结果" className="flex-1">
            <div className="space-y-3">
              {/* toolbar */}
              <div className="flex gap-2 items-center">
                <div className="flex-1 relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-celestial-textDim" />
                  <Input placeholder="搜索标题、文件..." value={searchQuery} onChange={e => setSearchQuery(e.target.value)} className="pl-9" />
                </div>
                <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value as Severity | 'all')} className="rounded-md border border-celestial-border bg-celestial-bg px-3 py-2 text-sm text-celestial-text">
                  <option value="all">全部严重等级</option>
                  <option value="critical">严重</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                  <option value="info">信息</option>
                </select>
                <select value={`${sortBy}-${sortDir}`} onChange={e => { const [b, d] = e.target.value.split('-'); setSortBy(b as typeof sortBy); setSortDir(d as typeof sortDir) }} className="rounded-md border border-celestial-border bg-celestial-bg px-3 py-2 text-sm text-celestial-text">
                  <option value="severity-desc">严重度 ↓</option>
                  <option value="severity-asc">严重度 ↑</option>
                  <option value="confidence-desc">置信度 ↓</option>
                  <option value="confidence-asc">置信度 ↑</option>
                  <option value="file-asc">文件名 A-Z</option>
                  <option value="file-desc">文件名 Z-A</option>
                </select>
              </div>

              {/* table */}
              <div className="overflow-auto rounded-md border border-celestial-border">
                <table className="w-full text-sm">
                  <thead className="bg-celestial-surfaceLight text-celestial-textDim sticky top-0">
                    <tr>
                      <th className="text-left px-3 py-2 font-medium">严重等级</th>
                      <th className="text-left px-3 py-2 font-medium">标题</th>
                      <th className="text-left px-3 py-2 font-medium">文件</th>
                      <th className="text-left px-3 py-2 font-medium">行</th>
                      <th className="text-left px-3 py-2 font-medium">规则</th>
                      <th className="text-left px-3 py-2 font-medium">置信度</th>
                      <th className="text-left px-3 py-2 font-medium">操作</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filtered.map(f => (
                      <tr key={f.id} className="border-t border-celestial-border/50 hover:bg-celestial-surfaceLight/50 cursor-pointer transition-colors">
                        <td className="px-3 py-2"><Badge variant="severity" severity={f.severity}>{f.severity === 'critical' ? '严重' : f.severity === 'high' ? '高危' : f.severity === 'medium' ? '中危' : f.severity === 'low' ? '低危' : '信息'}</Badge></td>
                        <td className="px-3 py-2 text-celestial-text font-medium truncate max-w-[200px]" title={f.message}>{f.message}</td>
                        <td className="px-3 py-2 text-celestial-textDim font-mono text-xs truncate max-w-[180px]" title={f.file}>{f.file}</td>
                        <td className="px-3 py-2 text-celestial-textDim">{f.line}</td>
                        <td className="px-3 py-2 text-celestial-textDim font-mono text-xs">{f.rule_id}</td>
                        <td className="px-3 py-2"><span className={`font-mono ${f.confidence > 0.85 ? 'text-celestial-star-safe' : f.confidence > 0.6 ? 'text-celestial-star-medium' : 'text-celestial-star-low'}`}>{(f.confidence * 100).toFixed(0)}%</span></td>
                        <td className="px-3 py-2"><Button variant="ghost" size="sm"><Eye className="h-3 w-3" /></Button></td>
                      </tr>
                    ))}
                    {filtered.length === 0 && (
                      <tr><td colSpan={7} className="text-center py-8 text-celestial-textDim">无匹配结果</td></tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </Card>
        </>
      )}

      {/* config panel */}
      {(scanStatus === 'configuring' || (scanStatus !== 'idle' && scanStatus !== 'scanning' && scanStatus !== 'paused' && scanStatus !== 'completed' && scanStatus !== 'error')) ? (
        <Card title="扫描配置">
          <div className="space-y-4">
            <div className="grid grid-cols-3 gap-4">
              <div>
                <label className="mb-1.5 block text-sm text-celestial-textDim">扫描模式</label>
                <select value={scanMode} onChange={e => setScanMode(e.target.value)} className="w-full rounded-md border border-celestial-border bg-celestial-bg px-3 py-2 text-sm text-celestial-text">
                  <option value="auto">Auto — 自动选择</option>
                  <option value="static">Static — 静态分析</option>
                  <option value="hybrid">Hybrid — 混合分析</option>
                </select>
              </div>
              <div>
                <label className="mb-1.5 block text-sm text-celestial-textDim">AI 模型</label>
                <select value={aiModel} onChange={e => setAiModel(e.target.value)} className="w-full rounded-md border border-celestial-border bg-celestial-bg px-3 py-2 text-sm text-celestial-text">
                  <option value="claude-sonnet">Claude Sonnet</option>
                  <option value="claude-opus">Claude Opus</option>
                  <option value="gpt-4o">GPT-4o</option>
                  <option value="gemini-pro">Gemini Pro</option>
                </select>
              </div>
              <div>
                <label className="mb-1.5 block text-sm text-celestial-textDim">并发线程数: {maxWorkers}</label>
                <input type="range" min={1} max={16} value={maxWorkers} onChange={e => setMaxWorkers(Number(e.target.value))} className="w-full accent-celestial-primary" />
              </div>
            </div>

            {/* rule checkboxes */}
            <div>
              <label className="mb-1.5 block text-sm text-celestial-textDim">扫描规则</label>
              <div className="grid grid-cols-4 gap-2">
                {DEFAULT_RULE_CATEGORIES.map(rule => (
                  <label key={rule.id} className="flex items-center gap-2 rounded-md border border-celestial-border px-3 py-2 text-sm cursor-pointer hover:border-celestial-primary transition-colors" style={{ borderColor: selectedRules.includes(rule.id) ? undefined : undefined }}>
                    <input type="checkbox" checked={selectedRules.includes(rule.id)} onChange={() => toggleRule(rule.id)} className="rounded border-celestial-border bg-celestial-bg text-celestial-primary focus:ring-celestial-primary/50" />
                    <span className="text-celestial-textDim">{rule.label}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* patterns */}
            <div className="grid grid-cols-2 gap-4">
              <Input label="包含模式" value={includePatterns} onChange={e => setIncludePatterns(e.target.value)} placeholder="*.py,*.js,*.go" />
              <Input label="排除模式" value={excludePatterns} onChange={e => setExcludePatterns(e.target.value)} placeholder="node_modules,dist,*.test.*" />
            </div>

            {/* advanced */}
            <button onClick={() => setAdvancedOpen(!advancedOpen)} className="flex items-center gap-1 text-sm text-celestial-textDim hover:text-celestial-text transition-colors">
              {advancedOpen ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}高级选项
            </button>
            {advancedOpen && (
              <div className="space-y-3 pl-4 border-l-2 border-celestial-border">
                <label className="flex items-center gap-2 text-sm text-celestial-textDim"><input type="checkbox" className="rounded border-celestial-border bg-celestial-bg text-celestial-primary" />深度上下文分析</label>
                <label className="flex items-center gap-2 text-sm text-celestial-textDim"><input type="checkbox" className="rounded border-celestial-border bg-celestial-bg text-celestial-primary" />跨文件调用链追踪</label>
                <label className="flex items-center gap-2 text-sm text-celestial-textDim"><input type="checkbox" className="rounded border-celestial-border bg-celestial-bg text-celestial-primary" />生成修复代码补丁</label>
                <Input label="自定义规则文件路径" placeholder="/path/to/custom-rules.yaml" />
              </div>
            )}

            <div className="flex gap-2 pt-2">
              <Button variant="primary" onClick={handleStartScan}><Play className="mr-2 h-4 w-4" />开始扫描</Button>
              <Button variant="secondary" onClick={() => setScanStatus('idle')}><Settings className="mr-2 h-4 w-4" />返回</Button>
            </div>
          </div>
        </Card>
      ) : null}

      {/* import modal */}
      {importOpen && <ImportModal
        tab={importTab} setTab={setImportTab}
        gitUrl={gitUrl} setGitUrl={setGitUrl}
        localPath={localPath} setLocalPath={setLocalPath}
        dragOver={dragOver} setDragOver={setDragOver}
        onClose={() => setImportOpen(false)}
        onImport={handleImport}
      />}
    </div>
  )
}

/* ─── Import Modal Component ─── */
interface ImportModalProps {
  tab: ImportTab; setTab: (t: ImportTab) => void
  gitUrl: string; setGitUrl: (v: string) => void
  localPath: string; setLocalPath: (v: string) => void
  dragOver: boolean; setDragOver: (v: boolean) => void
  onClose: () => void; onImport: () => void
}

function ImportModal({ tab, setTab, gitUrl, setGitUrl, localPath, setLocalPath, dragOver, setDragOver, onClose, onImport }: ImportModalProps) {
  const tabs: { key: ImportTab; label: string; icon: typeof FolderOpen }[] = [
    { key: 'git', label: 'Git 仓库', icon: GitBranch },
    { key: 'local', label: '本地目录', icon: FolderOpen },
    { key: 'upload', label: '文件上传', icon: Upload },
  ]

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm z-50 flex items-center justify-center" onClick={onClose}>
      <div className="bg-celestial-surface border border-celestial-border rounded-xl w-full max-w-lg shadow-2xl" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-celestial-border px-5 py-4">
          <h2 className="text-lg font-bold text-celestial-text">导入项目</h2>
          <button onClick={onClose} className="text-celestial-textDim hover:text-celestial-text transition-colors"><X className="h-5 w-5" /></button>
        </div>
        <div className="flex border-b border-celestial-border">
          {tabs.map(t => (
            <button key={t.key} onClick={() => setTab(t.key)} className={`flex-1 flex items-center justify-center gap-2 py-3 text-sm font-medium transition-colors ${tab === t.key ? 'text-celestial-accent border-b-2 border-celestial-accent' : 'text-celestial-textDim hover:text-celestial-text'}`}>
              <t.icon className="h-4 w-4" />{t.label}
            </button>
          ))}
        </div>
        <div className="p-5 space-y-4">
          {tab === 'git' && (
            <div className="space-y-3">
              <Input label="Git 仓库 URL" placeholder="https://github.com/user/repo.git" value={gitUrl} onChange={e => setGitUrl(e.target.value)} />
              <Button variant="primary" className="w-full" disabled={!gitUrl}><GitBranch className="mr-2 h-4 w-4" />Clone 仓库</Button>
            </div>
          )}
          {tab === 'local' && (
            <div className="space-y-3">
              <Input label="本地目录路径" placeholder="C:\projects\my-app 或 /home/user/project" value={localPath} onChange={e => setLocalPath(e.target.value)} />
              <Button variant="primary" className="w-full" disabled={!localPath}><FolderOpen className="mr-2 h-4 w-4" />导入目录</Button>
            </div>
          )}
          {tab === 'upload' && (
            <div
              className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${dragOver ? 'border-celestial-primary bg-celestial-primary/10' : 'border-celestial-border'}`}
              onDragOver={e => { e.preventDefault(); setDragOver(true) }}
              onDragLeave={() => setDragOver(false)}
              onDrop={e => { e.preventDefault(); setDragOver(false) }}
            >
              <Upload className="h-10 w-10 mx-auto mb-3 text-celestial-textDim" />
              <p className="text-celestial-text mb-1">拖放 ZIP 文件到此处</p>
              <p className="text-xs text-celestial-textDim mb-3">或点击选择文件</p>
              <Button variant="secondary" size="sm">选择文件</Button>
            </div>
          )}
        </div>
        <div className="flex justify-end gap-2 border-t border-celestial-border px-5 py-3">
          <Button variant="secondary" onClick={onClose}>取消</Button>
          <Button variant="primary" onClick={onImport} disabled={tab === 'git' && !gitUrl || tab === 'local' && !localPath}>确认导入</Button>
        </div>
      </div>
    </div>
  )
}
