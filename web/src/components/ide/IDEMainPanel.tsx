import { useState, useCallback, useMemo } from 'react'
import { X, Copy, Wand2, FileCode, FileX } from 'lucide-react'
import CodeViewer from './CodeViewer'
import VulnTimeline from './VulnTimeline'
import FixSuggestions from './FixSuggestions'
import type { VulnItem, FixSuggestion } from './types'

export interface IDEPanelProps {
  fileId: string
  filePath: string
  code: string
  vulns: VulnItem[]
  fixes: FixSuggestion[]
  onClose?: () => void
}

export default function IDEPanel({
  fileId,
  filePath,
  code,
  vulns,
  fixes,
  onClose,
}: IDEPanelProps) {
  const [activeLine, setActiveLine] = useState<number | null>(null)
  const [showCopied, setShowCopied] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  const language = useMemo(() => {
    const ext = filePath.split('.').pop()?.toLowerCase()
    const map: Record<string, string> = {
      py: 'python',
      js: 'javascript', jsx: 'javascript',
      ts: 'typescript', tsx: 'typescript',
      java: 'java',
      cpp: 'cpp', cc: 'cpp', cxx: 'cpp', h: 'cpp', hpp: 'cpp',
      go: 'go',
      rs: 'rust',
    }
    return map[ext || ''] || 'plaintext'
  }, [filePath])

  const vulnLines = useMemo(() => vulns.map((v) => v.line), [vulns])

  const handleJumpToLine = useCallback((line: number) => {
    setActiveLine(line)
  }, [])

  const handleCopyCode = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(code)
      setShowCopied(true)
      setTimeout(() => setShowCopied(false), 2000)
    } catch {
      // Clipboard not available
    }
  }, [code])

  const handleAnalyze = useCallback(async () => {
    setIsAnalyzing(true)
    try {
      const res = await fetch('/api/ide/code', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_path: filePath, action: 'analyze' }),
      })
      if (!res.ok) {
        console.error(`[IDE] 分析失败: ${res.status} ${res.statusText}`)
        alert(`AI 分析功能不可用 (HTTP ${res.status})。\n请检查后端日志获取详细信息。`)
      }
    } catch (err) {
      console.error('[IDE] 分析请求异常:', err)
      alert('AI 分析功能不可用，请检查后端服务是否正常运行。\n详细错误请查看浏览器控制台日志。')
    } finally {
      setIsAnalyzing(false)
    }
  }, [filePath])

  return (
    <div className="flex flex-col h-full bg-celestial-bg">
      {/* Toolbar */}
      <div className="flex items-center justify-between px-3 py-2 border-b border-celestial-border bg-celestial-surface shrink-0">
        <div className="flex items-center gap-2 min-w-0">
          <FileCode size={16} className="text-celestial-accent shrink-0" />
          <span className="text-sm font-mono text-celestial-text truncate" title={filePath}>
            {filePath}
          </span>
          {vulns.length > 0 && (
            <span className="text-xs px-1.5 py-0.5 rounded-full bg-red-400/10 text-red-400 border border-red-400/30 shrink-0">
              {vulns.length}
            </span>
          )}
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          <button
            className={`flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded border transition-colors ${
              showCopied
                ? 'border-celestial-accent/30 text-celestial-accent'
                : 'border-celestial-border text-celestial-textDim hover:text-celestial-text hover:border-celestial-textDim'
            }`}
            onClick={handleCopyCode}
            title="复制代码"
          >
            <Copy size={12} />
            {showCopied ? '已复制' : '复制'}
          </button>

          <button
            className="flex items-center gap-1.5 text-xs px-2.5 py-1.5 rounded bg-celestial-accent/10 text-celestial-accent border border-celestial-accent/30 hover:bg-celestial-accent/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
            onClick={handleAnalyze}
            disabled={isAnalyzing}
            title="AI 分析"
          >
            <Wand2 size={12} />
            {isAnalyzing ? '分析中...' : 'AI 分析'}
          </button>

          {onClose && (
            <button
              className="p-1.5 rounded border border-celestial-border text-celestial-textDim hover:text-celestial-text hover:border-celestial-textDim transition-colors"
              onClick={onClose}
              title="关闭"
            >
              <X size={14} />
            </button>
          )}
        </div>
      </div>

      {/* Main content area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Code editor - 70% */}
        <div className="flex-[7] min-w-0 border-r border-celestial-border">
          <CodeViewer
            filePath={filePath}
            code={code}
            vulnLines={activeLine ? [...vulnLines, activeLine] : vulnLines}
            language={language}
            onLineClick={handleJumpToLine}
          />
        </div>

        {/* Right sidebar - 30% */}
        <div className="flex-[3] min-w-0 flex flex-col overflow-hidden bg-celestial-surface">
          <div className="flex-1 overflow-auto p-3 space-y-4">
            {/* Vulnerability Timeline */}
            <div className="pb-3 border-b border-celestial-border">
              <VulnTimeline
                vulns={vulns}
                onJumpToLine={handleJumpToLine}
              />
            </div>

            {/* Fix Suggestions */}
            <div>
              <FixSuggestions suggestions={fixes} />
            </div>
          </div>
        </div>
      </div>

      {/* Status bar */}
      <div className="flex items-center justify-between px-3 py-1.5 border-t border-celestial-border bg-celestial-surface shrink-0">
        <div className="flex items-center gap-3 text-xs text-celestial-textDim">
          <span className="font-mono">{filePath.split('/').pop()}</span>
          <span className="text-celestial-textDim/60">|</span>
          <span>{language}</span>
          <span className="text-celestial-textDim/60">|</span>
          <span>{code.split('\n').length} 行</span>
        </div>
        <div className="flex items-center gap-3 text-xs">
          {vulns.length > 0 && (
            <span className="text-red-400 flex items-center gap-1">
              <FileX size={12} />
              {vulns.length} 个漏洞
            </span>
          )}
          {fixes.length > 0 && (
            <span className="text-celestial-accent flex items-center gap-1">
              <Wand2 size={12} />
              {fixes.length} 条修复建议
            </span>
          )}
        </div>
      </div>
    </div>
  )
}
