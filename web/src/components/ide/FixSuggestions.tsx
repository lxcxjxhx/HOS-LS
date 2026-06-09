import { useState } from 'react'
import { Copy, Check, Wand2 } from 'lucide-react'
import type { FixSuggestion } from './types'

interface FixSuggestionsProps {
  suggestions: FixSuggestion[]
}

export default function FixSuggestions({ suggestions }: FixSuggestionsProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null)

  if (suggestions.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-celestial-textDim">
        <Wand2 size={32} className="mb-2 text-celestial-accent/50" />
        <p className="text-sm">暂无修复建议</p>
        <p className="text-xs mt-1">点击 "AI 分析" 生成修复方案</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-sm font-semibold text-celestial-text">
          AI 修复建议
        </h3>
        <span className="text-xs px-2 py-0.5 rounded-full bg-celestial-accent/10 text-celestial-accent border border-celestial-accent/30">
          {suggestions.length} 条
        </span>
      </div>

      {suggestions.map((fix) => (
        <FixCard
          key={fix.id}
          fix={fix}
          isCopied={copiedId === fix.id}
          onCopy={() => {
            navigator.clipboard.writeText(fix.code)
            setCopiedId(fix.id)
            setTimeout(() => setCopiedId(null), 2000)
          }}
        />
      ))}
    </div>
  )
}

function FixCard({
  fix,
  isCopied,
  onCopy,
}: {
  fix: FixSuggestion
  isCopied: boolean
  onCopy: () => void
}) {
  const [expanded, setExpanded] = useState(false)

  const confidenceColor =
    fix.confidence >= 0.8
      ? 'text-green-400'
      : fix.confidence >= 0.5
        ? 'text-yellow-400'
        : 'text-red-400'

  const confidenceLabel =
    fix.confidence >= 0.8
      ? '高'
      : fix.confidence >= 0.5
        ? '中'
        : '低'

  return (
    <div className="rounded-lg border border-celestial-border bg-celestial-surface overflow-hidden">
      <div className="p-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <h4 className="text-sm font-medium text-celestial-text truncate">
              {fix.title}
            </h4>
            <div className="flex items-center gap-2 mt-1">
              <span className={`text-xs ${confidenceColor}`}>
                置信度: {Math.round(fix.confidence * 100)}% ({confidenceLabel})
              </span>
              {fix.vuln_id && (
                <span className="text-xs text-celestial-textDim/60">
                  关联漏洞: {fix.vuln_id}
                </span>
              )}
            </div>
          </div>
        </div>

        {expanded && (
          <div className="mt-3 space-y-3">
            <p className="text-xs text-celestial-textDim leading-relaxed">
              {fix.description}
            </p>

            <div className="relative">
              <div className="flex items-center justify-between bg-celestial-bg rounded-t px-2 py-1 border border-celestial-border border-b-0">
                <span className="text-xs text-celestial-textDim/60">修复代码</span>
                <button
                  className="flex items-center gap-1 text-xs text-celestial-textDim hover:text-celestial-accent transition-colors"
                  onClick={onCopy}
                >
                  {isCopied ? (
                    <>
                      <Check size={12} />
                      <span className="text-celestial-accent">已复制</span>
                    </>
                  ) : (
                    <>
                      <Copy size={12} />
                      <span>复制</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="bg-celestial-bg rounded-b border border-celestial-border p-3 overflow-x-auto">
                <code className="text-xs font-mono text-celestial-text whitespace-pre">
                  {fix.code}
                </code>
              </pre>
            </div>
          </div>
        )}

        <div className="flex items-center gap-2 mt-2">
          <button
            className="text-xs px-2.5 py-1 rounded bg-celestial-accent/10 text-celestial-accent hover:bg-celestial-accent/20 transition-colors"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? '收起' : '展开'}
          </button>
          <button
            className="text-xs px-2.5 py-1 rounded bg-celestial-primary/20 text-celestial-primaryLight hover:bg-celestial-primary/30 transition-colors opacity-50 cursor-not-allowed"
            title="Coming Soon"
            disabled
          >
            应用修复
          </button>
        </div>
      </div>
    </div>
  )
}
