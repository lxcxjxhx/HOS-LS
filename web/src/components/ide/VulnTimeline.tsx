import { useState } from 'react'
import { ChevronDown, ChevronRight, AlertTriangle, ShieldX, ShieldAlert, ShieldCheck, Shield } from 'lucide-react'
import type { VulnItem } from './types'

interface VulnTimelineProps {
  vulns: VulnItem[]
  onJumpToLine: (line: number) => void
}

const SEVERITY_CONFIG: Record<string, { color: string; bg: string; icon: typeof Shield; label: string }> = {
  critical: {
    color: 'text-red-400',
    bg: 'bg-red-400/10 border-red-400/30',
    icon: ShieldX,
    label: '严重',
  },
  high: {
    color: 'text-orange-400',
    bg: 'bg-orange-400/10 border-orange-400/30',
    icon: ShieldAlert,
    label: '高危',
  },
  medium: {
    color: 'text-yellow-400',
    bg: 'bg-yellow-400/10 border-yellow-400/30',
    icon: AlertTriangle,
    label: '中危',
  },
  low: {
    color: 'text-blue-400',
    bg: 'bg-blue-400/10 border-blue-400/30',
    icon: ShieldCheck,
    label: '低危',
  },
  info: {
    color: 'text-gray-400',
    bg: 'bg-gray-400/10 border-gray-400/30',
    icon: Shield,
    label: '信息',
  },
}

export default function VulnTimeline({ vulns, onJumpToLine }: VulnTimelineProps) {
  if (vulns.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center py-8 text-celestial-textDim">
        <ShieldCheck size={32} className="mb-2 text-celestial-accent/50" />
        <p className="text-sm">未发现漏洞</p>
        <p className="text-xs mt-1">此文件暂无安全风险</p>
      </div>
    )
  }

  // Group by severity
  const grouped: Record<string, VulnItem[]> = {}
  vulns.forEach((v) => {
    if (!grouped[v.severity]) grouped[v.severity] = []
    grouped[v.severity].push(v)
  })

  const severityOrder = ['critical', 'high', 'medium', 'low', 'info']

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-celestial-text">
          漏洞时间线
        </h3>
        <span className="text-xs px-2 py-0.5 rounded-full bg-red-400/10 text-red-400 border border-red-400/30">
          {vulns.length} 个漏洞
        </span>
      </div>

      <div className="space-y-3">
        {severityOrder.map((sev) => {
          const items = grouped[sev]
          if (!items) return null
          const config = SEVERITY_CONFIG[sev]
          const Icon = config.icon

          return (
            <div key={sev}>
              <div className="flex items-center gap-2 text-xs font-medium text-celestial-textDim mb-1">
                <Icon size={12} className={config.color} />
                <span className={config.color}>{config.label}</span>
                <span className="text-celestial-textDim/60">({items.length})</span>
              </div>

              <div className="ml-4 space-y-1.5">
                {items.map((vuln, idx) => (
                  <VulnCard
                    key={vuln.id}
                    vuln={vuln}
                    config={config}
                    isLast={idx === items.length - 1}
                    onClick={() => onJumpToLine(vuln.line)}
                  />
                ))}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

function VulnCard({
  vuln,
  config,
  isLast,
  onClick,
}: {
  vuln: VulnItem
  config: (typeof SEVERITY_CONFIG)[string]
  isLast: boolean
  onClick: () => void
}) {
  const [expanded, setExpanded] = useState(false)

  return (
    <div className="relative">
      {/* Timeline connector */}
      <div className="absolute left-[-16px] top-0 bottom-0 w-px bg-celestial-border">
        {!isLast && <div className="absolute top-0 bottom-0 left-0 w-px bg-celestial-border" />}
      </div>
      <div className="absolute left-[-18px] top-3 w-2 h-2 rounded-full bg-celestial-border" />

      <div
        className={`rounded-lg border ${config.bg} cursor-pointer transition-all hover:opacity-80`}
        onClick={() => setExpanded(!expanded)}
      >
        <div className="p-2.5">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <span className={`text-xs font-mono px-1.5 py-0.5 rounded ${config.color} bg-celestial-bg/50`}>
                L:{vuln.line}
              </span>
              <span className="text-sm font-medium text-celestial-text">{vuln.title}</span>
            </div>
            <div className="flex items-center gap-1">
              <span className="text-xs text-celestial-textDim/60">行 {vuln.line}</span>
              {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
            </div>
          </div>

          {vuln.cwe_id && (
            <div className="mt-1 flex items-center gap-2">
              <span className="text-xs text-celestial-textDim/60">CWE: {vuln.cwe_id}</span>
              {vuln.rule_id && (
                <span className="text-xs text-celestial-textDim/60">规则: {vuln.rule_id}</span>
              )}
            </div>
          )}

          {expanded && (
            <div className="mt-2 pt-2 border-t border-celestial-border/30">
              <p className="text-xs text-celestial-textDim leading-relaxed">
                {vuln.description}
              </p>
              <button
                className="mt-2 text-xs px-2 py-1 rounded bg-celestial-accent/10 text-celestial-accent hover:bg-celestial-accent/20 transition-colors"
                onClick={(e) => {
                  e.stopPropagation()
                  onClick()
                }}
              >
                跳转到行 →
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
