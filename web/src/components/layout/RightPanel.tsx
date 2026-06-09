import { X } from 'lucide-react'
import { useAppStore } from '../../stores/appStore'
import type { Finding } from '../../types'

export default function RightPanel() {
  const { rightPanelOpen, rightPanelType, rightPanelData, closeRightPanel } = useAppStore()
  
  if (!rightPanelOpen) return null
  
  return (
    <aside className="w-80 border-l border-celestial-border bg-celestial-surface flex flex-col">
      <div className="flex items-center justify-between border-b border-celestial-border p-3">
        <h3 className="text-sm font-medium text-celestial-text">
          {rightPanelType === 'finding' ? '漏洞详情' : rightPanelType === 'node' ? '资产详情' : '详情'}
        </h3>
        <button onClick={closeRightPanel} className="text-celestial-textDim hover:text-celestial-text">
          <X className="h-4 w-4" />
        </button>
      </div>
      <div className="flex-1 overflow-auto p-4">
        {rightPanelType === 'finding' && rightPanelData && (
          <FindingDetail finding={rightPanelData as Finding} />
        )}
        {rightPanelType === 'node' && rightPanelData && (
          <div className="space-y-3 text-sm">
            <div><span className="text-celestial-textDim">名称</span><p className="text-celestial-text mt-1">{rightPanelData.label}</p></div>
            <div><span className="text-celestial-textDim">类型</span><p className="text-celestial-text mt-1">{rightPanelData.type}</p></div>
            {rightPanelData.severity && (
              <div><span className="text-celestial-textDim">风险等级</span><p className={`mt-1 font-mono ${severityColor(rightPanelData.severity)}`}>{rightPanelData.severity}</p></div>
            )}
          </div>
        )}
      </div>
    </aside>
  )
}

function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div className="space-y-4 text-sm">
      <div>
        <span className="text-celestial-textDim">标题</span>
        <p className="text-celestial-text mt-1 font-medium">{finding.title}</p>
      </div>
      <div>
        <span className="text-celestial-textDim">严重级别</span>
        <p className={`mt-1 font-mono font-bold ${severityColor(finding.severity)}`}>
          {finding.severity.toUpperCase()}
        </p>
      </div>
      <div>
        <span className="text-celestial-textDim">文件</span>
        <p className="mt-1 font-mono text-xs text-celestial-accent break-all">{finding.file_path}</p>
        {finding.line_number && <p className="text-xs text-celestial-textDim">行号: {finding.line_number}</p>}
      </div>
      <div>
        <span className="text-celestial-textDim">描述</span>
        <p className="mt-1 text-celestial-textDim">{finding.description}</p>
      </div>
      {finding.fix_suggestion && (
        <div>
          <span className="text-celestial-textDim">修复建议</span>
          <p className="mt-1 text-celestial-accent">{finding.fix_suggestion}</p>
        </div>
      )}
    </div>
  )
}

function severityColor(severity: string): string {
  switch (severity) {
    case 'critical': return 'text-red-500'
    case 'high': return 'text-celestial-star-high'
    case 'medium': return 'text-celestial-star-medium'
    case 'low': return 'text-celestial-star-low'
    default: return 'text-celestial-star-safe'
  }
}
