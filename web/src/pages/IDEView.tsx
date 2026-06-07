import { useParams, useNavigate } from 'react-router-dom'
import { IDEPanel } from '../components/ide'
import type { VulnItem, FixSuggestion } from '../components/ide/types'
import { useState, useEffect } from 'react'
import { AlertTriangle, ArrowLeft } from 'lucide-react'

const API_BASE = import.meta.env.VITE_API_BASE || '/api'

export default function IDEView() {
  const { fileId } = useParams<{ fileId: string }>()
  const navigate = useNavigate()
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)
  const [filePath, setFilePath] = useState('')
  const [code, setCode] = useState('')
  const [vulns, setVulns] = useState<VulnItem[]>([])
  const [fixes, setFixes] = useState<FixSuggestion[]>([])

  useEffect(() => {
    if (!fileId) { setNotFound(true); setLoading(false); return }

    // Try to fetch file data from backend (file content + findings)
    Promise.all([
      fetch(`${API_BASE}/star-map`).then(res => res.ok ? res.json() : null).catch(() => null),
      fetch(`${API_BASE}/findings`).then(res => res.ok ? res.json() : []).catch(() => []),
    ]).then(([starMap, findings]) => {
      // Find the node matching this fileId
      const node = starMap?.nodes?.find((n: any) => n.id === fileId)
      if (node) {
        setFilePath(node.label || fileId)
      } else {
        setFilePath(fileId)
      }

      // Find vulns for this file
      const fileVulns: VulnItem[] = (findings || [])
        .filter((f: any) => f.file_path === node?.label || f.file === node?.label || f.id === fileId)
        .map((f: any) => ({
          id: f.id,
          severity: f.severity as VulnItem['severity'],
          title: f.title || f.message || 'Unknown vulnerability',
          line: f.line_number || f.line || 0,
          description: f.description || f.details || '',
          rule_id: f.rule_id,
          cwe_id: f.cwe_id,
        }))

      setVulns(fileVulns)
      setFixes([])

      // Try to read file content via a file endpoint
      return fetch(`${API_BASE}/files/${encodeURIComponent(fileId)}`)
        .then(res => {
          if (res.ok) return res.json()
          return null
        })
        .catch(() => null)
    }).then(fileData => {
      if (fileData?.content) {
        setCode(fileData.content)
      } else {
        // No file content available — the IDE panel will show the path
        setCode('// 文件内容不可用 — 请先确保项目已正确导入\n// File content not available')
      }
    }).catch(() => {
      setNotFound(true)
    }).finally(() => {
      setLoading(false)
    })
  }, [fileId])

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-celestial-textDim">
        <p className="text-lg mb-2">加载文件...</p>
      </div>
    )
  }

  if (notFound) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-celestial-textDim">
        <AlertTriangle className="h-12 w-12 mb-3 text-celestial-textDim/30" />
        <p className="text-lg mb-2">文件未找到</p>
        <button
          className="text-sm text-celestial-accent hover:underline flex items-center gap-1"
          onClick={() => navigate('/')}
        >
          <ArrowLeft className="h-3 w-3" />返回星图
        </button>
      </div>
    )
  }

  return (
    <div className="h-full">
      <IDEPanel
        fileId={fileId || ''}
        filePath={filePath || fileId || ''}
        code={code}
        vulns={vulns}
        fixes={fixes}
        onClose={() => navigate('/')}
      />
    </div>
  )
}
