import { useCallback, useRef, useEffect, useState } from 'react'
import Editor, { loader, OnMount } from '@monaco-editor/react'
import type * as monaco from 'monaco-editor'

interface CodeViewerProps {
  filePath: string
  code: string
  vulnLines: number[]
  language: string
  onLineClick?: (line: number) => void
}

// Detect language from file extension
export function detectLanguage(filePath: string): string {
  const ext = filePath.split('.').pop()?.toLowerCase()
  const map: Record<string, string> = {
    py: 'python',
    js: 'javascript',
    jsx: 'javascript',
    ts: 'typescript',
    tsx: 'typescript',
    java: 'java',
    cpp: 'cpp',
    cc: 'cpp',
    cxx: 'cpp',
    h: 'cpp',
    hpp: 'cpp',
    go: 'go',
    rs: 'rust',
    rb: 'ruby',
    php: 'php',
    cs: 'csharp',
    swift: 'swift',
    kt: 'kotlin',
    scala: 'scala',
    sh: 'shell',
    bash: 'shell',
    zsh: 'shell',
    ps1: 'powershell',
    html: 'html',
    css: 'css',
    scss: 'scss',
    json: 'json',
    yaml: 'yaml',
    yml: 'yaml',
    xml: 'xml',
    md: 'markdown',
    sql: 'sql',
    dockerfile: 'dockerfile',
  }
  return map[ext || ''] || 'plaintext'
}

export default function CodeViewer({
  filePath,
  code,
  vulnLines,
  language,
  onLineClick,
}: CodeViewerProps) {
  const editorRef = useRef<monaco.editor.IStandaloneCodeEditor | null>(null)
  const [decorations, setDecorations] = useState<string[]>([])

  const handleEditorDidMount: OnMount = useCallback((editor) => {
    editorRef.current = editor

    // Add click handler for line clicks
    editor.onMouseDown((e) => {
      if (e.target.position && onLineClick) {
        const line = e.target.position.lineNumber
        if (vulnLines.includes(line)) {
          onLineClick(line)
        }
      }
    })
  }, [vulnLines, onLineClick])

  // Update decorations when vulnLines change
  useEffect(() => {
    const editor = editorRef.current
    if (!editor) return

    const model = editor.getModel()
    if (!model) return

    const newDecorations = vulnLines.map((line) => ({
      range: new (monaco as any).Range(line, 1, line, 1),
      options: {
        isWholeLine: true,
        className: 'hos-vuln-line-highlight',
        glyphMarginClassName: 'hos-vuln-gutter',
        glyphMarginHoverMessage: { value: '⚠ Vulnerable line' },
      },
    }))

    const ids = editor.deltaDecorations(decorations, newDecorations)
    setDecorations(ids)
  }, [vulnLines])

  // Jump to a specific line
  useEffect(() => {
    const editor = editorRef.current
    if (!editor || vulnLines.length === 0) return
    // Reveal the first vulnerable line
    editor.revealLineInCenter(vulnLines[0])
  }, [code])

  return (
    <div className="h-full w-full overflow-hidden">
      <style>{`
        .hos-vuln-line-highlight {
          background: rgba(255, 34, 34, 0.12) !important;
        }
        .hos-vuln-gutter {
          background: rgba(255, 34, 34, 0.25) !important;
          width: 4px !important;
          margin-left: 4px !important;
          border-radius: 2px !important;
        }
        /* Monaco editor container height */
        .monaco-editor-container {
          height: 100% !important;
        }
      `}</style>
      <Editor
        height="100%"
        language={language}
        value={code}
        theme="vs-dark"
        options={{
          readOnly: true,
          minimap: { enabled: true },
          lineNumbers: 'on',
          fontSize: 13,
          fontFamily: "'JetBrains Mono', 'Fira Code', 'Consolas', monospace",
          scrollBeyondLastLine: true,
          renderLineHighlight: 'all',
          smoothScrolling: true,
          cursorBlinking: 'smooth',
          cursorSmoothCaretAnimation: 'on',
          folding: true,
          wordWrap: 'off',
          tabSize: 2,
          bracketPairColorization: { enabled: true },
          guides: { bracketPairs: true, indentation: true },
          padding: { top: 8, bottom: 8 },
          scrollbar: {
            verticalScrollbarSize: 8,
            horizontalScrollbarSize: 8,
          },
        }}
        onMount={handleEditorDidMount}
      />
    </div>
  )
}
