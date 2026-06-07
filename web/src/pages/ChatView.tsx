import { useState, useRef, useEffect, useCallback } from 'react'
import { Button } from '../components/ui/Button'
import { Input } from '../components/ui/Input'
import { Card } from '../components/ui/Card'
import { Badge } from '../components/ui/Badge'
import {
  Send, MessageSquare, BookOpen, Code, GitBranch,
  FileText, Search, Shield, X, Plus, Edit2, Trash2,
  Sparkles, ChevronLeft, ChevronRight, StopCircle,
  Paperclip, FileCode
} from 'lucide-react'

/* ─── types ─── */
interface ChatMessage {
  id: string
  role: 'user' | 'assistant' | 'system'
  content: string
  timestamp: string
}

interface ChatSession {
  id: string
  name: string
  messageCount: number
  createdAt: string
}

interface QuickAction {
  label: string
  icon: typeof BookOpen
  message: string
}

const QUICK_ACTIONS: QuickAction[] = [
  { label: '解释这个漏洞', icon: BookOpen, message: '请详细解释这个漏洞的原理、影响范围和利用方式' },
  { label: '生成修复代码', icon: Code, message: '请生成修复这个漏洞的代码补丁' },
  { label: '分析攻击路径', icon: GitBranch, message: '请分析从入口到目标的完整攻击路径' },
  { label: '生成渗透测试报告', icon: FileText, message: '请生成一份完整的渗透测试报告' },
  { label: '代码安全审计', icon: Search, message: '请对以下代码进行全面的安全审计' },
  { label: 'OWASP Top 10 检查', icon: Shield, message: '请检查项目是否符合 OWASP Top 10 安全要求' },
]

/* ─── simple markdown-like renderer ─── */
function renderContent(content: string): React.ReactNode {
  const lines = content.split('\n')
  const elements: React.ReactNode[] = []
  let inCodeBlock = false
  let codeLines: string[] = []
  let codeLang = ''
  let listItems: string[] = []
  let keyIdx = 0

  const flushList = () => {
    if (listItems.length > 0) {
      elements.push(
        <ul key={`list-${keyIdx++}`} className="list-disc pl-5 space-y-0.5 my-1">
          {listItems.map((item, i) => <li key={i} className="text-sm">{renderInline(item.replace(/^[-*•]\s?/, ''))}</li>)}
        </ul>
      )
      listItems = []
    }
  }

  const flushCode = () => {
    if (codeLines.length > 0) {
      elements.push(
        <div key={`code-${keyIdx++}`} className="my-2 rounded-md bg-celestial-bg border border-celestial-border overflow-hidden">
          {codeLang && <div className="px-3 py-1 text-xs text-celestial-textDim bg-celestial-surfaceLight border-b border-celestial-border">{codeLang}</div>}
          <pre className="p-3 text-xs text-celestial-accent overflow-x-auto"><code>{codeLines.join('\n')}</code></pre>
        </div>
      )
      codeLines = []
      codeLang = ''
    }
  }

  for (const line of lines) {
    if (line.startsWith('```')) {
      if (inCodeBlock) { flushCode(); inCodeBlock = false }
      else { flushList(); inCodeBlock = true; codeLang = line.slice(3) }
      continue
    }
    if (inCodeBlock) { codeLines.push(line); continue }

    if (line.startsWith('## ')) { flushList(); elements.push(<h3 key={`h3-${keyIdx++}`} className="text-sm font-bold text-celestial-text mt-3 mb-1">{renderInline(line.slice(3))}</h3>); continue }
    if (line.startsWith('### ')) { flushList(); elements.push(<h4 key={`h4-${keyIdx++}`} className="text-xs font-bold text-celestial-text mt-2 mb-1">{renderInline(line.slice(4))}</h4>); continue }
    if (line.startsWith('|')) { continue }
    if (line.startsWith('- ') || line.startsWith('• ') || line.startsWith('* ')) { listItems.push(line); continue }

    flushList()
    if (line.trim() === '') { elements.push(<div key={`br-${keyIdx++}`} className="h-1" />); continue }
    elements.push(<p key={`p-${keyIdx++}`} className="text-sm leading-relaxed my-0.5">{renderInline(line)}</p>)
  }

  flushList()
  flushCode()
  return elements
}

function renderInline(text: string): React.ReactNode {
  const parts: React.ReactNode[] = []
  const segments = text.split(/(\*\*[^*]+\*\*|`[^`]+`)/g)
  segments.forEach((seg, i) => {
    if (seg.startsWith('**') && seg.endsWith('**')) {
      parts.push(<strong key={i} className="font-bold text-celestial-text">{seg.slice(2, -2)}</strong>)
    } else if (seg.startsWith('`') && seg.endsWith('`')) {
      parts.push(<code key={i} className="px-1 py-0.5 rounded bg-celestial-bg text-celestial-accent text-xs font-mono">{seg.slice(1, -1)}</code>)
    } else {
      parts.push(seg)
    }
  })
  return parts.length === 1 ? parts[0] : <>{parts}</>
}

const API_BASE = import.meta.env.VITE_API_BASE || '/api'

export default function ChatView() {
  const [sessions, setSessions] = useState<ChatSession[]>([])
  const [activeSession, setActiveSession] = useState<string>('')
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [input, setInput] = useState('')
  const [isStreaming, setIsStreaming] = useState(false)
  const [streamText, setStreamText] = useState('')
  const [sidebarOpen, setSidebarOpen] = useState(true)
  const [contextData, setContextData] = useState<{ file: string; vuln: string } | null>(null)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [editName, setEditName] = useState('')
  const [apiError, setApiError] = useState<string | null>(null)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const abortRef = useRef<AbortController | null>(null)

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages, streamText])

  /* cleanup on unmount */
  useEffect(() => {
    return () => { if (abortRef.current) abortRef.current.abort() }
  }, [])

  /* load sessions on mount */
  useEffect(() => {
    fetch(`${API_BASE}/chat/sessions`)
      .then(res => {
        if (!res.ok) throw new Error('Failed to load sessions')
        return res.json()
      })
      .then(data => {
        const sessionList: ChatSession[] = (data.sessions || []).map((s: any) => ({
          id: s.session_id || s.id,
          name: s.name || s.title || '新对话',
          messageCount: s.message_count || 0,
          createdAt: s.created_at || s.created || '',
        }))
        setSessions(sessionList)
        if (sessionList.length > 0) setActiveSession(sessionList[0].id)
      })
      .catch(() => {
        // No sessions yet or API unavailable — start fresh
      })
  }, [])

  /* load messages when session changes */
  useEffect(() => {
    if (!activeSession) return
    fetch(`${API_BASE}/chat/${activeSession}/history`)
      .then(res => {
        if (!res.ok) throw new Error('Failed to load history')
        return res.json()
      })
      .then(data => {
        const msgs: ChatMessage[] = (data.messages || []).map((m: any) => ({
          id: m.id || `msg-${Math.random()}`,
          role: m.role || 'assistant',
          content: m.content || '',
          timestamp: m.timestamp || m.created_at || '',
        }))
        setMessages(msgs)
      })
      .catch(() => {
        setMessages([])
      })
  }, [activeSession])

  const handleSend = useCallback(async () => {
    if (!input.trim() || isStreaming) return

    const userMsg: ChatMessage = {
      id: `m-${Date.now()}`,
      role: 'user',
      content: input,
      timestamp: new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }),
    }
    setMessages(prev => [...prev, userMsg])
    const currentInput = input
    setInput('')
    setIsStreaming(true)
    setStreamText('')
    setApiError(null)

    const abortController = new AbortController()
    abortRef.current = abortController

    const sessionCtx = contextData ? `[上下文: ${contextData.file} - ${contextData.vuln}]\n\n` : ''

    try {
      const response = await fetch(`${API_BASE}/chat/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          message: sessionCtx + currentInput,
          session_id: activeSession || undefined,
        }),
        signal: abortController.signal,
      })

      if (!response.ok) throw new Error(`API error: ${response.status}`)

      const reader = response.body?.getReader()
      if (!reader) throw new Error('No response body')

      const decoder = new TextDecoder()
      let fullText = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        const chunk = decoder.decode(value, { stream: true })
        fullText += chunk
        setStreamText(fullText)
      }

      // Stream complete — save to messages and update sessions
      const assistantMsg: ChatMessage = {
        id: `m-${Date.now() + 1}`,
        role: 'assistant',
        content: fullText,
        timestamp: new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }),
      }
      setMessages(prev => [...prev, assistantMsg])

      // If no active session, the response might include session_id — create a new session entry
      if (!activeSession && fullText) {
        const newSession: ChatSession = {
          id: `s-${Date.now()}`,
          name: currentInput.slice(0, 20),
          messageCount: 2,
          createdAt: new Date().toLocaleString('zh-CN'),
        }
        setSessions(prev => [newSession, ...prev])
        setActiveSession(newSession.id)
      } else {
        // Update message count
        setSessions(prev => prev.map(s =>
          s.id === activeSession ? { ...s, messageCount: s.messageCount + 2 } : s
        ))
      }
    } catch (err: any) {
      if (err.name !== 'AbortError') {
        setApiError(err.message || '发送消息失败')
      }
    } finally {
      setIsStreaming(false)
      setStreamText('')
      abortRef.current = null
    }
  }, [input, isStreaming, activeSession, contextData])

  const handleStop = useCallback(() => {
    if (abortRef.current) abortRef.current.abort()
    if (streamText) {
      const assistantMsg: ChatMessage = {
        id: `m-${Date.now() + 1}`,
        role: 'assistant',
        content: streamText + '\n\n*[生成已停止]*',
        timestamp: new Date().toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }),
      }
      setMessages(prev => [...prev, assistantMsg])
    }
    setIsStreaming(false)
    setStreamText('')
    abortRef.current = null
  }, [streamText])

  const handleNewChat = async () => {
    try {
      // Create a new session via API
      const res = await fetch(`${API_BASE}/chat/sessions`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: '新对话' }),
      })
      if (res.ok) {
        const data = await res.json()
        const newSession: ChatSession = {
          id: data.session_id || data.id,
          name: '新对话',
          messageCount: 0,
          createdAt: new Date().toLocaleString('zh-CN'),
        }
        setSessions(prev => [newSession, ...prev])
        setActiveSession(newSession.id)
        setMessages([])
      } else {
        // Fallback: create local session
        const newSession: ChatSession = {
          id: `s-${Date.now()}`,
          name: '新对话',
          messageCount: 0,
          createdAt: new Date().toLocaleString('zh-CN'),
        }
        setSessions(prev => [newSession, ...prev])
        setActiveSession(newSession.id)
        setMessages([])
      }
    } catch {
      // Fallback
      const newSession: ChatSession = {
        id: `s-${Date.now()}`,
        name: '新对话',
        messageCount: 0,
        createdAt: new Date().toLocaleString('zh-CN'),
      }
      setSessions(prev => [newSession, ...prev])
      setActiveSession(newSession.id)
      setMessages([])
    }
  }

  const handleDeleteSession = async (id: string) => {
    try {
      await fetch(`${API_BASE}/chat/${id}`, { method: 'DELETE' })
    } catch { /* ignore */ }
    setSessions(prev => prev.filter(s => s.id !== id))
    if (activeSession === id) {
      const remaining = sessions.filter(s => s.id !== id)
      setActiveSession(remaining[0]?.id || '')
      setMessages(remaining[0] ? [] : [])
    }
  }

  const handleRenameSession = async (id: string) => {
    if (!editName.trim()) { setEditingId(null); return }
    try {
      await fetch(`${API_BASE}/chat/${id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: editName }),
      })
    } catch { /* ignore */ }
    setSessions(prev => prev.map(s => s.id === id ? { ...s, name: editName } : s))
    setEditingId(null)
  }

  const handleQuickAction = (action: QuickAction) => {
    setInput(action.message)
  }

  return (
    <div className="h-full flex gap-4">
      {/* sidebar */}
      <div className={`${sidebarOpen ? 'w-56' : 'w-0'} flex-shrink-0 transition-all duration-300 overflow-hidden`}>
        <Card className="h-full flex flex-col p-0">
          <div className="border-b border-celestial-border px-3 py-2.5 flex items-center justify-between">
            <span className="text-sm font-medium text-celestial-text">对话历史</span>
            <Button variant="ghost" size="sm" onClick={handleNewChat}><Plus className="h-4 w-4" /></Button>
          </div>
          <div className="flex-1 overflow-auto p-2 space-y-1">
            {sessions.map(s => (
              <div key={s.id}
                className={`rounded-lg px-3 py-2 text-sm cursor-pointer transition-colors ${s.id === activeSession ? 'bg-celestial-primary/20 text-celestial-accent' : 'text-celestial-textDim hover:bg-celestial-surfaceLight hover:text-celestial-text'}`}
                onClick={() => setActiveSession(s.id)}>
                <div className="flex items-center justify-between">
                  {editingId === s.id ? (
                    <input autoFocus value={editName} onChange={e => setEditName(e.target.value)}
                      onBlur={() => handleRenameSession(s.id)}
                      onKeyDown={e => e.key === 'Enter' && handleRenameSession(s.id)}
                      className="bg-celestial-bg border border-celestial-border rounded px-1 py-0.5 text-xs text-celestial-text w-full mr-2"
                      onClick={e => e.stopPropagation()} />
                  ) : (
                    <span className="truncate flex-1">{s.name}</span>
                  )}
                  <div className="flex gap-0.5 flex-shrink-0 ml-1">
                    <button onClick={e => { e.stopPropagation(); setEditingId(s.id); setEditName(s.name) }} className="p-0.5 rounded hover:bg-celestial-surfaceLight text-celestial-textDim hover:text-celestial-text">
                      <Edit2 className="h-3 w-3" />
                    </button>
                    <button onClick={e => { e.stopPropagation(); handleDeleteSession(s.id) }} className="p-0.5 rounded hover:bg-celestial-surfaceLight text-celestial-textDim hover:text-celestial-alert">
                      <Trash2 className="h-3 w-3" />
                    </button>
                  </div>
                </div>
                <div className="text-xs text-celestial-textDim mt-0.5">{s.messageCount} 条消息</div>
              </div>
            ))}
            {sessions.length === 0 && (
              <p className="text-xs text-celestial-textDim text-center py-4">暂无对话</p>
            )}
          </div>
        </Card>
      </div>

      {/* main chat */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* header */}
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="sm" onClick={() => setSidebarOpen(!sidebarOpen)}>
              {sidebarOpen ? <ChevronLeft className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
            </Button>
            <h1 className="text-xl font-bold text-celestial-text">AI 安全对话</h1>
            {activeSession && <Badge variant="status">{sessions.find(s => s.id === activeSession)?.name || '对话中'}</Badge>}
          </div>
          <Button variant="ghost" size="sm" onClick={handleNewChat}><Plus className="mr-1 h-3 w-3" />新对话</Button>
        </div>

        {/* api error */}
        {apiError && (
          <div className="mb-3 rounded-lg border border-celestial-alert/30 bg-celestial-alert/5 px-3 py-2 text-sm text-celestial-alert">
            {apiError}
          </div>
        )}

        {/* context indicator */}
        {contextData && (
          <div className="flex items-center gap-2 mb-3 rounded-lg border border-celestial-primary/30 bg-celestial-primary/5 px-3 py-2 text-sm">
            <Sparkles className="h-4 w-4 text-celestial-accent" />
            <span className="text-celestial-textDim">当前上下文:</span>
            <span className="text-celestial-text font-medium">{contextData.file}</span>
            <span className="text-celestial-textDim">—</span>
            <span className="text-celestial-accent">{contextData.vuln}</span>
            <button onClick={() => setContextData(null)} className="ml-auto text-celestial-textDim hover:text-celestial-text">
              <X className="h-4 w-4" />
            </button>
          </div>
        )}

        {/* quick actions */}
        <div className="flex gap-2 mb-4 flex-wrap">
          {QUICK_ACTIONS.map(action => (
            <button key={action.label} onClick={() => handleQuickAction(action)}
              className="rounded-full border border-celestial-border px-3 py-1.5 text-xs text-celestial-textDim hover:border-celestial-primary hover:text-celestial-accent transition-colors flex items-center gap-1.5">
              <action.icon className="h-3.5 w-3.5" />{action.label}
            </button>
          ))}
        </div>

        {/* messages */}
        <div className="flex-1 overflow-auto space-y-4 mb-4">
          {messages.length === 0 && !isStreaming && (
            <div className="flex items-center justify-center h-full text-celestial-textDim">
              <div className="text-center">
                <MessageSquare className="h-12 w-12 mx-auto mb-3 text-celestial-primary" />
                <p className="text-celestial-text mb-1">向 AI 安全专家提问</p>
                <p className="text-xs">支持代码分析、漏洞解释、修复建议等</p>
              </div>
            </div>
          )}
          {messages.map((msg) => (
            <div key={msg.id} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              <div className={`max-w-[80%] rounded-lg px-4 py-2.5 text-sm ${
                msg.role === 'user'
                  ? 'bg-celestial-primary/30 text-celestial-text'
                  : 'bg-celestial-surface border border-celestial-border text-celestial-textDim'
              }`}>
                {msg.role === 'assistant' ? renderContent(msg.content) : <span className="text-sm">{msg.content}</span>}
                <div className="text-xs text-celestial-textDim mt-1.5 text-right">{msg.timestamp}</div>
              </div>
            </div>
          ))}

          {/* streaming message */}
          {isStreaming && (
            <div className="flex justify-start">
              <div className="max-w-[80%] rounded-lg px-4 py-2.5 text-sm bg-celestial-surface border border-celestial-accent/30 text-celestial-textDim">
                {renderContent(streamText)}
                <span className="inline-block w-2 h-4 bg-celestial-accent animate-pulse ml-0.5 align-text-bottom" />
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>

        {/* input */}
        <div className="flex gap-2">
          <div className="flex-1 relative">
            <Input
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleSend() } }}
              placeholder="输入你的问题... (Enter 发送)"
              className="pr-20"
            />
            <div className="absolute right-2 top-1/2 -translate-y-1/2 flex gap-1">
              <button className="p-1.5 rounded text-celestial-textDim hover:text-celestial-text transition-colors">
                <Paperclip className="h-4 w-4" />
              </button>
            </div>
          </div>
          {isStreaming ? (
            <Button variant="danger" onClick={handleStop}><StopCircle className="h-4 w-4" /></Button>
          ) : (
            <Button onClick={handleSend} disabled={!input.trim()} size="md"><Send className="h-4 w-4" /></Button>
          )}
        </div>
      </div>
    </div>
  )
}
