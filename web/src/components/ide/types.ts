export interface VulnItem {
  id: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  title: string
  line: number
  description: string
  rule_id?: string
  cwe_id?: string
}

export interface FixSuggestion {
  id: string
  title: string
  description: string
  code: string
  confidence: number
  vuln_id?: string
}

export interface IDEFileData {
  id: string
  filePath: string
  code: string
  language: string
  vulns: VulnItem[]
  fixes: FixSuggestion[]
}
