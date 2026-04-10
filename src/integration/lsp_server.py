"""LSP服务器模块

实现语言服务器协议，为IDE提供实时漏洞检测功能。
"""

import json
import sys
import traceback
from typing import Dict, Any, Optional, List, Tuple

from pygls.server import LanguageServer
from pygls.lsp.types import (
    TextDocumentSyncKind,
    TextDocumentPositionParams,
    CompletionParams,
    CompletionList,
    CompletionItem,
    CompletionItemKind,
    Diagnostic,
    DiagnosticSeverity,
    Position,
    Range,
    WorkspaceFolder,
    DidChangeTextDocumentParams,
    DidOpenTextDocumentParams,
    DidSaveTextDocumentParams,
)

from src.ai.pure_ai.multi_agent_pipeline import MultiAgentPipeline
from src.ai.client import get_model_manager
from src.core.config import Config


class HOSLSLanguageServer(LanguageServer):
    """HOS-LS语言服务器"""
    
    def __init__(self):
        super().__init__()
        self.config = Config()
        self.ai_client = get_model_manager(self.config)
        self.agent_pipeline = MultiAgentPipeline(self.ai_client, self.config)
        self.documents = {}  # 存储文档内容
        
    def initialize(self, params):
        """初始化语言服务器"""
        self.show_message("HOS-LS语言服务器已启动")
        return {
            "capabilities": {
                "textDocumentSync": {
                    "openClose": True,
                    "change": TextDocumentSyncKind.Incremental,
                    "save": True
                },
                "completionProvider": {
                    "resolveProvider": True
                },
                "diagnosticProvider": {
                    "documentSelector": [
                        {"language": "python"},
                        {"language": "javascript"},
                        {"language": "typescript"},
                        {"language": "java"},
                        {"language": "c"},
                        {"language": "cpp"}
                    ],
                    "interFileDependencies": True,
                    "workspaceDiagnostics": True
                }
            }
        }

    async def analyze_document(self, document_uri: str, text: str):
        """分析文档并生成诊断信息"""
        try:
            # 分析文件
            result = await self.agent_pipeline.run_pipeline(document_uri, fast_mode=True)
            
            # 生成诊断信息
            diagnostics = []
            if 'final_report' in result:
                findings = result['final_report'].get('final_findings', [])
                for finding in findings:
                    # 提取位置信息
                    location = finding.get('location', 'unknown')
                    line = 0
                    try:
                        # 尝试从位置信息中提取行号
                        if ':' in location:
                            line_str = location.split(':')[-1]
                            line = int(line_str) - 1  # LSP使用0-based行号
                    except:
                        pass
                    
                    # 确定严重程度
                    severity_map = {
                        'critical': DiagnosticSeverity.Error,
                        'high': DiagnosticSeverity.Error,
                        'medium': DiagnosticSeverity.Warning,
                        'low': DiagnosticSeverity.Information,
                        'info': DiagnosticSeverity.Hint
                    }
                    severity = severity_map.get(finding.get('severity', 'info'), DiagnosticSeverity.Information)
                    
                    # 创建诊断
                    diagnostic = Diagnostic(
                        range=Range(
                            start=Position(line=line, character=0),
                            end=Position(line=line + 1, character=0)
                        ),
                        message=f"{finding.get('vulnerability', 'Unknown')}: {finding.get('message', '')}",
                        severity=severity,
                        source="HOS-LS"
                    )
                    diagnostics.append(diagnostic)
            
            # 发送诊断信息
            self.publish_diagnostics(document_uri, diagnostics)
            
        except Exception as e:
            self.show_message(f"分析文档时出错: {e}")
            traceback.print_exc()

    async def on_text_document_did_open(self, params: DidOpenTextDocumentParams):
        """文档打开时的处理"""
        document_uri = params.text_document.uri
        text = params.text_document.text
        self.documents[document_uri] = text
        await self.analyze_document(document_uri, text)

    async def on_text_document_did_change(self, params: DidChangeTextDocumentParams):
        """文档变更时的处理"""
        document_uri = params.text_document.uri
        # 更新文档内容
        if document_uri in self.documents:
            for change in params.content_changes:
                if change.range:
                    # 处理增量变更
                    start_line = change.range.start.line
                    end_line = change.range.end.line
                    lines = self.documents[document_uri].split('\n')
                    new_lines = lines[:start_line] + [change.text] + lines[end_line + 1:]
                    self.documents[document_uri] = '\n'.join(new_lines)
                else:
                    # 处理全量变更
                    self.documents[document_uri] = change.text
            
            # 分析文档
            await self.analyze_document(document_uri, self.documents[document_uri])

    async def on_text_document_did_save(self, params: DidSaveTextDocumentParams):
        """文档保存时的处理"""
        document_uri = params.text_document.uri
        if document_uri in self.documents:
            await self.analyze_document(document_uri, self.documents[document_uri])

    async def on_completion(self, params: CompletionParams):
        """提供代码补全"""
        # 简单的补全示例
        items = [
            CompletionItem(
                label="secure_input",
                kind=CompletionItemKind.Function,
                detail="安全的输入处理函数",
                documentation="用于处理用户输入，防止注入攻击"
            ),
            CompletionItem(
                label="sanitize_output",
                kind=CompletionItemKind.Function,
                detail="安全的输出处理函数",
                documentation="用于处理输出，防止XSS攻击"
            ),
            CompletionItem(
                label="secure_hash",
                kind=CompletionItemKind.Function,
                detail="安全的哈希函数",
                documentation="用于安全地哈希密码等敏感数据"
            )
        ]
        return CompletionList(is_incomplete=False, items=items)


def main():
    """主函数"""
    server = HOSLSLanguageServer()
    server.start_io()


if __name__ == "__main__":
    main()
