# DEPRECATED: This module is a shim that re-exports from src.core.chat.
# Please update imports to use src.core.chat directly.
# This directory will be removed in a future release.
from src.core.chat.conversational_agent import ConversationalSecurityAgent
from src.core.chat.terminal_ui import TerminalUI
from src.core.chat.pipeline_builder import PipelineBuilder

__all__ = [
    "ConversationalSecurityAgent",
    "TerminalUI",
    "PipelineBuilder",
]
