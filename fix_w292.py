#!/usr/bin/env python3
"""Fix W292 errors - missing newlines at end of files"""

import os

files = [
    "src/ai/providers/aliyun.py",
    "src/ai/providers/anthropic.py",
    "src/ai/providers/deepseek.py",
    "src/ai/providers/openai.py",
    "src/ai/pure_ai/agent_selector.py",
    "src/ai/pure_ai/context_builder.py",
    "src/ai/pure_ai/file_prioritizer.py",
    "src/ai/pure_ai/multi_agent_pipeline.py",
    "src/ai/pure_ai/rag/code_embedder.py",
    "src/ai/pure_ai/rag/embedding_optimizer.py",
    "src/ai/pure_ai/rag/faiss_vector_store.py",
    "src/ai/pure_ai/rag/knowledge_base.py",
    "src/ai/pure_ai/schema_validator.py",
    "src/ai/pure_ai_analyzer.py",
    "src/analyzers/config_finding_enhancer.py",
    "src/analyzers/context_analyzer.py",
    "src/analyzers/finding_verifier.py",
    "src/analyzers/input_tracer.py",
    "src/analyzers/verification/dynamic_loader.py",
    "src/analyzers/verification/java_to_python_converter.py",
    "src/analyzers/verification/poc_generator.py",
    "src/analyzers/verification/python_test_executor.py",
    "src/analyzers/verification/result_reviewer.py",
    "src/analyzers/verification/transpiler_quality_verifier.py",
    "src/analyzers/verification/tree_sitter_adapter.py",
    "src/analyzers/verification/universal_parser.py",
    "src/analyzers/verification/virtual_runtime.py",
    "src/analyzers/verification_adapter.py",
    "src/assessment/vulnerability_assessor.py",
    "src/chat/main.py",
    "src/chat/terminal_ui.py",
    "src/cli/main.py",
    "src/cli/panel/__init__.py",
    "src/core/chat/main.py",
    "src/core/chat/terminal_ui.py",
    "src/core/file_filter.py",
    "src/core/langgraph_flow.py",
    "src/core/multi_stage_scanner.py",
    "src/core/scanner.py",
    "src/integration/nvd_importer.py",
    "src/integration/poc_integration.py",
    "src/integration/remote.py",
    "src/nvd/etl/cwe_etl.py",
    "src/nvd/etl/exploit_etl.py",
    "src/nvd/etl/kev_etl.py",
    "src/nvd/etl/nvd_etl.py",
    "src/plugins/builtin/ast_analysis_plugin.py",
    "src/plugins/builtin/regex_rules_plugin.py",
    "src/plugins/builtin/semantic_analysis_plugin.py",
    "src/plugins/manager.py",
    "src/reporting/generator.py",
    "src/rules/builtin/ai_security/logging_security.py",
    "src/rules/builtin/ai_security/output_control.py",
    "src/rules/builtin/injection/sql_injection.py",
    "src/utils/priority/priority_engine.py",
    "src/utils/priority_engine.py",
    "src/utils/time_estimator.py",
    "src/vulnerability/osv_client.py",
]

for file_path in files:
    if not os.path.exists(file_path):
        print(f"File not found: {file_path}")
        continue

    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Add newline if missing
    if content and not content.endswith("\n"):
        with open(file_path, "a", encoding="utf-8") as f:
            f.write("\n")
        print(f"Fixed: {file_path}")
    else:
        print(f"OK: {file_path}")

print("Done!")
