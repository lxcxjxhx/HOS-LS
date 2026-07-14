#!/usr/bin/env python3
"""Script to fix F841 unused variable issues by commenting them out."""

import re
from pathlib import Path

# List of files and line numbers with F841 issues
F841_ISSUES = [
    ("src/ai/prompts.py", [42, 43, 48, 49, 50]),
    ("src/ai/providers/aliyun.py", [51, 149]),
    ("src/ai/providers/anthropic.py", [124]),
    ("src/ai/providers/deepseek.py", [185]),
    ("src/ai/providers/openai.py", [123]),
    ("src/ai/pure_ai/agent_selector.py", [121, 123]),
    ("src/ai/pure_ai/context_builder.py", [1341]),
    ("src/ai/pure_ai/file_prioritizer.py", [813, 823]),
    ("src/ai/pure_ai/multi_agent_pipeline.py", [503, 1163, 3202]),
    ("src/ai/pure_ai/rag/code_embedder.py", [704]),
    ("src/ai/pure_ai/rag/embedding_optimizer.py", [161]),
    ("src/ai/pure_ai/rag/faiss_vector_store.py", [107]),
    ("src/ai/pure_ai/rag/knowledge_base.py", [46]),
    ("src/ai/pure_ai/schema_validator.py", [1168, 1485, 2359, 2475]),
    ("src/ai/pure_ai_analyzer.py", [1099, 1189, 1474, 2209, 2646]),
    ("src/analyzers/config_finding_enhancer.py", [268, 405]),
    ("src/analyzers/context_analyzer.py", [85]),
    ("src/analyzers/finding_verifier.py", [295, 497, 779, 1169]),
    ("src/analyzers/input_tracer.py", [189, 190, 276, 365, 703, 1022]),
    ("src/analyzers/verification/dynamic_loader.py", [69]),
    ("src/analyzers/verification/java_to_python_converter.py", [239, 258]),
    ("src/analyzers/verification/poc_generator.py", [377, 664, 665, 697, 782, 812, 842, 872, 873]),
    ("src/analyzers/verification/python_test_executor.py", [54]),
    ("src/analyzers/verification/result_reviewer.py", [336, 337, 338]),
    ("src/analyzers/verification/transpiler_quality_verifier.py", [512, 663]),
    ("src/analyzers/verification/tree_sitter_adapter.py", [149]),
    ("src/analyzers/verification/universal_parser.py", [241, 268, 285, 302, 319, 336]),
    ("src/analyzers/verification/virtual_runtime.py", [758]),
    ("src/analyzers/verification_adapter.py", [196]),
    ("src/assessment/vulnerability_assessor.py", [344, 461, 715]),
    ("src/chat/main.py", [254, 255]),
    ("src/chat/terminal_ui.py", [102]),
    ("src/cli/main.py", [1298, 1380, 1413, 1442, 1517, 1731, 2077, 2141]),
    ("src/cli/panel/__init__.py", [34]),
    ("src/core/chat/main.py", [254, 255]),
    ("src/core/chat/terminal_ui.py", [102]),
    ("src/core/file_filter.py", [121]),
    ("src/core/langgraph_flow.py", [43, 170, 210, 822, 894, 1173]),
    ("src/core/multi_stage_scanner.py", [344, 648, 678, 708]),
    ("src/core/scanner.py", [1305, 1306, 1569, 2153, 4103]),
    ("src/integration/nvd_importer.py", [95]),
    ("src/integration/poc_integration.py", [34, 86, 135]),
    ("src/integration/remote.py", [105]),
    ("src/nvd/etl/cwe_etl.py", [163, 178]),
    ("src/nvd/etl/exploit_etl.py", [120]),
    ("src/nvd/etl/kev_etl.py", [114]),
    ("src/nvd/etl/nvd_etl.py", [82]),
    ("src/plugins/builtin/ast_analysis_plugin.py", [77]),
    ("src/plugins/builtin/regex_rules_plugin.py", [74]),
    ("src/plugins/builtin/semantic_analysis_plugin.py", [68]),
    ("src/plugins/manager.py", [57]),
    ("src/reporting/generator.py", [137, 985, 989, 1085, 1110, 1171, 1177, 1205, 1209, 1218, 1224]),
    ("src/rules/builtin/ai_security/logging_security.py", [322]),
    ("src/rules/builtin/ai_security/output_control.py", [402, 553]),
    ("src/rules/builtin/injection/sql_injection.py", [233]),
    ("src/utils/priority/priority_engine.py", [1475, 1495]),
    ("src/utils/priority_engine.py", [1475, 1495]),
    ("src/utils/time_estimator.py", [233]),
    ("src/vulnerability/osv_client.py", [96, 97, 98]),
]


def fix_file(file_path: str, line_numbers: list):
    """Comment out unused variables in a file."""
    path = Path(file_path)
    if not path.exists():
        print(f"File not found: {file_path}")
        return

    lines = path.read_text(encoding="utf-8").splitlines()

    # Sort line numbers in descending order to avoid offset issues
    for line_num in sorted(line_numbers, reverse=True):
        idx = line_num - 1
        if idx < len(lines):
            line = lines[idx]
            # Comment out the line if it's an assignment
            if "=" in line and not line.strip().startswith("#"):
                indent = len(line) - len(line.lstrip())
                lines[idx] = " " * indent + "# " + line.lstrip()

    path.write_text("\n".join(lines), encoding="utf-8")
    print(f"Fixed {len(line_numbers)} issues in {file_path}")


if __name__ == "__main__":
    for file_path, line_numbers in F841_ISSUES:
        fix_file(file_path, line_numbers)
    print("Done!")
