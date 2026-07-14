"""批量修复 F841 未使用局部变量"""
from pathlib import Path

# (file_path, line_number) 列表
fixes = [
    ("src/ai/prompts.py", 44),
    ("src/ai/prompts.py", 45),
    ("src/ai/prompts.py", 46),
    ("src/ai/providers/aliyun.py", 47),
    ("src/ai/providers/anthropic.py", 126),
    ("src/ai/pure_ai/rag/embedding_optimizer.py", 153),
    ("src/ai/pure_ai/rag/knowledge_base.py", 44),
    ("src/ai/pure_ai/schema_validator.py", 1482),
    ("src/ai/pure_ai_analyzer.py", 1092),
    ("src/ai/pure_ai_analyzer.py", 1098),
    ("src/ai/pure_ai_analyzer.py", 1182),
    ("src/analyzers/config_finding_enhancer.py", 320),
    ("src/analyzers/finding_verifier.py", 292),
    ("src/analyzers/verification/java_to_python_converter.py", 258),
    ("src/analyzers/verification/poc_generator.py", 843),
    ("src/analyzers/verification/python_test_executor.py", 54),
    ("src/core/langgraph_flow.py", 169),
    ("src/core/langgraph_flow.py", 209),
    ("src/core/langgraph_flow.py", 821),
    ("src/core/langgraph_flow.py", 893),
    ("src/core/langgraph_flow.py", 1172),
    ("src/core/multi_stage_scanner.py", 339),
    ("src/core/multi_stage_scanner.py", 644),
    ("src/core/multi_stage_scanner.py", 675),
    ("src/integration/poc_integration.py", 34),
    ("src/integration/poc_integration.py", 86),
    ("src/integration/poc_integration.py", 135),
    ("src/nvd/etl/cwe_etl.py", 163),
    ("src/nvd/etl/cwe_etl.py", 178),
    ("src/nvd/etl/exploit_etl.py", 120),
    ("src/nvd/etl/nvd_etl.py", 82),
    ("src/plugins/builtin/ast_analysis_plugin.py", 77),
    ("src/plugins/builtin/regex_rules_plugin.py", 74),
    ("src/plugins/builtin/semantic_analysis_plugin.py", 68),
    ("src/plugins/manager.py", 57),
    ("src/reporting/generator.py", 137),
    ("src/reporting/generator.py", 988),
    ("src/reporting/generator.py", 1082),
    ("src/reporting/generator.py", 1177),
    ("src/reporting/generator.py", 1205),
    ("src/reporting/generator.py", 1209),
    ("src/reporting/generator.py", 1218),
    ("src/reporting/generator.py", 1224),
    ("src/rules/builtin/ai_security/logging_security.py", 320),
    ("src/rules/builtin/ai_security/logging_security.py", 321),
    ("src/rules/builtin/ai_security/output_control.py", 400),
    ("src/rules/builtin/ai_security/output_control.py", 401),
    ("src/rules/builtin/ai_security/output_control.py", 551),
    ("src/rules/builtin/ai_security/output_control.py", 552),
]

# 按文件分组
from collections import defaultdict

file_fixes = defaultdict(list)
for file_path, line_num in fixes:
    file_fixes[file_path].append(line_num)

for file_path, line_nums in file_fixes.items():
    path = Path(file_path)
    if not path.exists():
        print(f"SKIP: {file_path} not found")
        continue

    lines = path.read_text(encoding="utf-8").splitlines()

    for line_num in sorted(line_nums, reverse=True):
        idx = line_num - 1
        if idx < len(lines):
            line = lines[idx]
            stripped = line.lstrip()
            indent = len(line) - len(stripped)
            # 注释掉赋值行
            if "=" in stripped and not stripped.startswith("#"):
                lines[idx] = " " * indent + "# " + stripped
                print(f"FIXED: {file_path}:{line_num}")
            else:
                print(f"SKIP (no assignment): {file_path}:{line_num}: {stripped[:50]}")

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"\nDone! Fixed {len(fixes)} F841 issues across {len(file_fixes)} files.")
