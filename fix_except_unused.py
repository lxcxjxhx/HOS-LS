"""Fix except Exception as e -> except Exception for unused e"""
from pathlib import Path

# (file, line) where 'except Exception as e:' appears
fixes = [
    ("src/core/langgraph_flow.py", 169),
    ("src/core/langgraph_flow.py", 209),
    ("src/core/langgraph_flow.py", 821),
    ("src/core/langgraph_flow.py", 893),
    ("src/core/langgraph_flow.py", 1172),
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
]

from collections import defaultdict

file_fixes = defaultdict(list)
for f, l in fixes:
    file_fixes[f].append(l)

for file_path, line_nums in file_fixes.items():
    path = Path(file_path)
    lines = path.read_text(encoding="utf-8").splitlines()
    for line_num in sorted(line_nums, reverse=True):
        idx = line_num - 1
        if idx < len(lines):
            line = lines[idx]
            # Replace 'except Exception as e:' with 'except Exception:'
            if "except Exception as e:" in line:
                lines[idx] = line.replace("except Exception as e:", "except Exception:")
                print(f"FIXED: {file_path}:{line_num}")
            elif "except ImportError as e:" in line:
                lines[idx] = line.replace("except ImportError as e:", "except ImportError:")
                print(f"FIXED: {file_path}:{line_num}")
            else:
                print(f"SKIP: {file_path}:{line_num}: {line.strip()[:60]}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

print(f"\nDone!")
