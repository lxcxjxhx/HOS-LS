"""AI 安全分析 Agent 测试

验证 AI 动态编排系统替代硬编码规则的功能。
使用真实 LLM 客户端，无任何 Mock 数据。
"""

import sys
import os

# Add project root to path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

import asyncio
from src.nvd.nvd_query_adapter import NVDQueryAdapter


def test_nvd_cwe_match():
    """测试 NVD CWE 动态匹配（替代硬编码 CWE_PATTERNS）"""
    print("\n" + "=" * 60)
    print("测试 1: NVD CWE 动态匹配")
    print("=" * 60)

    nvd = NVDQueryAdapter()

    # 模拟 AI 提取关键词后的匹配
    keywords = ['sql', 'injection', 'cursor', 'execute']
    results = nvd.match_cwe(keywords, limit=3)

    print(f"关键词: {keywords}")
    print(f"匹配结果: {len(results)} 个")
    for r in results:
        print(f"  {r.get('cwe_id')}: {r.get('cwe_name')} (confidence={r.get('confidence'):.2f})")

    assert len(results) > 0, "NVD 应匹配到 CWE"
    print("✓ NVD CWE 匹配测试通过")


def test_nvd_dangerous_functions():
    """测试 NVD 危险函数动态加载（替代硬编码 SINK_PATTERNS）"""
    print("\n" + "=" * 60)
    print("测试 2: NVD 危险函数动态加载")
    print("=" * 60)

    nvd = NVDQueryAdapter()

    py_funcs = nvd.get_dangerous_functions("python")
    print(f"Python 危险函数类别: {len(py_funcs)} 种")
    for vuln_type, funcs in py_funcs.items():
        print(f"  {vuln_type}: {len(funcs)} 个函数")
        for f in funcs[:3]:
            print(f"    - {f}")

    assert len(py_funcs) > 0, "应加载危险函数"
    print("✓ 危险函数加载测试通过")


def test_nvd_sanitizer_patterns():
    """测试 NVD sanitizer 动态加载（替代硬编码 SANITIZER_PATTERNS）"""
    print("\n" + "=" * 60)
    print("测试 3: NVD sanitizer 动态加载")
    print("=" * 60)

    nvd = NVDQueryAdapter()

    sanitizers = nvd.get_sanitizer_patterns("python")
    print(f"Python sanitizer 模式: {len(sanitizers)} 个")
    for s in sanitizers:
        print(f"  {s['function']} ({s['type']})")

    assert len(sanitizers) > 0, "应加载 sanitizer 模式"
    print("✓ sanitizer 加载测试通过")


def test_taint_engine_nvd_dynamic():
    """测试污点引擎 NVD 动态模式加载"""
    print("\n" + "=" * 60)
    print("测试 4: 污点引擎 NVD 动态模式")
    print("=" * 60)

    from src.taint.engine import get_taint_engine

    engine = get_taint_engine()
    files = [
        'tests/fixtures/vulnerable_code/sql_injection.py',
        'tests/fixtures/vulnerable_code/command_injection.py',
        'tests/fixtures/vulnerable_code/xss.py',
    ]
    paths = engine.analyze(files)

    same = [p for p in paths if p.source.file_path == p.sink.file_path]
    cross = [p for p in paths if p.source.file_path != p.sink.file_path]

    print(f"总路径: {len(paths)} | 同文件: {len(same)} | 跨文件: {len(cross)}")

    by_file = {}
    for p in paths:
        by_file.setdefault(p.source.file_path, []).append(p)
    for k, v in by_file.items():
        print(f"  {os.path.basename(k)}: {len(v)} 条路径")

    assert len(paths) > 0, "应检出污点路径"
    assert len(cross) == 0, "独立文件间不应有跨文件路径"
    print("✓ 污点引擎动态模式测试通过")


def main():
    print("\n🧪 AI 动态编排系统测试套件（零硬编码）")
    print("=" * 60)

    try:
        test_nvd_cwe_match()
        test_nvd_dangerous_functions()
        test_nvd_sanitizer_patterns()
        test_taint_engine_nvd_dynamic()

        print("\n" + "=" * 60)
        print("✅ 所有测试通过!")
        print("=" * 60)
    except Exception as e:
        print(f"\n❌ 测试失败: {e}")
        import traceback
        traceback.print_exc()
        return 1

    return 0


if __name__ == '__main__':
    sys.exit(main())
