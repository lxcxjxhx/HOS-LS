"""完整测试验证套件 - 修复后版本"""
import sys
import os

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.nvd.nvd_query_adapter import NVDQueryAdapter


def test_cwe_match():
    """测试 CWE 动态匹配"""
    print("\n" + "=" * 60)
    print("测试 1: CWE 动态匹配")
    print("=" * 60)

    nvd = NVDQueryAdapter()
    nvd._cwe_index = None  # Force rebuild
    
    # Test 1: SQL injection keywords
    results = nvd.match_cwe(['sql', 'injection', 'cursor', 'execute'], limit=5)
    print(f"关键词: ['sql', 'injection', 'cursor', 'execute']")
    print(f"匹配结果: {len(results)} 个")
    for r in results:
        print(f"  {r['cwe_id']}: {r['cwe_name']} (confidence={r['confidence']:.2f}, score={r.get('score', 0)})")
    
    assert len(results) > 0, "CWE 应匹配到结果"
    cwe_ids = [r['cwe_id'] for r in results]
    assert 'CWE-89' in cwe_ids, f"应匹配到 CWE-89 (SQL Injection), got: {cwe_ids}"
    print("✓ CWE-89 SQL Injection 匹配通过")
    
    # Test 2: Command injection keywords
    results2 = nvd.match_cwe(['command', 'injection', 'os'], limit=5)
    print(f"\n关键词: ['command', 'injection', 'os']")
    print(f"匹配结果: {len(results2)} 个")
    for r in results2:
        print(f"  {r['cwe_id']}: {r['cwe_name']} (score={r.get('score', 0)})")
    
    assert len(results2) > 0, "CWE 应匹配到结果"
    cwe_ids2 = [r['cwe_id'] for r in results2]
    assert 'CWE-78' in cwe_ids2, f"应匹配到 CWE-78 (OS Command Injection), got: {cwe_ids2}"
    print("✓ CWE-78 命令注入匹配通过")


def test_dangerous_functions():
    """测试危险函数提取"""
    print("\n" + "=" * 60)
    print("测试 2: 危险函数动态提取")
    print("=" * 60)

    nvd = NVDQueryAdapter()
    
    for lang in ['python', 'java', 'javascript']:
        funcs = nvd.get_dangerous_functions(lang)
        print(f"\n{lang}: {len(funcs)} 类危险函数")
        for vuln_type, f_list in funcs.items():
            print(f"  {vuln_type}: {len(f_list)} 个函数")
            for f in f_list[:3]:
                print(f"    - {f}")
    
    py_funcs = nvd.get_dangerous_functions('python')
    assert len(py_funcs) > 0, "Python 危险函数应非空"
    print("✓ 危险函数提取测试通过")


def test_sanitizer_patterns():
    """测试 sanitizer 模式提取"""
    print("\n" + "=" * 60)
    print("测试 3: Sanitizer 模式动态提取")
    print("=" * 60)

    nvd = NVDQueryAdapter()
    
    sanitizers = nvd.get_sanitizer_patterns('python')
    print(f"Python sanitizer: {len(sanitizers)} 个")
    for s in sanitizers[:10]:
        print(f"  {s['function']} ({s['type']})")
    
    assert len(sanitizers) > 0, "Sanitizer 模式应非空"
    print("✓ Sanitizer 提取测试通过")


def test_taint_engine():
    """测试污点引擎"""
    print("\n" + "=" * 60)
    print("测试 4: 污点引擎 NVD 动态模式")
    print("=" * 60)

    from src.taint.engine import get_taint_engine, TaintEngine
    # Reset singleton to pick up new patterns
    TaintEngine._instance = None
    
    engine = get_taint_engine()
    files = [
        os.path.join(project_root, 'tests/fixtures/vulnerable_code/sql_injection.py'),
        os.path.join(project_root, 'tests/fixtures/vulnerable_code/command_injection.py'),
        os.path.join(project_root, 'tests/fixtures/vulnerable_code/xss.py'),
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
    print("✓ 污点引擎测试通过")


def test_reachability():
    """测试可达性分析"""
    print("\n" + "=" * 60)
    print("测试 5: 可达性分析 NVD 动态模式")
    print("=" * 60)

    from src.assessment.reachability_analyzer import ReachabilityCalculator
    
    calc = ReachabilityCalculator()
    print(f"Sink 模式: {len(calc.SINK_PATTERNS)} 类")
    print(f"Sanitizer 模式: {len(calc.SANITIZER_PATTERNS)} 类")
    
    for key, vals in calc.SINK_PATTERNS.items():
        print(f"  {key}: {len(vals)} 个函数")
    
    assert len(calc.SINK_PATTERNS) > 0, "Sink 模式应非空"
    print("✓ 可达性分析测试通过")


def main():
    print("\n🧪 AI 动态编排系统完整测试套件")
    print("=" * 60)

    tests = [
        ("CWE 动态匹配", test_cwe_match),
        ("危险函数提取", test_dangerous_functions),
        ("Sanitizer 提取", test_sanitizer_patterns),
        ("污点引擎", test_taint_engine),
        ("可达性分析", test_reachability),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_fn in tests:
        try:
            test_fn()
            passed += 1
        except Exception as e:
            print(f"\n❌ {name} 失败: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"测试结果: {passed} 通过, {failed} 失败")
    print("=" * 60)
    
    return 0 if failed == 0 else 1


if __name__ == '__main__':
    sys.exit(main())
