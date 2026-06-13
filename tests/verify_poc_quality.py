"""POC 质量验证脚本

验证 POC 模块的核心功能：
1. POC Reviewer - 静态安全检查
2. POC Executor - 代码安全检查和执行
3. POC Memory - 经验记录和检索
4. POC Generator - 知识加载和 Prompt 构建
"""

import sys
import os
import json
import tempfile
from pathlib import Path

# 确保项目根目录在路径中
# 文件在 HOS-LS/tests/verify_poc_quality.py，项目根目录在 tests 的上一级
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.pentest.poc.poc_reviewer import PocReviewer, ReviewResult
from src.pentest.poc.poc_executor import PocExecutor, ExecutionResult
from src.pentest.poc.poc_memory import PocMemory
from src.pentest.poc.ai_poc_generator import AIPocGenerator, VulnContext


def test_poc_reviewer_static_analysis():
    """测试 POC Reviewer 静态安全检查"""
    print("\n=== POC Reviewer 静态安全检查 ===")
    
    reviewer = PocReviewer()
    
    # 测试 1: 安全代码应通过
    safe_code = """
import requests

def check_sqli(target):
    response = requests.get(target, timeout=10)
    if 'error' in response.text:
        return True
    return False
"""
    result = reviewer._static_safety_check(safe_code)
    assert len(result) == 0, f"安全代码不应有问题: {result}"
    print("[PASS] 安全代码通过检查")
    
    # 测试 2: 危险代码应被检测
    dangerous_code = """
import os
os.system('rm -rf /')
eval(user_input)
"""
    result = reviewer._static_safety_check(dangerous_code)
    assert len(result) > 0, "应检测到危险代码"
    print(f"[PASS] 检测到 {len(result)} 个安全问题")
    
    # 测试 3: 破坏性 SQL 应被检测
    sql_code = """
cursor.execute("DROP TABLE users")
cursor.execute("DELETE FROM sessions")
"""
    result = reviewer._static_safety_check(sql_code)
    assert len(result) >= 2, "应检测到破坏性 SQL"
    print(f"[PASS] 检测到 {len(result)} 个破坏性 SQL 操作")
    
    # 测试 4: 命令注入应被检测
    cmd_code = """
import subprocess
subprocess.run(cmd, shell=True)
"""
    result = reviewer._static_safety_check(cmd_code)
    assert len(result) > 0, "应检测到命令注入风险"
    print(f"[PASS] 检测到命令注入风险")
    
    print("[OK] POC Reviewer 静态安全检查通过")


def test_poc_executor_safety():
    """测试 POC Executor 安全检查"""
    print("\n=== POC Executor 安全检查 ===")
    
    executor = PocExecutor(timeout=5)
    
    # 测试 1: 安全代码应通过
    safe_code = """
import requests
def check(target):
    r = requests.get(target, timeout=5)
    return r.status_code == 200
"""
    issues = executor._check_safety(safe_code)
    assert len(issues) == 0, f"安全代码不应有问题: {issues}"
    print("[PASS] 安全代码通过执行器检查")
    
    # 测试 2: AST 检查应检测危险调用
    ast_dangerous = """
result = eval("1+1")
"""
    issues = executor._check_safety(ast_dangerous)
    assert any("eval" in i for i in issues), "应检测到 eval 调用"
    print("[PASS] AST 检查检测到 eval 调用")
    
    # 测试 3: 模式检查应检测破坏性命令
    pattern_dangerous = """
import os
os.system("rm -rf /")
"""
    issues = executor._check_safety(pattern_dangerous)
    assert any("rm -rf" in i for i in issues), "应检测到 rm -rf 命令"
    print("[PASS] 模式检查检测到破坏性命令")
    
    # 测试 4: 目标验证
    executor_with_hosts = PocExecutor(timeout=5, allowed_hosts=["example.com"])
    assert executor_with_hosts._validate_target("https://example.com/test")
    assert not executor_with_hosts._validate_target("https://evil.com/test")
    print("[PASS] 目标验证正常工作")
    
    print("[OK] POC Executor 安全检查通过")


def test_poc_memory():
    """测试 POC Memory 经验记录和检索"""
    print("\n=== POC Memory 经验记录 ===")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        memory = PocMemory(memory_dir=Path(tmpdir))
        
        # 测试 1: 记录成功经验
        exp1 = memory.record_experience(
            method_id="test_sqli_001",
            vuln_type="sql_injection",
            poc_code="import requests; print('test')",
            review_passed=True,
            execution_passed=True,
            is_exploitable=True,
            execution_time=1.5,
            tags=["boolean_blind", "mysql"],
        )
        assert exp1.success, "经验应标记为成功"
        print("[PASS] 成功经验记录正常")
        
        # 测试 2: 记录失败经验
        exp2 = memory.record_experience(
            method_id="test_sqli_002",
            vuln_type="sql_injection",
            poc_code="import requests; raise Exception('fail')",
            review_passed=True,
            execution_passed=False,
            is_exploitable=False,
            execution_time=2.0,
            error="Timeout",
            tags=["time_based"],
        )
        assert not exp2.success, "经验应标记为失败"
        print("[PASS] 失败经验记录正常")
        
        # 测试 3: 获取成功模式
        patterns = memory.get_successful_patterns("sql_injection")
        assert len(patterns) == 1, "应有 1 个成功模式"
        assert "boolean_blind" in patterns[0]["tags"]
        print(f"[PASS] 获取成功模式: {len(patterns)} 条")
        
        # 测试 4: 获取失败模式
        failures = memory.get_failure_patterns("sql_injection")
        assert len(failures) == 1, "应有 1 个失败模式"
        assert failures[0]["error"] == "Timeout"
        print(f"[PASS] 获取失败模式: {len(failures)} 条")
        
        # 测试 5: 统计数据
        stats = memory.get_stats("sql_injection")
        assert stats["total"] == 2
        assert stats["successful"] == 1
        assert stats["success_rate"] == 0.5
        print(f"[PASS] 统计数据正确: {stats}")
        
        # 测试 6: 清除数据
        cleared = memory.clear("sql_injection")
        assert cleared == 1
        stats_after = memory.get_stats("sql_injection")
        assert stats_after["total"] == 0
        print("[PASS] 清除数据正常")
    
    print("[OK] POC Memory 功能验证通过")


def test_poc_generator_knowledge():
    """测试 POC Generator 知识加载和 Prompt 构建"""
    print("\n=== POC Generator 知识加载 ===")
    
    generator = AIPocGenerator(ai_client=None)
    
    # 测试 1: 知识加载 - 需要确保 poc-knowledge 目录存在
    # 如果知识目录不存在，应该返回空字典而不是抛出异常
    import asyncio
    knowledge = asyncio.get_event_loop().run_until_complete(
        generator._load_knowledge("sql_injection")
    )
    # 知识可能加载成功或目录不存在，两种情况都应正常处理
    print(f"[PASS] 知识加载正常，加载了 {len(knowledge)} 个知识源")
    
    # 测试 2: 知识相关性判断
    assert generator._is_knowledge_relevant("sql_injection", "sql_injection")
    assert generator._is_knowledge_relevant("general", "sql_injection")
    assert not generator._is_knowledge_relevant("unrelated_topic", "sql_injection")
    print("[PASS] 知识相关性判断正确")
    
    # 测试 3: Prompt 构建
    safe_knowledge = {"principles/test.md": "# Test\nTest content"}
    system_prompt = generator._build_system_prompt(safe_knowledge)
    assert "POC" in system_prompt
    assert "JSON" in system_prompt
    print("[PASS] 系统 Prompt 构建正常")
    
    # 测试 4: 用户 Prompt 构建
    context = VulnContext(
        file_path="test.py",
        line_number=10,
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        vuln_type="sql_injection",
        project_root="/tmp/test",
    )
    user_prompt = generator._build_user_prompt(context, None, None)
    assert "sql_injection" in user_prompt
    assert "test.py" in user_prompt
    print("[PASS] 用户 Prompt 构建正常")
    
    # 测试 5: 方法 ID 生成
    method_id = generator._generate_method_id(context)
    assert "sql_injection" in method_id
    assert "test" in method_id
    assert "L10" in method_id
    print(f"[PASS] 方法 ID 生成: {method_id}")
    
    # 测试 6: 代码提取
    llm_response = """
好的，这是 POC 代码：

```python
import requests
import sys

def exploit(target):
    payload = "' OR 1=1 --"
    r = requests.get(f"{target}?id={payload}")
    return r.status_code == 200

if __name__ == "__main__":
    target = sys.argv[1]
    result = exploit(target)
    print(json.dumps({"is_exploitable": result}))
```

希望这对你有帮助！
"""
    code = generator._extract_poc_code(llm_response)
    assert code is not None
    assert "import requests" in code
    assert "exploit" in code
    print("[PASS] 代码提取正常")
    
    # 测试 7: 代码提取 - 通用代码块
    generic_response = """
```
import os
print("test")
```
"""
    code = generator._extract_poc_code(generic_response)
    assert code is not None
    assert "import os" in code
    print("[PASS] 通用代码块提取正常")
    
    # 测试 8: 无代码块时返回 None
    no_code_response = "这里没有代码"
    code = generator._extract_poc_code(no_code_response)
    assert code is None
    print("[PASS] 无代码时正确返回 None")
    
    print("[OK] POC Generator 知识加载和 Prompt 构建验证通过")


def test_poc_generation_without_llm():
    """测试 POC 生成器在 LLM 不可用时的行为"""
    print("\n=== POC Generator 无 LLM 行为 ===")
    
    generator = AIPocGenerator(ai_client=None)
    
    context = VulnContext(
        file_path="test.py",
        line_number=10,
        code_snippet="test code",
        vuln_type="sql_injection",
        project_root="/tmp",
    )
    
    import asyncio
    result = asyncio.get_event_loop().run_until_complete(
        generator.generate_poc(context)
    )
    
    assert not result.success, "LLM 不可用时应返回失败"
    assert result.error is not None
    assert "AI client" in result.error or "LLM" in result.error
    print(f"[PASS] LLM 不可用时正确返回失败: {result.error}")
    
    print("[OK] POC Generator 无 LLM 行为验证通过")


def main():
    """运行所有验证"""
    print("=" * 60)
    print("POC 质量验证")
    print("=" * 60)
    
    try:
        test_poc_reviewer_static_analysis()
        test_poc_executor_safety()
        test_poc_memory()
        test_poc_generator_knowledge()
        test_poc_generation_without_llm()
        
        print("\n" + "=" * 60)
        print("所有 POC 质量验证通过!")
        print("=" * 60)
        return 0
    except AssertionError as e:
        print(f"\n[FAIL] 验证失败: {e}")
        return 1
    except Exception as e:
        print(f"\n[ERROR] 验证异常: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
