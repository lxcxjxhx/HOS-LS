"""LLM 响应链路验证测试

验证 LiteLLMClient + SyncLLMWrapper + AISecurityAnalyzer 链路畅通。
"""

import sys
import os
import io

# Fix Windows console encoding
if sys.stdout.encoding != 'utf-8':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
if sys.stderr.encoding != 'utf-8':
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', errors='replace')

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)


def test_litellm_init():
    """测试 LiteLLMClient 初始化"""
    print("\n" + "=" * 60)
    print("测试 1: LiteLLMClient 初始化")
    print("=" * 60)

    from src.core.config import get_config
    from src.ai.providers.litellm_client import LiteLLMClient
    import asyncio

    config = get_config()
    print(f"Provider: {config.ai.provider}")
    print(f"Model: {config.ai.model}")
    print(f"Base URL: {config.ai.base_url or 'default'}")
    print(f"API Key: {'已配置' if config.ai.api_key else '未配置'}")

    client = LiteLLMClient(config=config)
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(client.initialize())
        print("✓ LiteLLMClient 初始化成功")
    finally:
        loop.close()

    return client


def test_sync_wrapper():
    """测试 SyncLLMWrapper 同步包装"""
    print("\n" + "=" * 60)
    print("测试 2: SyncLLMWrapper 同步包装")
    print("=" * 60)

    from src.core.config import get_config
    from src.ai.providers.litellm_client import LiteLLMClient
    from src.ai.agents.ai_security_agents import SyncLLMWrapper
    import asyncio

    config = get_config()
    client = LiteLLMClient(config=config)
    loop = asyncio.new_event_loop()
    loop.run_until_complete(client.initialize())
    loop.close()

    wrapper = SyncLLMWrapper(client)
    assert hasattr(wrapper, 'invoke'), "SyncLLMWrapper 应有 invoke 方法"
    assert hasattr(wrapper, 'chat'), "SyncLLMWrapper 应有 chat 方法"
    print("✓ SyncLLMWrapper 创建成功")

    return wrapper


def test_security_analyzer_with_llm():
    """测试 AISecurityAnalyzerWithLLM 初始化"""
    print("\n" + "=" * 60)
    print("测试 3: AISecurityAnalyzerWithLLM 初始化")
    print("=" * 60)

    from src.ai.agents.ai_security_agents import AISecurityAnalyzerWithLLM

    # Reset any existing instance
    AISecurityAnalyzerWithLLM.reset_instance()

    analyzer = AISecurityAnalyzerWithLLM.get_instance()
    analyzer.initialize()

    assert analyzer.is_initialized, "分析器应已初始化"
    assert analyzer._sync_llm is not None, "同步 LLM 应存在"
    assert analyzer._analyzer is not None, "安全分析器应存在"
    print("✓ AISecurityAnalyzerWithLLM 初始化成功")

    return analyzer


def test_llm_response():
    """测试实际 LLM 响应"""
    print("\n" + "=" * 60)
    print("测试 4: LLM 实际响应")
    print("=" * 60)

    from src.ai.agents.ai_security_agents import AISecurityAnalyzerWithLLM

    analyzer = AISecurityAnalyzerWithLLM.get_instance()

    if not analyzer.is_initialized:
        analyzer.initialize()

    # 发送简单测试请求
    test_code = """
def hello():
    return "world"
"""

    try:
        # 测试 SyncLLMWrapper 直接调用
        response = analyzer._sync_llm.invoke(
            prompt="请用一句话总结以下代码:\n" + test_code,
            system_prompt="你是一个代码分析助手。"
        )
        print(f"LLM 响应: {response[:100]}...")
        assert response and response != "{}", "LLM 应返回有效响应"
        print("✓ LLM 响应链路正常")
        return True
    except Exception as e:
        print(f"⚠ LLM 调用失败: {e}")
        print("  这可能是网络问题或 API Key 无效，非代码问题")
        return False


def main():
    print("\n[Test] LLM 响应链路验证测试")
    print("=" * 60)

    results = {}

    try:
        test_litellm_init()
        results['LiteLLMClient 初始化'] = True
    except Exception as e:
        print(f"❌ LiteLLMClient 初始化失败: {e}")
        results['LiteLLMClient 初始化'] = False

    try:
        test_sync_wrapper()
        results['SyncLLMWrapper 同步包装'] = True
    except Exception as e:
        print(f"❌ SyncLLMWrapper 创建失败: {e}")
        results['SyncLLMWrapper 同步包装'] = False

    try:
        test_security_analyzer_with_llm()
        results['AISecurityAnalyzerWithLLM 初始化'] = True
    except Exception as e:
        print(f"❌ AISecurityAnalyzerWithLLM 初始化失败: {e}")
        results['AISecurityAnalyzerWithLLM 初始化'] = False

    try:
        llm_ok = test_llm_response()
        results['LLM 实际响应'] = llm_ok
    except Exception as e:
        print(f"❌ LLM 响应测试失败: {e}")
        results['LLM 实际响应'] = False

    print("\n" + "=" * 60)
    print("测试结果汇总:")
    print("=" * 60)
    for name, ok in results.items():
        status = "✓ 通过" if ok else "❌ 失败"
        print(f"  {name}: {status}")

    all_ok = all(results.values())
    print(f"\n总计: {sum(results.values())}/{len(results)} 通过")

    return 0 if all_ok else 1


if __name__ == '__main__':
    sys.exit(main())
