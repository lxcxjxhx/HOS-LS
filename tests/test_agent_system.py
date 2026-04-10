#!/usr/bin/env python
"""Agent 能力系统快速验证脚本

用于验证统一 Agent 架构是否正确安装和配置。
运行: python -m tests.test_agent_system
"""

import sys
import os
import asyncio

# 🔥 添加项目根目录到 Python 路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_registry_initialization():
    """测试1：Registry 初始化"""
    print("\n" + "="*60)
    print("📋 测试 1: Agent Registry 初始化")
    print("="*60)

    try:
        from src.core.agent_registry import get_agent_registry
        from src.core.agent_initialization import register_builtin_agents

        registry = get_agent_registry()
        register_builtin_agents()

        stats = registry.get_statistics()

        print(f"✅ Registry 初始化成功")
        print(f"   已注册 Agent 数量: {stats['total_agents']}")
        print(f"   分类统计: {stats['by_category']}")
        print(f"   可用 Flags 数量: {stats['total_flags']}")

        assert stats['total_agents'] > 0, "未注册任何 Agent"
        return True

    except Exception as e:
        print(f"❌ Registry 初始化失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_pipeline_building():
    """测试2：Pipeline 构建"""
    print("\n" + "="*60)
    print("🔧 测试 2: Pipeline 构建（从 flags）")
    print("="*60)

    try:
        from src.core.agent_registry import get_agent_registry

        registry = get_agent_registry()

        # 测试1：简单 flags
        pipeline1 = registry.build_pipeline_from_flags(["--scan", "--reason"])
        print(f"✅ 简单 Pipeline: {' → '.join(pipeline1)}")

        # 测试2：宏命令展开
        pipeline2 = registry.build_pipeline_from_flags(["--full-audit"])
        print(f"✅ 宏命令展开 (full-audit): {' → '.join(pipeline2)}")

        # 测试3：依赖自动补全
        pipeline3 = registry.build_pipeline_from_flags(["--poc"])
        print(f"✅ 依赖补全 (poc): {' → '.join(pipeline3)}")

        # 验证
        assert "scan" in pipeline3, "依赖补全失败：应该包含 scan"
        assert "reason" in pipeline3, "依赖补全失败：应该包含 reason"

        return True

    except Exception as e:
        print(f"❌ Pipeline 构建失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_base_agent_interface():
    """测试3：BaseAgent 接口"""
    print("\n" + "="*60)
    print("🤖 测试 3: BaseAgent 接口验证")
    print("="*60)

    try:
        from src.core.base_agent import BaseAgent, ExecutionContext, AgentResult, AgentStatus

        # 创建一个简单的同步测试 Agent（避免 asyncio 问题）
        class SyncTestAgent(BaseAgent):
            async def execute(self, context):
                return AgentResult(
                    agent_name="test",
                    status=AgentStatus.COMPLETED,
                    message="Test OK",
                    confidence=1.0
                )

        # 验证接口存在且正确
        agent = SyncTestAgent()
        context = ExecutionContext(target=".")

        assert hasattr(agent, 'execute'), "缺少 execute 方法"
        assert hasattr(agent, 'validate_input'), "缺少 validate_input 方法"
        assert hasattr(agent, 'capabilities'), "缺少 capabilities 属性"

        print(f"✅ Agent 接口验证成功")
        print(f"   Agent 名称: {agent.capabilities.name}")
        print(f"   描述: {agent.capabilities.description}")
        print(f"   状态: {agent.status.value}")

        return True

    except Exception as e:
        print(f"❌ BaseAgent 接口测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_unified_engine():
    """测试4：统一执行引擎"""
    print("\n" + "="*60)
    print("⚙️  测试 4: UnifiedExecutionEngine")
    print("="*60)

    try:
        from src.core.unified_execution_engine import UnifiedExecutionEngine, ExecutionRequest

        engine = UnifiedExecutionEngine()

        stats = engine.get_statistics()
        print(f"✅ 引擎初始化成功")
        print(f"   可用模式: {stats['available_modes']}")
        print(f"   Registry Agents: {stats['registry']['total_agents']}")

        # 测试构建请求
        request = ExecutionRequest(
            target=".",
            flags=["--scan", "--report"],
            mode="auto"
        )

        print(f"✅ 请求创建成功")
        print(f"   目标: {request.target}")
        print(f"   Flags: {request.flags}")
        print(f"   模式: {request.mode}")

        return True

    except Exception as e:
        print(f"❌ 统一引擎测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


def test_cli_integration():
    """测试5：CLI 集成"""
    print("\n" + "="*60)
    print("💻 测试 5: CLI 集成模块")
    print("="*60)

    try:
        from src.cli.agent_integration import (
            initialize_cli_agent_system,
            collect_behavior_flags_from_kwargs,
            LegacyFallbackExecutor
        )

        # 初始化
        success = initialize_cli_agent_system()
        print(f"✅ CLI Agent 系统初始化: {'成功' if success else '跳过'}")

        # 测试 flag 收集
        kwargs = {
            'scan': True,
            'reason': True,
            'report': False,
            'full_audit': True
        }

        flags = collect_behavior_flags_from_kwargs(**kwargs)
        print(f"✅ Flag 收集: {flags}")

        assert len(flags) >= 2, "应该收集到至少2个flag"

        return True

    except Exception as e:
        print(f"❌ CLI 集成测试失败: {e}")
        import traceback
        traceback.print_exc()
        return False


async def main():
    """主测试函数"""
    print("\n" + "🚀"*30)
    print("HOS-LS Agent 能力系统 - 快速验证")
    print("🚀"*30)

    results = []

    # 运行所有测试
    results.append(("Registry 初始化", test_registry_initialization()))
    results.append(("Pipeline 构建", test_pipeline_building()))
    results.append(("BaseAgent 接口", test_base_agent_interface()))
    results.append(("统一执行引擎", await test_unified_engine()))
    results.append(("CLI 集成", test_cli_integration()))

    # 输出总结
    print("\n" + "="*60)
    print("📊 测试结果总结")
    print("="*60)

    passed = sum(1 for _, r in results if r)
    total = len(results)

    for name, result in results:
        status = "✅ PASS" if result else "❌ FAIL"
        print(f"{status}: {name}")

    print("\n" + "-"*60)
    print(f"总计: {passed}/{total} 通过")

    if passed == total:
        print("\n🎉 所有测试通过！Agent 统一架构已就绪！")
        print("\n可用的 CLI 命令示例:")
        print("  hos-ls --scan --reason --report .")
        print("  hos-ls --full-audit ./my-project")
        print("  hos-ls --quick-scan --pure-ai")
        print("  hos-ls chat  # 进入交互模式")
        return 0
    else:
        print(f"\n⚠️  {total - passed} 个测试失败，请检查错误信息")
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)
