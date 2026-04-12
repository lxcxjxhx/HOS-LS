#!/usr/bin/env python3
"""
测试AI语义理解的准确性
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.intent_parser import IntentParser
from src.core.ai_plan_generator import AIPlanGenerator
from src.core.config import get_config

async def test_semantic_understanding():
    """测试AI语义理解的准确性"""
    print("测试AI语义理解的准确性...")
    
    # 初始化配置
    config = get_config()
    
    # 初始化意图解析器
    from src.ai.client import get_model_manager
    model_manager = await get_model_manager(config)
    ai_client = model_manager.get_default_client()
    intent_parser = IntentParser(ai_client)
    
    # 测试多步骤指令
    test_input = "解释一下漏扫实现方案 然后进行对该文件目录下的测试文件进行纯净AI模式的扫描 扫3个文件 就行"
    
    print(f"\n测试输入: {test_input}")
    
    # 解析意图
    intent = intent_parser.parse(test_input)
    print(f"\n识别到的意图类型: {intent.type}")
    print(f"是否包含多个意图: {intent.has_multiple_intents()}")
    
    if intent.has_multiple_intents():
        print(f"子意图数量: {len(intent.sub_intents)}")
        for i, sub_intent in enumerate(intent.sub_intents):
            print(f"子意图 {i+1} 类型: {sub_intent.type}")
            print(f"子意图 {i+1} 实体: {sub_intent.entities}")
    
    # 初始化计划生成器
    plan_generator = AIPlanGenerator(config)
    
    # 生成执行计划
    plan = await plan_generator.generate_plan(intent, test_input)
    
    # 打印执行计划
    print(f"\n生成的执行计划:")
    print(f"计划名称: {plan.name}")
    print(f"计划描述: {plan.description}")
    print(f"步骤数量: {len(plan.steps)}")
    
    for i, step in enumerate(plan.steps):
        print(f"\n步骤 {i+1}:")
        print(f"  名称: {step.name}")
        print(f"  描述: {step.description}")
        print(f"  模块: {step.module}")
        print(f"  参数: {step.parameters}")
        print(f"  依赖: {step.dependencies}")
        print(f"  估计时间: {step.estimated_time}秒")
    
    # 验证计划是否符合用户需求
    print(f"\n验证计划是否符合用户需求:")
    print(f"- 是否包含AI回答步骤: {any(step.module == 'ai_chat' for step in plan.steps)}")
    print(f"- 是否包含扫描步骤: {any(step.module == 'scan' for step in plan.steps)}")
    
    # 检查扫描步骤的参数
    scan_steps = [step for step in plan.steps if step.module == 'scan']
    if scan_steps:
        scan_step = scan_steps[0]
        print(f"- 扫描步骤文件数量: {scan_step.parameters.get('test_file_count', 'N/A')}")
        print(f"- 扫描步骤模式: {scan_step.parameters.get('mode', 'N/A')}")
        print(f"- 扫描步骤测试模式: {scan_step.parameters.get('test_mode', 'N/A')}")

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_semantic_understanding())
