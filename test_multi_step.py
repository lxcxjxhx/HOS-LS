#!/usr/bin/env python3
"""
测试多步骤指令的识别和执行
"""

import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.core.intent_parser import IntentParser
from src.core.ai_plan_generator import AIPlanGenerator
from src.core.config import get_config

async def test_multi_step_recognition():
    """测试多步骤指令的识别和执行"""
    print("测试多步骤指令的识别和执行...")
    
    # 初始化意图解析器
    intent_parser = IntentParser()
    
    # 测试多步骤指令
    test_input = "解释一下漏扫实现方案 然后进行对该文件目录下的测试文件进行纯净AI模式的扫描 扫一个文件就行"
    
    # 解析意图
    intent = intent_parser.parse(test_input)
    print(f"识别到的意图类型: {intent.type}")
    print(f"是否包含多个意图: {intent.has_multiple_intents()}")
    
    if intent.has_multiple_intents():
        print(f"子意图数量: {len(intent.sub_intents)}")
        for i, sub_intent in enumerate(intent.sub_intents):
            print(f"子意图 {i+1} 类型: {sub_intent.type}")
            print(f"子意图 {i+1} 实体: {sub_intent.entities}")
    
    # 初始化计划生成器
    plan_generator = AIPlanGenerator(get_config())
    
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

if __name__ == "__main__":
    import asyncio
    asyncio.run(test_multi_step_recognition())
