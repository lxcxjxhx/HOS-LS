#!/usr/bin/env python3
import os
import sys
import json
from datetime import datetime

# 项目路径
AGENTFLOW_PROJECT_PATH = "c:\\1AAA_PROJECT\\HOS\\HOS-LS\\real-project\\agentflow-main"
TEST_SCRIPT_PATH = "c:\\1AAA_PROJECT\\HOS\\HOS-LS\\HOS-LS\\tests\\AAA-ai-test.py"
OUTPUT_DIR = "c:\\1AAA_PROJECT\\HOS\\HOS-LS\\HOS-LS\\tests\\test-ai"

# 确保输出目录存在
def ensure_output_dir():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR, exist_ok=True)
    print(f"Output directory ensured: {OUTPUT_DIR}")

# 检查 agentflow 项目是否存在
def check_agentflow_project():
    if not os.path.exists(AGENTFLOW_PROJECT_PATH):
        print(f"Error: agentflow project not found at {AGENTFLOW_PROJECT_PATH}")
        sys.exit(1)
    print(f"Agentflow project found: {AGENTFLOW_PROJECT_PATH}")

# 分析 AI 功能模块
def analyze_ai_modules():
    print("\nAnalyzing AI functionality modules...")
    
    # 检查 AI 相关文件
    ai_files = [
        "packages/core/src/ai/index.ts",
        "packages/core/src/ai/calculator.ts",
        "packages/core/src/ai/models.ts",
        "packages/core/src/actions/gen-text.ts",
        "packages/core/src/actions/gen-object.ts"
    ]
    
    found_files = []
    missing_files = []
    
    for file_path in ai_files:
        full_path = os.path.join(AGENTFLOW_PROJECT_PATH, file_path)
        if os.path.exists(full_path):
            found_files.append(file_path)
        else:
            missing_files.append(file_path)
    
    print(f"Found AI files: {len(found_files)}")
    for file in found_files:
        print(f"  - {file}")
    
    if missing_files:
        print(f"Missing AI files: {len(missing_files)}")
        for file in missing_files:
            print(f"  - {file}")
    
    # 保存分析结果
    analysis_result = {
        "timestamp": datetime.now().isoformat(),
        "found_files": found_files,
        "missing_files": missing_files,
        "ai_modules": [
            "CostCalculator",
            "gen-text action",
            "gen-object action",
            "AI models configuration"
        ]
    }
    
    result_path = os.path.join(OUTPUT_DIR, "ai-analysis.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(analysis_result, f, indent=2)
    print(f"Saved AI analysis to: {result_path}")

# 测试 CostCalculator 功能（通过分析源代码）
def test_cost_calculator():
    print("\nTesting CostCalculator functionality...")
    
    # 读取 calculator.ts 文件内容
    calculator_path = os.path.join(AGENTFLOW_PROJECT_PATH, "packages/core/src/ai/calculator.ts")
    if not os.path.exists(calculator_path):
        print(f"Error: calculator.ts not found at {calculator_path}")
        return
    
    with open(calculator_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # 分析 CostCalculator 类
    has_add_usage = "addUsage" in content
    has_input_cost = "inputCost" in content
    has_output_cost = "outputCost" in content
    has_total_cost = "totalCost" in content
    
    # 测试结果
    test_results = {
        "timestamp": datetime.now().isoformat(),
        "tests": [
            {"name": "addUsage method", "result": "PASS" if has_add_usage else "FAIL"},
            {"name": "inputCost property", "result": "PASS" if has_input_cost else "FAIL"},
            {"name": "outputCost property", "result": "PASS" if has_output_cost else "FAIL"},
            {"name": "totalCost property", "result": "PASS" if has_total_cost else "FAIL"}
        ],
        "source_code_preview": content[:500] + "..." if len(content) > 500 else content
    }
    
    # 保存测试结果
    result_path = os.path.join(OUTPUT_DIR, "cost-calculator-test.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(test_results, f, indent=2)
    print(f"Saved CostCalculator test results to: {result_path}")

# 测试 AI 模型配置
def test_ai_models():
    print("\nTesting AI models configuration...")
    
    # 读取 models.ts 文件内容
    models_path = os.path.join(AGENTFLOW_PROJECT_PATH, "packages/core/src/ai/models.ts")
    if not os.path.exists(models_path):
        print(f"Error: models.ts not found at {models_path}")
        return
    
    with open(models_path, "r", encoding="utf-8") as f:
        content = f.read()
    
    # 分析模型配置
    providers = ["openai", "anthropic", "google"]
    found_providers = []
    
    for provider in providers:
        if provider in content:
            found_providers.append(provider)
    
    # 测试结果
    test_results = {
        "timestamp": datetime.now().isoformat(),
        "found_providers": found_providers,
        "total_providers": len(found_providers),
        "source_code_preview": content[:500] + "..." if len(content) > 500 else content
    }
    
    # 保存测试结果
    result_path = os.path.join(OUTPUT_DIR, "ai-models-test.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(test_results, f, indent=2)
    print(f"Saved AI models test results to: {result_path}")

# 测试 gen-text 和 gen-object 动作
def test_ai_actions():
    print("\nTesting AI actions...")
    
    # 检查动作文件
    actions = {
        "gen-text": "packages/core/src/actions/gen-text.ts",
        "gen-object": "packages/core/src/actions/gen-object.ts"
    }
    
    action_results = {}
    
    for action_name, action_path in actions.items():
        full_path = os.path.join(AGENTFLOW_PROJECT_PATH, action_path)
        if os.path.exists(full_path):
            with open(full_path, "r", encoding="utf-8") as f:
                content = f.read()
            
            # 分析动作内容
            has_model_param = "model" in content
            has_role_param = "role" in content
            has_execute_method = "execute" in content
            
            action_results[action_name] = {
                "exists": True,
                "tests": [
                    {"name": "model parameter", "result": "PASS" if has_model_param else "FAIL"},
                    {"name": "role parameter", "result": "PASS" if has_role_param else "FAIL"},
                    {"name": "execute method", "result": "PASS" if has_execute_method else "FAIL"}
                ],
                "source_code_preview": content[:300] + "..." if len(content) > 300 else content
            }
        else:
            action_results[action_name] = {
                "exists": False,
                "tests": []
            }
    
    # 保存测试结果
    test_results = {
        "timestamp": datetime.now().isoformat(),
        "actions": action_results
    }
    
    result_path = os.path.join(OUTPUT_DIR, "ai-actions-test.json")
    with open(result_path, "w", encoding="utf-8") as f:
        json.dump(test_results, f, indent=2)
    print(f"Saved AI actions test results to: {result_path}")

# 主测试函数
def main():
    print("=== Agentflow AI Functionality Test ===")
    print(f"Test script: {TEST_SCRIPT_PATH}")
    print(f"Agentflow project: {AGENTFLOW_PROJECT_PATH}")
    print(f"Output directory: {OUTPUT_DIR}")
    
    # 1. 确保输出目录存在
    ensure_output_dir()
    
    # 2. 检查 agentflow 项目
    check_agentflow_project()
    
    # 3. 分析 AI 功能模块
    analyze_ai_modules()
    
    # 4. 测试 CostCalculator 功能
    test_cost_calculator()
    
    # 5. 测试 AI 模型配置
    test_ai_models()
    
    # 6. 测试 AI 动作
    test_ai_actions()
    
    print("\n=== Test Completed ===")
    print(f"All test results have been saved to: {OUTPUT_DIR}")
    
    # 生成测试摘要
    generate_test_summary()

# 生成测试摘要
def generate_test_summary():
    print("\n=== Test Summary ===")
    
    # 读取所有测试结果
    summary = {
        "timestamp": datetime.now().isoformat(),
        "tests": {}
    }
    
    test_files = [
        "ai-analysis.json",
        "cost-calculator-test.json",
        "ai-models-test.json",
        "ai-actions-test.json"
    ]
    
    for test_file in test_files:
        file_path = os.path.join(OUTPUT_DIR, test_file)
        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            summary["tests"][test_file] = data
    
    # 保存摘要
    summary_path = os.path.join(OUTPUT_DIR, "test-summary.json")
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    
    print(f"Generated test summary: {summary_path}")
    print("Test summary includes:")
    print("  - AI module analysis")
    print("  - CostCalculator functionality")
    print("  - AI models configuration")
    print("  - AI actions (gen-text, gen-object)")

if __name__ == "__main__":
    main()
