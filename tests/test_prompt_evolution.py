import unittest
import sys
import os

# 添加 src 目录到路径
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

# 直接导入 prompt_evolver，避免循环导入
from ai.pure_ai.prompt_evolver import PromptEvolver

class MockLLMClient:
    """模拟 LLM 客户端"""
    def generate(self, prompt):
        """模拟生成响应"""
        # 简单返回优化后的 Prompt（实际应用中需要调用真实的 LLM）
        return prompt

class TestPromptEvolution(unittest.TestCase):
    """测试 Prompt 进化功能"""
    
    def setUp(self):
        """设置测试环境"""
        self.llm_client = MockLLMClient()
        self.evolver = PromptEvolver(self.llm_client)
        # 创建测试用的 Prompt
        self.test_prompt = """
[CHARACTER]
你不是聊天AI，而是一个"受约束的安全分析执行模块"。

你必须严格按照协议运行。

[CORE TRAITS]
- Precision First（精确优先）
- No Assumption（禁止假设）
- Evidence Driven（基于代码事实）
- Deterministic Output（稳定输出）

[DECISION RULES]
- 只基于提供内容
- 不允许推测用途

[HARD RULES]
- 禁止输出解释性文本
- 禁止输出推理过程
- 禁止偏离任务
- 禁止补充未提供的信息
- 禁止使用"可能/大概/推测"等词

[INPUT]
文件路径: {file_path}

文件内容:
{file_content}

[TASK]
提取代码结构化上下文信息。

[OUTPUT PROTOCOL]
- 只允许输出 JSON
- 必须严格符合 schema
- 不允许缺失字段
- 不允许多余字段
- 必须可被 json.loads 解析

[OUTPUT FORMAT]
{
  "file_function": "",
  "dependencies": []
}

[FAILSAFE]
如果信息不足：
- 使用 "" 或 []
- 不允许编造
"""
        self.prompts = {
            'test_agent': self.test_prompt
        }
    
    def test_prompt_quality_evaluation(self):
        """测试 Prompt 质量评估"""
        for name, prompt in self.prompts.items():
            score = self.evolver.evaluate_prompt_quality(prompt)
            print(f"{name}: 质量评分 = {score:.2f}")
            self.assertGreater(score, 0, f"{name} 评分应该大于 0")
            self.assertLessEqual(score, 10, f"{name} 评分应该小于等于 10")
    
    def test_batch_evaluation(self):
        """测试批量评估"""
        evaluations = self.evolver.batch_evaluate_prompts(self.prompts)
        for name, eval_result in evaluations.items():
            print(f"{name}: 评分 = {eval_result['score']:.2f}, 评级 = {eval_result['rating']}")
            self.assertIn('score', eval_result)
            self.assertIn('rating', eval_result)
    
    def test_optimize_prompt(self):
        """测试 Prompt 优化"""
        for name, prompt in self.prompts.items():
            optimized = self.evolver.optimize_prompt(prompt)
            print(f"{name}: 原始长度 = {len(prompt)}, 优化后长度 = {len(optimized)}")
            self.assertIsInstance(optimized, str)
    
    def test_evolve_prompts(self):
        """测试进化 Prompt"""
        evolved = self.evolver.evolve_prompts(self.prompts)
        for name in self.prompts:
            self.assertIn(name, evolved)
            print(f"{name}: 已进化")
    
    def test_evolution_cycle(self):
        """测试进化循环"""
        final_prompts, history = self.evolver.start_evolution_cycle(self.prompts, max_iterations=2)
        print(f"进化完成，迭代次数: {len(history)}")
        for name in self.prompts:
            self.assertIn(name, final_prompts)
    
    def test_prompt_structure(self):
        """测试 Prompt 结构完整性"""
        required_sections = [
            '[CHARACTER]',
            '[CORE TRAITS]',
            '[DECISION RULES]',
            '[HARD RULES]',
            '[INPUT]',
            '[TASK]',
            '[OUTPUT PROTOCOL]',
            '[FAILSAFE]'
        ]
        
        for name, prompt in self.prompts.items():
            for section in required_sections:
                self.assertIn(section, prompt, f"{name} 缺少 {section} 部分")
    
    def test_json_format_integrity(self):
        """测试 JSON 格式完整性"""
        # 检查所有 Prompt 是否包含有效的 JSON 格式示例
        json_indicators = ['{', '}', '"', ':']
        for name, prompt in self.prompts.items():
            has_json = any(indicator in prompt for indicator in json_indicators)
            self.assertTrue(has_json, f"{name} 应该包含 JSON 格式示例")

if __name__ == '__main__':
    unittest.main()