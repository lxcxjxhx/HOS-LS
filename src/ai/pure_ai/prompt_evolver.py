class PromptEvolver:
    """Prompt 自进化系统
    
    自动优化、测试和评估 Prompt，实现 Prompt 的自我进化
    """
    
    def __init__(self, llm_client):
        """初始化 Prompt 进化器
        
        Args:
            llm_client: LLM 客户端，用于生成优化后的 Prompt
        """
        self.llm_client = llm_client
    
    def optimize_prompt(self, original_prompt, optimizer_type="standard"):
        """使用优化器优化单个 Prompt
        
        Args:
            original_prompt: 原始 Prompt
            optimizer_type: 优化器类型，可选 "standard" 或 "anti_hallucination"
            
        Returns:
            优化后的 Prompt
        """
        from .prompt_templates import PromptTemplates
        
        if optimizer_type == "anti_hallucination":
            optimizer_prompt = PromptTemplates.ANTI_HALLUCINATION_PROMPT_OPTIMIZER
        else:
            optimizer_prompt = PromptTemplates.PROMPT_OPTIMIZER
        
        # 生成优化后的 Prompt
        optimized_prompt = self.llm_client.generate(
            optimizer_prompt.format(original_prompt=original_prompt)
        )
        
        return optimized_prompt
    
    def evolve_prompts(self, prompts, test_cases=None):
        """进化所有 Prompt
        
        Args:
            prompts: Prompt 字典，格式为 {name: prompt}
            test_cases: 测试用例列表，用于评估优化效果
            
        Returns:
            进化后的 Prompt 字典
        """
        evolved_prompts = {}
        
        for name, prompt in prompts.items():
            # 选择合适的优化器
            if "vulnerability" in name.lower() or "adversarial" in name.lower():
                optimizer_type = "anti_hallucination"
            else:
                optimizer_type = "standard"
            
            # 优化 Prompt
            optimized = self.optimize_prompt(prompt, optimizer_type)
            
            # 测试优化效果
            if test_cases:
                test_result = self.test_prompt(optimized, test_cases)
                if self.is_better(test_result):
                    evolved_prompts[name] = optimized
                    print(f"✅ {name} 优化成功")
                else:
                    evolved_prompts[name] = prompt
                    print(f"❌ {name} 优化失败，保持原 Prompt")
            else:
                # 如果没有测试用例，直接使用优化后的 Prompt
                evolved_prompts[name] = optimized
                print(f"⚠️  {name} 已优化（无测试）")
        
        return evolved_prompts
    
    def test_prompt(self, prompt, test_cases):
        """测试 Prompt 效果
        
        Args:
            prompt: 要测试的 Prompt
            test_cases: 测试用例列表
            
        Returns:
            测试结果
        """
        test_results = []
        
        for test_case in test_cases:
            # 生成测试输入
            test_input = test_case.get('input', {})
            expected_output = test_case.get('expected_output', {})
            
            # 执行测试
            try:
                # 这里需要根据实际的 LLM 调用方式调整
                output = self.llm_client.generate(
                    prompt.format(**test_input)
                )
                
                # 评估测试结果
                result = self.evaluate_output(output, expected_output)
                test_results.append(result)
            except Exception as e:
                test_results.append({
                    'success': False,
                    'error': str(e)
                })
        
        return {
            'results': test_results,
            'success_rate': sum(1 for r in test_results if r.get('success', False)) / len(test_results) if test_results else 0
        }
    
    def evaluate_output(self, output, expected_output):
        """评估输出结果
        
        Args:
            output: 实际输出
            expected_output: 期望输出
            
        Returns:
            评估结果
        """
        import json
        
        try:
            # 解析输出为 JSON
            output_json = json.loads(output)
            
            # 检查输出结构
            success = True
            errors = []
            
            # 检查期望的关键字段
            for key in expected_output:
                if key not in output_json:
                    success = False
                    errors.append(f"缺少字段: {key}")
                elif isinstance(expected_output[key], dict):
                    # 递归检查嵌套结构
                    nested_result = self.evaluate_output(output_json[key], expected_output[key])
                    if not nested_result['success']:
                        success = False
                        errors.extend(nested_result['errors'])
            
            return {
                'success': success,
                'errors': errors,
                'output': output_json
            }
        except json.JSONDecodeError:
            return {
                'success': False,
                'errors': ['输出不是有效的 JSON'],
                'output': output
            }
    
    def is_better(self, test_result):
        """判断是否更好
        
        Args:
            test_result: 测试结果
            
        Returns:
            是否更好
        """
        # 简单的评估逻辑：成功率超过 80% 认为更好
        return test_result.get('success_rate', 0) >= 0.8
    
    def create_evolution_report(self, original_prompts, evolved_prompts, test_results):
        """创建进化报告
        
        Args:
            original_prompts: 原始 Prompt
            evolved_prompts: 进化后的 Prompt
            test_results: 测试结果
            
        Returns:
            进化报告
        """
        report = {
            'summary': {
                'total_prompts': len(original_prompts),
                'evolved_prompts': len([p for p in evolved_prompts if p != original_prompts.get(p)]),
                'success_rate': sum(1 for r in test_results if r.get('success_rate', 0) >= 0.8) / len(test_results) if test_results else 0
            },
            'details': {}
        }
        
        for name in original_prompts:
            report['details'][name] = {
                'original_length': len(original_prompts[name]),
                'evolved_length': len(evolved_prompts.get(name, original_prompts[name])),
                'changed': original_prompts[name] != evolved_prompts.get(name, original_prompts[name])
            }
        
        return report
    
    def start_evolution_cycle(self, prompts, test_cases=None, max_iterations=3):
        """启动进化循环
        
        Args:
            prompts: Prompt 字典
            test_cases: 测试用例列表
            max_iterations: 最大迭代次数
            
        Returns:
            最终进化后的 Prompt 字典和进化报告
        """
        current_prompts = prompts.copy()
        evolution_history = []
        
        for iteration in range(max_iterations):
            print(f"\n🔄 进化循环第 {iteration + 1} 轮")
            
            # 进化 Prompt
            evolved_prompts = self.evolve_prompts(current_prompts, test_cases)
            
            # 测试进化效果
            if test_cases:
                test_results = []
                for name, prompt in evolved_prompts.items():
                    test_result = self.test_prompt(prompt, test_cases)
                    test_results.append(test_result)
                
                # 创建进化报告
                report = self.create_evolution_report(current_prompts, evolved_prompts, test_results)
                evolution_history.append(report)
                
                print(f"📊 第 {iteration + 1} 轮进化报告:")
                print(f"   成功率: {report['summary']['success_rate']:.2f}")
                print(f"   进化 Prompt 数: {report['summary']['evolved_prompts']}")
                
                # 检查是否收敛
                if report['summary']['evolved_prompts'] == 0:
                    print("✅ 进化已收敛，停止循环")
                    break
            
            current_prompts = evolved_prompts
        
        return current_prompts, evolution_history
    
    def evaluate_prompt_quality(self, prompt):
        """评估 Prompt 质量
        
        Args:
            prompt: 要评估的 Prompt
            
        Returns:
            质量评分
        """
        # 评估维度
        score = 0
        
        # 1. 结构完整性
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
        
        for section in required_sections:
            if section in prompt:
                score += 1
        
        # 2. 约束强度
        constraint_keywords = [
            '禁止',
            '必须',
            '不允许',
            'NO',
            'REFUTE'
        ]
        
        constraint_count = sum(prompt.count(keyword) for keyword in constraint_keywords)
        score += min(constraint_count / 10, 2)  # 最多加 2 分
        
        # 3. 简洁性
        prompt_length = len(prompt)
        if prompt_length < 1000:
            score += 2
        elif prompt_length < 2000:
            score += 1
        
        # 4. 明确性
        clarity_keywords = [
            '严格',
            '精确',
            '稳定',
            '一致'
        ]
        
        clarity_count = sum(prompt.count(keyword) for keyword in clarity_keywords)
        score += min(clarity_count / 5, 1)  # 最多加 1 分
        
        # 归一化到 0-10 分
        final_score = min(score / (len(required_sections) + 5) * 10, 10)
        
        return final_score
    
    def batch_evaluate_prompts(self, prompts):
        """批量评估 Prompt 质量
        
        Args:
            prompts: Prompt 字典
            
        Returns:
            评估结果字典
        """
        evaluations = {}
        
        for name, prompt in prompts.items():
            score = self.evaluate_prompt_quality(prompt)
            evaluations[name] = {
                'score': score,
                'rating': self._get_rating(score)
            }
        
        return evaluations
    
    def _get_rating(self, score):
        """根据评分获取评级
        
        Args:
            score: 评分
            
        Returns:
            评级
        """
        if score >= 9:
            return 'A+'
        elif score >= 8:
            return 'A'
        elif score >= 7:
            return 'B+'
        elif score >= 6:
            return 'B'
        elif score >= 5:
            return 'C'
        else:
            return 'D'