#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HOS-LS v2.0 agentflow-main 全功能安全测试脚本
对 agentflow-main 项目进行全面的安全扫描测试
"""

import os
import sys
import json
import time
from datetime import datetime
from colorama import init, Fore, Style

# 初始化 colorama
init(autoreset=True)

# 添加项目路径
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

from enhanced_scanner import EnhancedSecurityScanner
from ast_scanner import ASTScanner
from taint_analyzer import TaintAnalyzer
from encoding_detector import EncodingDetector
from ai_suggestion_generator import AISuggestionGenerator
from attack_simulator import AttackSimulator
from report_generator import ReportGenerator
from sandbox_analyzer import SandboxAnalyzer


def print_section(title):
    """打印章节标题"""
    print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{title}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")


def print_step(step_num, description):
    """打印步骤信息"""
    print(f"{Fore.GREEN}[{step_num}]{Style.RESET_ALL} {description}...")


def run_agentflow_test():
    """运行 agentflow-main 全功能测试"""
    # 配置路径
    target_dir = r"c:\1AAA_PROJECT\HOS\HOS-LS\agentflow-main"
    output_dir = r"c:\1AAA_PROJECT\HOS\HOS-LS\HOS-LS\tests\test-other"
    
    # 确保输出目录存在
    os.makedirs(output_dir, exist_ok=True)
    
    print_section(f"HOS-LS v2.0 agentflow-main 全功能安全测试")
    print(f"目标项目：{target_dir}")
    print(f"输出目录：{output_dir}")
    print(f"测试时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    start_time = time.time()
    
    # 初始化结果存储
    all_results = {}
    all_summary = {
        'total_issues': 0,
        'high_risk': 0,
        'medium_risk': 0,
        'low_risk': 0,
        'ast_issues': 0,
        'taint_issues': 0,
        'encoding_issues': 0,
        'sandbox_issues': 0,
        'attack_scenarios': 0
    }
    
    try:
        # ==================== 第一部分：增强规则扫描 ====================
        print_section("第一部分：增强规则扫描")
        step = 1
        
        print_step(step, "初始化增强安全扫描器 (并行模式)")
        scanner = EnhancedSecurityScanner(
            target=target_dir,
            silent=False,
            use_parallel=True,
            max_workers=4
        )
        
        print_step(step + 1, "执行安全规则扫描")
        rule_results = scanner.scan()
        
        print_step(step + 2, "获取扫描摘要")
        rule_summary = scanner.get_summary()
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} 完成，发现问题数：{rule_summary['total_issues']}")
        
        all_results['rule_results'] = rule_results
        all_summary['total_issues'] += rule_summary['total_issues']
        all_summary['high_risk'] += rule_summary.get('high_risk', 0)
        all_summary['medium_risk'] += rule_summary.get('medium_risk', 0)
        all_summary['low_risk'] += rule_summary.get('low_risk', 0)
        
        # ==================== 第二部分：AST 分析 ====================
        print_section("第二部分：AST 抽象语法树分析")
        step = 10
        
        print_step(step, "初始化 AST 扫描器")
        ast_scanner = ASTScanner()
        
        print_step(step + 1, "执行 AST 分析")
        ast_results = ast_scanner.analyze(target_dir)
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} 完成，发现问题数：{len(ast_results)}")
        
        all_results['ast_analysis'] = ast_results
        all_summary['ast_issues'] = len(ast_results)
        all_summary['total_issues'] += len(ast_results)
        
        # ==================== 第三部分：数据流分析 ====================
        print_section("第三部分：数据流分析（污点追踪）")
        step = 20
        
        print_step(step, "初始化污点分析器")
        taint_analyzer = TaintAnalyzer()
        
        print_step(step + 1, "执行数据流分析")
        taint_results = taint_analyzer.analyze(target_dir)
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} 完成，发现问题数：{len(taint_results)}")
        
        all_results['taint_analysis'] = taint_results
        all_summary['taint_issues'] = len(taint_results)
        all_summary['total_issues'] += len(taint_results)
        
        # ==================== 第四部分：编码检测 ====================
        print_section("第四部分：编码检测")
        step = 30
        
        print_step(step, "初始化编码检测器")
        detector = EncodingDetector()
        encoding_issues = []
        
        print_step(step + 1, "遍历项目文件")
        file_count = 0
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                if file.endswith('.py') or file.endswith('.ts') or file.endswith('.js'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        results = detector.scan(content)
                        if results:
                            for result in results:
                                result['file'] = file_path
                                encoding_issues.append(result)
                        file_count += 1
                    except Exception as e:
                        pass
        
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} 完成，扫描文件数：{file_count}，发现问题数：{len(encoding_issues)}")
        
        all_results['encoding_detection'] = encoding_issues
        all_summary['encoding_issues'] = len(encoding_issues)
        all_summary['total_issues'] += len(encoding_issues)
        
        # ==================== 第五部分：AI 安全建议生成 ====================
        print_section("第五部分：AI 安全建议生成")
        step = 40
        
        print_step(step, "初始化 AI 建议生成器")
        ai_generator = AISuggestionGenerator()
        
        print_step(step + 1, "生成安全风险评估")
        ai_advice = ai_generator.generate_security_advice(rule_results)
        
        print_step(step + 2, "生成 Cursor 安全提示")
        ai_prompt_cursor = ai_generator.generate_security_prompts(tool_name='cursor')
        
        print_step(step + 3, "生成 Trae 安全提示")
        ai_prompt_trae = ai_generator.generate_security_prompts(tool_name='trae')
        
        print_step(step + 4, "生成 Kiro 安全提示")
        ai_prompt_kiro = ai_generator.generate_security_prompts(tool_name='kiro')
        
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} 完成，已生成 AI 安全建议和提示")
        
        all_results['ai_advice'] = ai_advice
        all_results['ai_prompts'] = {
            'cursor': ai_prompt_cursor,
            'trae': ai_prompt_trae,
            'kiro': ai_prompt_kiro
        }
        
        # ==================== 第六部分：攻击模拟测试 ====================
        print_section("第六部分：攻击模拟测试")
        step = 50
        
        print_step(step, "初始化攻击模拟器")
        attack_sim = AttackSimulator()
        
        print_step(step + 1, "获取 Agent 攻击场景")
        attack_scenarios = attack_sim.get_agent_scenarios()
        scenario_count = len(attack_scenarios) if isinstance(attack_scenarios, dict) else len(attack_scenarios) if isinstance(attack_scenarios, list) else 0
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} 完成，加载 {scenario_count} 个攻击场景")
        
        all_results['attack_scenarios'] = attack_scenarios
        all_summary['attack_scenarios'] = scenario_count
        
        # ==================== 第七部分：沙盒分析 ====================
        print_section("第七部分：沙盒分析")
        step = 60
        
        print_step(step, "初始化沙盒分析器")
        sandbox = SandboxAnalyzer()
        sandbox_results = []
        
        print_step(step + 1, "遍历项目文件进行沙盒分析")
        sandbox_file_count = 0
        for root, dirs, files in os.walk(target_dir):
            dirs[:] = [d for d in dirs if d not in ['node_modules', '.git', '__pycache__', '.venv', 'venv']]
            
            for file in files:
                if file.endswith('.py') or file.endswith('.ts') or file.endswith('.js'):
                    file_path = os.path.join(root, file)
                    try:
                        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                        result = sandbox.analyze_code(content)
                        if result:
                            result['file'] = file_path
                            sandbox_results.append(result)
                        sandbox_file_count += 1
                    except Exception as e:
                        pass
        
        print(f"  {Fore.GREEN}[OK]{Style.RESET_ALL} 完成，分析文件数：{sandbox_file_count}，发现问题数：{len(sandbox_results)}")
        
        all_results['sandbox_analysis'] = sandbox_results
        all_summary['sandbox_issues'] = len(sandbox_results)
        all_summary['total_issues'] += len(sandbox_results)
        
        # ==================== 第八部分：生成报告 ====================
        print_section("第八部分：生成测试报告")
        step = 70
        
        elapsed_time = time.time() - start_time
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        print_step(step, "准备报告数据")
        # 将 rule_results 中的内容展开合并到顶层，以便 report_generator 能正确识别
        report_results = all_results.copy()
        if 'rule_results' in report_results:
            rule_data = report_results.pop('rule_results')
            # 将 rule_results 中的各个类别合并到顶层
            for key, value in rule_data.items():
                if key not in report_results:
                    report_results[key] = value
        report_results['ai_suggestions'] = {
            'risk_assessment': ai_advice[:500] if ai_advice else '正在生成...',
            'specific_suggestions': [
                '使用环境变量管理敏感信息',
                '避免使用危险函数',
                '定期更新依赖',
                '实施输入验证',
                '使用参数化查询'
            ],
            'best_practices': [
                '最小权限原则',
                '输入验证',
                '输出编码',
                '安全配置管理',
                '日志记录与监控'
            ],
            'cursor_prompt': ai_prompt_cursor[:1000] if ai_prompt_cursor else '正在生成...',
            'trae_prompt': ai_prompt_trae[:1000] if ai_prompt_trae else '正在生成...',
            'kiro_prompt': ai_prompt_kiro[:1000] if ai_prompt_kiro else '正在生成...'
        }
        
        print_step(step + 1, "创建报告生成器")
        report_gen = ReportGenerator(
            results=report_results,
            target=target_dir,
            output_dir=output_dir
        )
        
        print_step(step + 2, "生成 HTML 报告")
        html_report = report_gen.generate_html(filename=f'agentflow_test_report_{timestamp}.html')
        
        print_step(step + 3, "生成 Markdown 报告")
        md_report = report_gen.generate_md(filename=f'agentflow_test_report_{timestamp}.md')
        
        print_step(step + 4, "生成 JSON 报告")
        json_report_file = os.path.join(output_dir, f'agentflow_test_report_{timestamp}.json')
        with open(json_report_file, 'w', encoding='utf-8') as f:
            json.dump({
                'metadata': {
                    'target': target_dir,
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'duration': elapsed_time,
                    'test_type': 'comprehensive'
                },
                'summary': all_summary,
                'results': all_results,
                'ai_advice': ai_advice,
                'ai_prompts': report_results['ai_suggestions'],
                'attack_scenarios': attack_scenarios if isinstance(attack_scenarios, dict) else {}
            }, f, ensure_ascii=False, indent=2, default=str)
        
        # ==================== 测试结果汇总 ====================
        print_section("测试结果汇总")
        
        print(f"{Fore.GREEN}[SUCCESS] 测试完成！{Style.RESET_ALL}")
        print(f"  耗时：{elapsed_time:.2f} 秒")
        print(f"  总问题数：{all_summary['total_issues']}")
        print(f"  高风险：{all_summary['high_risk']}")
        print(f"  中风险：{all_summary['medium_risk']}")
        print(f"  低风险：{all_summary['low_risk']}")
        print(f"  AST 问题：{all_summary['ast_issues']}")
        print(f"  数据流问题：{all_summary['taint_issues']}")
        print(f"  编码问题：{all_summary['encoding_issues']}")
        print(f"  沙盒问题：{all_summary['sandbox_issues']}")
        print(f"  攻击场景：{all_summary['attack_scenarios']}")
        print(f"\n  报告文件:")
        print(f"    HTML: {html_report}")
        print(f"    MD:   {md_report}")
        print(f"    JSON: {json_report_file}")
        
        print(f"\n{Fore.CYAN}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}所有测试模块运行成功！{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*80}{Style.RESET_ALL}\n")
        
        return 0
        
    except Exception as e:
        print(f"\n{Fore.RED}[ERROR] 测试失败：{e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == '__main__':
    sys.exit(run_agentflow_test())
