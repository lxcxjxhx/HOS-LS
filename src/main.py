#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HOS-LS 安全检测工具
"""

import os
import sys
import argparse
import logging
import json
import asyncio
from colorama import init, Fore, Style

# 添加当前目录和项目根目录到 Python 路径
current_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, current_dir)
sys.path.insert(0, os.path.dirname(current_dir))

# 导入安全扫描模块
from scanners import EnhancedSecurityScanner
from reports import ReportGenerator
from utils import ConfigManager
from integrations import PRCommenter

# 导入HOS-LS v2.5核心组件
from core import ContextBuilder, AISemanticEngine, AttackGraphEngine, ExploitGenerator, Validator

# 初始化colorama
init(autoreset=True)

# 设置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def main():
    """主函数"""
    # 初始化配置管理器
    config_manager = ConfigManager()
    
    parser = argparse.ArgumentParser(
        description='HOS-LS 安全检测工具',
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        '-o', '--output',
        choices=['html', 'docx', 'md'],
        default=config_manager.get('report.format', 'html'),
        help='报告输出格式 (默认: html)'
    )
    
    parser.add_argument(
        '-d', '--output-dir',
        default=config_manager.get('report.output_dir', 'reports'),
        help='报告输出目录 (默认: reports)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='显示详细输出'
    )
    
    parser.add_argument(
        '-s', '--silent',
        action='store_true',
        help='静默模式，不输出控制台信息'
    )
    
    parser.add_argument(
        '--version',
        action='store_true',
        help='显示版本信息'
    )
    
    parser.add_argument(
        'target',
        nargs='?',
        help='要检测的AI工具目录或文件路径'
    )
    
    parser.add_argument(
        '--scan-result',
        help='扫描结果文件路径'
    )
    
    parser.add_argument(
        '--parallel',
        action='store_true',
        default=config_manager.get('scanner.parallel', True),
        help='启用并行扫描 (默认开启)'
    )
    
    parser.add_argument(
        '--no-parallel',
        action='store_false',
        dest='parallel',
        help='禁用并行扫描'
    )
    
    parser.add_argument(
        '--workers',
        type=int,
        default=config_manager.get('scanner.max_workers', 4),
        help='并行扫描工作进程数 (默认：4)'
    )
    
    # PR 评论相关参数
    parser.add_argument(
        '--pr-comment',
        action='store_true',
        help='启用 PR 评论功能'
    )
    
    parser.add_argument(
        '--pr-platform',
        choices=['github', 'gitlab', 'gitee'],
        default='github',
        help='代码托管平台 (默认：github)'
    )
    
    parser.add_argument(
        '--pr-owner',
        help='仓库所有者'
    )
    
    parser.add_argument(
        '--pr-repo',
        help='仓库名称'
    )
    
    parser.add_argument(
        '--pr-number',
        type=int,
        help='PR 编号'
    )
    
    parser.add_argument(
        '--pr-token',
        help='API 令牌'
    )
    
    # 差异化扫描相关参数
    parser.add_argument(
        '--diff-scan',
        action='store_true',
        help='启用差异化扫描功能'
    )
    
    parser.add_argument(
        '--diff-base',
        help='基准版本（分支、提交、标签）'
    )
    
    parser.add_argument(
        '--diff-head',
        help='目标版本（分支、提交、标签）'
    )
    
    parser.add_argument(
        '--diff-type',
        choices=['branch', 'commit', 'tag', 'staged', 'unstaged'],
        default='commit',
        help='差异类型 (默认：commit)'
    )
    
    # HOS-LS v2.5 AI驱动功能
    parser.add_argument(
        '--ai-scan',
        action='store_true',
        help='启用AI驱动的安全扫描'
    )
    
    parser.add_argument(
        '--smart-scan',
        action='store_true',
        default=True,
        help='启用智能扫描模式（默认开启）'
    )
    
    parser.add_argument(
        '--no-smart-scan',
        action='store_false',
        dest='smart_scan',
        help='禁用智能扫描模式'
    )
    
    parser.add_argument(
        '--openai-api-key',
        help='OpenAI API密钥，用于AI语义分析'
    )
    
    parser.add_argument(
        '--generate-exploit',
        action='store_true',
        help='生成漏洞利用代码'
    )
    
    parser.add_argument(
        '--validate-vulns',
        action='store_true',
        help='自动验证漏洞'
    )
    
    args = parser.parse_args()
    
    if args.version:
        if not args.silent:
            print('HOS-LS 安全检测工具 v2.5.0')
        return
    
    if not args.target:
        if not args.silent:
            parser.print_help()
        return
    
    # 检查目标路径是否存在（跳过URL检查）
    if not args.target.startswith(('http://', 'https://')) and not os.path.exists(args.target):
        if not args.silent:
            print(f'{Fore.RED}错误: 目标路径不存在: {args.target}{Style.RESET_ALL}')
        sys.exit(1)
    
    # 确保输出目录存在
    os.makedirs(args.output_dir, exist_ok=True)
    
    if not args.silent:
        print(f'{Fore.BLUE}开始检测：{args.target}{Style.RESET_ALL}')
        print(f'{Fore.BLUE}输出格式：{args.output}{Style.RESET_ALL}')
        print(f'{Fore.BLUE}输出目录：{args.output_dir}{Style.RESET_ALL}')
        print(f'{Fore.BLUE}扫描模式：{"并行" if args.parallel else "串行"}{Style.RESET_ALL}')
        if args.parallel:
            print(f'{Fore.BLUE}工作进程数：{args.workers}{Style.RESET_ALL}')
    
    # 调试导入状态
    print("导入状态:")
    try:
        from scanners import ASTScanner
        print(f"ASTScanner: {ASTScanner}")
    except ImportError:
        print("ASTScanner: ImportError")
    
    try:
        from scanners import AttackSurfaceAnalyzer
        print(f"AttackSurfaceAnalyzer: {AttackSurfaceAnalyzer}")
    except ImportError:
        print("AttackSurfaceAnalyzer: ImportError")
    
    try:
        from scanners import AttackPlanner
        print(f"AttackPlanner: {AttackPlanner}")
    except ImportError:
        print("AttackPlanner: ImportError")
    
    try:
        from scanners import DynamicExecutor
        print(f"DynamicExecutor: {DynamicExecutor}")
    except ImportError:
        print("DynamicExecutor: ImportError")
    
    # 从文件读取扫描结果或执行安全扫描
    if args.scan_result and os.path.exists(args.scan_result):
        with open(args.scan_result, 'r', encoding='utf-8') as f:
            results = json.load(f)
        if not args.silent:
            print(f'{Fore.GREEN}从文件读取扫描结果：{args.scan_result}{Style.RESET_ALL}')
    else:
        # 执行安全扫描
        if args.diff_scan:
            # 检查必要的参数
            if not args.diff_base or not args.diff_head:
                if not args.silent:
                    print(f'{Fore.RED}错误: 差异化扫描功能需要 --diff-base 和 --diff-head 参数{Style.RESET_ALL}')
                sys.exit(1)
            
            # 初始化差异化扫描器
            from scanners import DiffScanner
            scanner = DiffScanner(
                target=args.target,
                config={
                    'silent': args.silent,
                    'use_parallel': args.parallel,
                    'max_workers': args.workers
                }
            )
            
            # 执行差异化扫描
            if not args.silent:
                print(f'\n{Fore.BLUE}开始差异化扫描...{Style.RESET_ALL}')
                print(f'目标路径: {args.target}')
                print(f'基准版本: {args.diff_base}')
                print(f'目标版本: {args.diff_head}')
                print(f'差异类型: {args.diff_type}')
                print('-' * 80)
            
            # 根据差异类型执行扫描
            if args.diff_type == 'branch':
                results = scanner.scan_branch(args.diff_base, args.diff_head)
            elif args.diff_type == 'commit':
                results = scanner.scan_commit(args.diff_base, args.diff_head)
            elif args.diff_type == 'tag':
                results = scanner.scan_tag(args.diff_base, args.diff_head)
            elif args.diff_type == 'staged':
                results = scanner.scan_staged()
            elif args.diff_type == 'unstaged':
                results = scanner.scan_unstaged()
            else:
                results = scanner.scan_diff(args.diff_base, args.diff_head)
        else:
            # 执行常规安全扫描 (使用增强扫描器，支持并行)
            scanner = EnhancedSecurityScanner(
                args.target, 
                silent=args.silent,
                use_parallel=args.parallel,
                max_workers=args.workers,
                use_smart_scan=args.smart_scan
            )
            results = scanner.scan()
        
        # 添加项目类型和规则集信息
        results['project_type'] = 'web_app'  # 默认值，实际应该从扫描器获取
        results['rule_set'] = 'default'  # 默认值
        
        # HOS-LS v2.5 AI驱动功能
        if args.ai_scan:
            if not args.silent:
                print(f'\n{Fore.BLUE}启用AI驱动的安全扫描...{Style.RESET_ALL}')
            
            # 收集要分析的文件
            files_to_analyze = []
            if os.path.isfile(args.target):
                files_to_analyze = [args.target]
            elif os.path.isdir(args.target):
                for root, _, files in os.walk(args.target):
                    for file in files:
                        if file.endswith(('.py', '.js', '.ts', '.php', '.java')):
                            files_to_analyze.append(os.path.join(root, file))
            
            if not files_to_analyze:
                if not args.silent:
                    print(f'{Fore.YELLOW}没有找到可分析的文件{Style.RESET_ALL}')
            else:
                if not args.silent:
                    print(f'{Fore.BLUE}找到 {len(files_to_analyze)} 个文件进行AI分析{Style.RESET_ALL}')
                
                # 1. 构建上下文
                if not args.silent:
                    print(f'{Fore.CYAN}  1. 构建代码上下文...{Style.RESET_ALL}')
                context_builder = ContextBuilder()
                context = context_builder.build(files_to_analyze)
                
                # 2. AI语义分析
                if not args.silent:
                    print(f'{Fore.CYAN}  2. AI语义分析...{Style.RESET_ALL}')
                try:
                    ai_engine = AISemanticEngine(api_key=args.openai_api_key)
                    ai_analysis = ai_engine.analyze(files_to_analyze)
                    results['ai_analysis'] = ai_analysis
                    if not args.silent:
                        print(f'{Fore.GREEN}  [OK] AI语义分析完成{Style.RESET_ALL}')
                except Exception as e:
                    if not args.silent:
                        print(f'{Fore.RED}  [ERROR] AI语义分析失败：{e}{Style.RESET_ALL}')
                
                # 3. 攻击链分析
                if not args.silent:
                    print(f'{Fore.CYAN}  3. 攻击链分析...{Style.RESET_ALL}')
                try:
                    attack_engine = AttackGraphEngine()
                    attack_chains = attack_engine.analyze_attack_chains(files_to_analyze)
                    results['attack_chains'] = attack_chains
                    if not args.silent:
                        print(f'{Fore.GREEN}  [OK] 攻击链分析完成，发现 {len(attack_chains)} 条攻击链{Style.RESET_ALL}')
                except Exception as e:
                    if not args.silent:
                        print(f'{Fore.RED}  [ERROR] 攻击链分析失败：{e}{Style.RESET_ALL}')
                
                # 4. 生成Exploit
                if args.generate_exploit and 'attack_chains' in results:
                    if not args.silent:
                        print(f'{Fore.CYAN}  4. 生成漏洞利用代码...{Style.RESET_ALL}')
                    try:
                        exploit_generator = ExploitGenerator()
                        exploits = exploit_generator.generate_exploit(results['attack_chains'])
                        results['exploits'] = exploits
                        if not args.silent:
                            print(f'{Fore.GREEN}  [OK] Exploit生成完成，生成 {len(exploits)} 个利用代码{Style.RESET_ALL}')
                    except Exception as e:
                        if not args.silent:
                            print(f'{Fore.RED}  [ERROR] Exploit生成失败：{e}{Style.RESET_ALL}')
                
                # 5. 自动验证
                if args.validate_vulns and 'exploits' in results:
                    if not args.silent:
                        print(f'{Fore.CYAN}  5. 自动验证漏洞...{Style.RESET_ALL}')
                    try:
                        async def validate():
                            validator = Validator()
                            validation_results = await validator.validate_vulnerabilities(results['exploits'])
                            await validator.close()
                            return validation_results
                        
                        validation_results = asyncio.run(validate())
                        results['validation_results'] = validation_results
                        if not args.silent:
                            valid_count = sum(1 for r in validation_results if r.get('validation', {}).get('valid', False))
                            print(f'{Fore.GREEN}  [OK] 漏洞验证完成，验证 {len(validation_results)} 个漏洞，其中 {valid_count} 个有效{Style.RESET_ALL}')
                    except Exception as e:
                        if not args.silent:
                            print(f'{Fore.RED}  [ERROR] 漏洞验证失败：{e}{Style.RESET_ALL}')

    # 生成AI辅助安全建议
    ai_suggestions = {}
    try:
        from utils import AISuggestionGenerator
        
        ai_generator = AISuggestionGenerator()
        if not args.silent:
            print(f'\n{Fore.BLUE}生成AI辅助安全建议...{Style.RESET_ALL}')
        
        # 为每个工具生成安全提示词（调用 AI 生成，不使用固定模板）
        if not args.silent:
            print(f'{Fore.BLUE}正在为各工具生成安全提示词（AI 生成）...{Style.RESET_ALL}')
        
        prompts = {}
        for tool_name in ['cursor', 'trae', 'kiro']:
            if not args.silent:
                print(f'{Fore.CYAN}  生成 {tool_name} 提示词...{Style.RESET_ALL}')
            try:
                # 调用 AI 生成安全提示词
                prompt = ai_generator.generate_security_prompts(tool_name)
                prompts[tool_name] = prompt
                if not args.silent:
                    print(f'{Fore.GREEN}  [OK] {tool_name} 提示词已生成（{len(prompt)} 字符）{Style.RESET_ALL}')
            except Exception as e:
                if not args.silent:
                    print(f'{Fore.RED}  [ERROR] 生成{tool_name}提示词时出错：{e}{Style.RESET_ALL}')
                import traceback
                traceback.print_exc()
                prompts[tool_name] = f"# {tool_name} 安全提示词（生成失败）"
        
        if not args.silent:
            print(f'{Fore.GREEN}[OK] 所有工具提示词生成完成{Style.RESET_ALL}')
            print(f'{Fore.GREEN}  - prompts 字典键：{list(prompts.keys())}{Style.RESET_ALL}')
        
        # 保存提示词到文件
        prompts_dir = os.path.join(args.output_dir, 'prompts')
        os.makedirs(prompts_dir, exist_ok=True)
        
        # 将 AI 生成的提示词保存到文件
        for tool_name, prompt in prompts.items():
            try:
                prompt_file = os.path.join(prompts_dir, f'{tool_name}_security_prompt.txt')
                with open(prompt_file, 'w', encoding='utf-8') as f:
                    f.write(prompt)
                if not args.silent:
                    print(f'{Fore.GREEN}  [OK] 已保存：{prompt_file}{Style.RESET_ALL}')
            except Exception as e:
                if not args.silent:
                    print(f'{Fore.RED}  [ERROR] 保存{tool_name}提示词时出错：{e}{Style.RESET_ALL}')
        
        # 分析扫描结果获取实际的风险数量
        high_risk = 0
        medium_risk = 0
        low_risk = 0
        
        for category in results.values():
            if isinstance(category, list):
                for item in category:
                    if item.get('severity') == 'high':
                        high_risk += 1
                    elif item.get('severity') == 'medium':
                        medium_risk += 1
                    elif item.get('severity') == 'low':
                        low_risk += 1
        
        # 生成风险评估
        if high_risk > 0:
            risk_assessment = f"本次扫描发现{high_risk}个高风险问题，{medium_risk}个中风险问题，{low_risk}个低风险问题。系统存在严重安全隐患，建议立即处理高风险问题。"
        elif medium_risk > 0:
            risk_assessment = f"本次扫描发现{high_risk}个高风险问题，{medium_risk}个中风险问题，{low_risk}个低风险问题。系统存在一定安全风险，建议尽快处理中风险问题。"
        else:
            risk_assessment = f"本次扫描发现{high_risk}个高风险问题，{medium_risk}个中风险问题，{low_risk}个低风险问题。系统安全状态良好，建议定期进行安全检查。"
        
        # 构建 AI 建议数据（完全使用 AI 生成的内容）
        ai_suggestions = {
            'risk_assessment': risk_assessment,
            'specific_suggestions': ["请查看各工具的安全提示词文件获取详细建议"],
            'best_practices': ["请参考生成的安全提示词文件"],
            'tool_prompts': "\n\n".join([f"# {tool_name} 安全提示词\n{prompt}" for tool_name, prompt in prompts.items()]),
            'cursor_prompt': prompts.get('cursor', '# Cursor 安全提示词（AI 生成失败）'),
            'trae_prompt': prompts.get('trae', '# Trae 安全提示词（AI 生成失败）'),
            'kiro_prompt': prompts.get('kiro', '# Kiro 安全提示词（AI 生成失败）')
        }
        
        # 将 AI 建议添加到扫描结果中
        results['ai_suggestions'] = ai_suggestions
        if not args.silent:
            print(f'{Fore.GREEN}  [OK] AI 建议已生成并添加到结果中{Style.RESET_ALL}')
            print(f'{Fore.GREEN}    - Cursor 提示词长度：{len(ai_suggestions.get("cursor_prompt", ""))} 字符{Style.RESET_ALL}')
            print(f'{Fore.GREEN}    - Trae 提示词长度：{len(ai_suggestions.get("trae_prompt", ""))} 字符{Style.RESET_ALL}')
            print(f'{Fore.GREEN}    - Kiro 提示词长度：{len(ai_suggestions.get("kiro_prompt", ""))} 字符{Style.RESET_ALL}')
    except Exception as e:
        if not args.silent:
            print(f'{Fore.YELLOW}生成 AI 建议时出错：{e}{Style.RESET_ALL}')
        import traceback
        traceback.print_exc()

    # 生成报告
    try:
        if not args.silent:
            print(f'\n{Fore.BLUE}开始生成报告...{Style.RESET_ALL}')
            print(f'{Fore.BLUE}  - 输出目录：{args.output_dir}{Style.RESET_ALL}')
            print(f'{Fore.BLUE}  - 输出格式：{args.output}{Style.RESET_ALL}')
            print(f'{Fore.BLUE}  - AI 建议是否存在：{"ai_suggestions" in results}{Style.RESET_ALL}')
            print(f'{Fore.BLUE}  - results 字典的键：{list(results.keys())}{Style.RESET_ALL}')
            if 'ai_suggestions' in results:
                print(f'{Fore.BLUE}  - ai_suggestions 的键：{list(results["ai_suggestions"].keys())}{Style.RESET_ALL}')
        
        # 检查输出目录是否存在
        if not os.path.exists(args.output_dir):
            if not args.silent:
                print(f'{Fore.YELLOW}输出目录不存在，创建目录：{args.output_dir}{Style.RESET_ALL}')
            os.makedirs(args.output_dir, exist_ok=True)
        
        # 检查扫描结果
        if not args.silent:
            print(f'{Fore.CYAN}创建 ReportGenerator 实例...{Style.RESET_ALL}')
        generator = ReportGenerator(results, args.target, args.output_dir)
        
        # 根据输出格式生成报告
        if args.output == 'html':
            if not args.silent:
                print(f'{Fore.CYAN}生成 HTML 报告...{Style.RESET_ALL}')
            report_path = generator.generate_html()
        elif args.output == 'md':
            if not args.silent:
                print(f'{Fore.CYAN}生成 Markdown 报告...{Style.RESET_ALL}')
            report_path = generator.generate_md()
        elif args.output == 'json':
            if not args.silent:
                print(f'{Fore.CYAN}生成 JSON 报告...{Style.RESET_ALL}')
            report_path = generator.generate_json()
        else:
            # 默认生成 HTML 报告
            if not args.silent:
                print(f'{Fore.CYAN}生成 HTML 报告...{Style.RESET_ALL}')
            report_path = generator.generate_html()
        
        if not args.silent:
            report_type = args.output.upper() if args.output in ['html', 'md', 'json'] else 'HTML'
            print(f'{Fore.GREEN}[OK] {report_type} 报告已生成：{report_path}{Style.RESET_ALL}')
            if report_path and os.path.exists(report_path):
                file_size = os.path.getsize(report_path)
                print(f'{Fore.GREEN}  - 文件大小：{file_size} 字节{Style.RESET_ALL}')
            else:
                print(f'{Fore.YELLOW}  [WARN] 报告文件不存在或路径为空{Style.RESET_ALL}')
    except Exception as e:
        if not args.silent:
            print(f'{Fore.RED}生成报告时出错：{e}{Style.RESET_ALL}')
        import traceback
        traceback.print_exc()
        if not results:
            if not args.silent:
                print(f'{Fore.YELLOW}扫描结果为空，无法生成报告{Style.RESET_ALL}')
            return
        
        # 检查AI建议
        if 'ai_suggestions' not in results:
            if not args.silent:
                print(f'{Fore.YELLOW}AI建议不存在，添加默认建议{Style.RESET_ALL}')
            results['ai_suggestions'] = {
                'risk_assessment': '正在生成风险评估...',
                'specific_suggestions': ['正在生成针对性建议...'],
                'best_practices': ['正在生成安全最佳实践...'],
                'tool_prompts': '',
                'cursor_prompt': '# Cursor 安全提示词\n正在生成...',
                'trae_prompt': '# Trae 安全提示词\n正在生成...',
                'kiro_prompt': '# Kiro 安全提示词\n正在生成...'
            }
        
        generator = ReportGenerator(results, args.target, args.output_dir)
        
        if args.output == 'html':
            if not args.silent:
                print(f'{Fore.BLUE}生成HTML报告...{Style.RESET_ALL}')
            report_path = generator.generate_html()
        elif args.output == 'docx':
            if not args.silent:
                print(f'{Fore.BLUE}生成DOCX报告...{Style.RESET_ALL}')
            report_path = generator.generate_docx()
        elif args.output == 'md':
            if not args.silent:
                print(f'{Fore.BLUE}生成MD报告...{Style.RESET_ALL}')
            report_path = generator.generate_md()
        
        if not args.silent:
            print(f'{Fore.GREEN}检测完成!{Style.RESET_ALL}')
            print(f'{Fore.GREEN}报告已生成：{report_path}{Style.RESET_ALL}')
            
            # 检查报告文件是否存在
            if os.path.exists(report_path):
                print(f'{Fore.GREEN}报告文件存在，大小：{os.path.getsize(report_path)} 字节{Style.RESET_ALL}')
            else:
                print(f'{Fore.RED}报告文件不存在，生成失败{Style.RESET_ALL}')
        
        # 生成 PR 评论（如果启用）
        if args.pr_comment:
            if not args.silent:
                print(f'\n{Fore.BLUE}生成 PR 评论...{Style.RESET_ALL}')
            
            try:
                # 检查必要的参数
                if not args.pr_owner or not args.pr_repo or not args.pr_number or not args.pr_token:
                    if not args.silent:
                        print(f'{Fore.RED}错误: PR 评论功能需要 --pr-owner, --pr-repo, --pr-number 和 --pr-token 参数{Style.RESET_ALL}')
                else:
                    # 创建 PR 评论器
                    commenter = PRCommenter(
                        platform=args.pr_platform,
                        config={
                            'token': args.pr_token,
                            'repo_owner': args.pr_owner,
                            'repo_name': args.pr_repo,
                            'pr_number': args.pr_number
                        }
                    )
                    
                    # 生成 PR 评论
                    response = commenter.comment_on_pr(results)
                    if response and not args.silent:
                        print(f'{Fore.GREEN}[OK] PR 评论已创建{Style.RESET_ALL}')
                    
                    # 生成内联评论
                    inline_responses = commenter.comment_on_files(results)
                    if inline_responses and not args.silent:
                        print(f'{Fore.GREEN}[OK] 已创建 {len(inline_responses)} 个内联评论{Style.RESET_ALL}')
            except Exception as e:
                if not args.silent:
                    print(f'{Fore.YELLOW}生成 PR 评论时出错：{e}{Style.RESET_ALL}')
                import traceback
                traceback.print_exc()
    except Exception as e:
        if not args.silent:
            print(f'{Fore.RED}生成报告时出错: {e}{Style.RESET_ALL}')
            import traceback
            traceback.print_exc()
    
if __name__ == '__main__':
    main()
