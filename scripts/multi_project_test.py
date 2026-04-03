#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
多项目测试脚本

功能：
1. 克隆多个开源项目
2. 在每个项目上运行 HOS-LS
3. 收集性能数据和漏洞检测结果
4. 生成测试报告
"""

import os
import subprocess
import time
import json
import git
from typing import List, Dict, Any

class MultiProjectTest:
    def __init__(self, output_dir: str = 'test_results'):
        """
        初始化多项目测试
        
        Args:
            output_dir: 输出目录
        """
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)
        
        # 开源项目列表
        self.projects = [
            {
                'name': 'agentflow',
                'url': 'https://github.com/agentflow/agentflow.git'
            },
            {
                'name': 'openclaw',
                'url': 'https://github.com/openclaw/openclaw.git'
            },
            {
                'name': 'langchain',
                'url': 'https://github.com/langchain-ai/langchain.git'
            },
            {
                'name': 'transformers',
                'url': 'https://github.com/huggingface/transformers.git'
            },
            {
                'name': 'tensorflow',
                'url': 'https://github.com/tensorflow/tensorflow.git'
            },
            {
                'name': 'pytorch',
                'url': 'https://github.com/pytorch/pytorch.git'
            },
            {
                'name': 'django',
                'url': 'https://github.com/django/django.git'
            },
            {
                'name': 'flask',
                'url': 'https://github.com/pallets/flask.git'
            },
            {
                'name': 'requests',
                'url': 'https://github.com/psf/requests.git'
            },
            {
                'name': 'scikit-learn',
                'url': 'https://github.com/scikit-learn/scikit-learn.git'
            }
        ]
    
    def clone_project(self, project: Dict[str, str]) -> str:
        """
        克隆项目
        
        Args:
            project: 项目信息
            
        Returns:
            项目路径
        """
        project_dir = os.path.join(self.output_dir, project['name'])
        
        if not os.path.exists(project_dir):
            print(f"克隆项目：{project['name']}")
            try:
                git.Repo.clone_from(project['url'], project_dir)
                print(f"项目 {project['name']} 克隆成功")
            except Exception as e:
                print(f"克隆项目 {project['name']} 失败：{e}")
                return None
        else:
            print(f"项目 {project['name']} 已存在，跳过克隆")
        
        return project_dir
    
    def run_hos_ls(self, project_dir: str, project_name: str) -> Dict[str, Any]:
        """
        运行 HOS-LS
        
        Args:
            project_dir: 项目路径
            project_name: 项目名称
            
        Returns:
            扫描结果
        """
        print(f"运行 HOS-LS 扫描项目：{project_name}")
        
        # 运行 HOS-LS
        hos_ls_path = os.path.join(os.path.dirname(__file__), '..', 'src', 'main.py')
        output_dir = os.path.join(self.output_dir, f'{project_name}_results')
        os.makedirs(output_dir, exist_ok=True)
        
        start_time = time.time()
        
        try:
            # 运行 HOS-LS 命令
            cmd = [
                'python', hos_ls_path,
                project_dir,
                '--output', 'json',
                '--output-dir', output_dir,
                '--silent'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                cwd=os.path.dirname(__file__)
            )
            
            end_time = time.time()
            scan_time = end_time - start_time
            
            # 读取扫描结果
            result_files = [f for f in os.listdir(output_dir) if f.endswith('.json')]
            if result_files:
                result_file = os.path.join(output_dir, result_files[0])
                with open(result_file, 'r', encoding='utf-8') as f:
                    scan_results = json.load(f)
            else:
                scan_results = {}
            
            # 收集性能数据
            performance_data = {
                'scan_time': scan_time,
                'exit_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }
            
            return {
                'project': project_name,
                'performance': performance_data,
                'results': scan_results
            }
        except Exception as e:
            print(f"运行 HOS-LS 失败：{e}")
            return {
                'project': project_name,
                'performance': {
                    'scan_time': time.time() - start_time,
                    'error': str(e)
                },
                'results': {}
            }
    
    def run_all_tests(self) -> List[Dict[str, Any]]:
        """
        运行所有测试
        
        Returns:
            测试结果列表
        """
        test_results = []
        
        for project in self.projects:
            project_dir = self.clone_project(project)
            if project_dir:
                result = self.run_hos_ls(project_dir, project['name'])
                test_results.append(result)
            else:
                test_results.append({
                    'project': project['name'],
                    'error': 'Failed to clone project'
                })
        
        return test_results
    
    def generate_report(self, test_results: List[Dict[str, Any]]) -> str:
        """
        生成测试报告
        
        Args:
            test_results: 测试结果列表
            
        Returns:
            报告文件路径
        """
        report_data = {
            'timestamp': time.time(),
            'projects': test_results,
            'summary': self._calculate_summary(test_results)
        }
        
        report_path = os.path.join(self.output_dir, 'multi_project_test_report.json')
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
        
        print(f"测试报告已生成：{report_path}")
        return report_path
    
    def _calculate_summary(self, test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        计算测试摘要
        
        Args:
            test_results: 测试结果列表
            
        Returns:
            摘要数据
        """
        total_projects = len(test_results)
        successful_projects = 0
        total_scan_time = 0
        total_high_risk = 0
        total_medium_risk = 0
        total_low_risk = 0
        
        for result in test_results:
            if 'error' not in result:
                successful_projects += 1
                if 'performance' in result and 'scan_time' in result['performance']:
                    total_scan_time += result['performance']['scan_time']
                if 'results' in result and 'risk_stats' in result['results']:
                    risk_stats = result['results']['risk_stats']
                    total_high_risk += risk_stats.get('high', 0)
                    total_medium_risk += risk_stats.get('medium', 0)
                    total_low_risk += risk_stats.get('low', 0)
        
        return {
            'total_projects': total_projects,
            'successful_projects': successful_projects,
            'total_scan_time': total_scan_time,
            'average_scan_time': total_scan_time / successful_projects if successful_projects > 0 else 0,
            'total_high_risk': total_high_risk,
            'total_medium_risk': total_medium_risk,
            'total_low_risk': total_low_risk,
            'total_vulnerabilities': total_high_risk + total_medium_risk + total_low_risk
        }

if __name__ == '__main__':
    test = MultiProjectTest()
    results = test.run_all_tests()
    test.generate_report(results)
