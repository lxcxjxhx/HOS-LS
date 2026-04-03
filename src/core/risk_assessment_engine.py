#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
风险评估引擎

功能：
1. 计算 Hybrid Risk Score
2. 融合传统规则评分和 AI 语义评分
3. 生成风险评估报告
"""

import os
import json
import time
from typing import List, Dict, Any, Optional

class RiskAssessmentEngine:
    def __init__(self, traditional_weight: float = 0.4, ai_weight: float = 0.6):
        """
        初始化风险评估引擎
        
        Args:
            traditional_weight: 传统规则评分权重
            ai_weight: AI 语义评分权重
        """
        self.traditional_weight = traditional_weight
        self.ai_weight = ai_weight
        
    def calculate_hybrid_score(self, traditional_score: float, ai_score: float) -> float:
        """
        计算混合风险评分
        
        Args:
            traditional_score: 传统规则评分 (0-100)
            ai_score: AI 语义评分 (0-100)
            
        Returns:
            混合风险评分 (0-100)
        """
        hybrid_score = (
            self.traditional_weight * traditional_score +
            self.ai_weight * ai_score
        )
        return min(max(hybrid_score, 0), 100)
    
    def calculate_traditional_score(self, issues: List[Dict[str, Any]]) -> float:
        """
        计算传统规则评分
        
        Args:
            issues: 传统规则检测到的问题列表
            
        Returns:
            传统规则评分 (0-100)
        """
        if not issues:
            return 0.0
        
        # 计算严重程度权重
        severity_weights = {
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0
        }
        
        total_score = 0.0
        max_possible_score = 0.0
        
        for issue in issues:
            severity = issue.get('severity', 'low')
            confidence = issue.get('confidence', 0.7)
            
            weight = severity_weights.get(severity, 1.0)
            score = weight * confidence
            
            total_score += score
            max_possible_score += weight
        
        if max_possible_score > 0:
            traditional_score = (total_score / max_possible_score) * 100
        else:
            traditional_score = 0.0
        
        return traditional_score
    
    def calculate_ai_score(self, ai_analysis: Dict[str, Any]) -> float:
        """
        计算 AI 语义评分
        
        Args:
            ai_analysis: AI 语义分析结果
            
        Returns:
            AI 语义评分 (0-100)
        """
        if not ai_analysis:
            return 0.0
        
        # 计算 AI 分析中的风险
        total_risk = 0.0
        risk_count = 0
        
        # 检查不同层次的分析结果
        for level in ['function_level', 'file_level', 'project_level']:
            if level in ai_analysis:
                level_data = ai_analysis[level]
                if isinstance(level_data, list):
                    for item in level_data:
                        if 'analysis' in item:
                            analysis = item['analysis']
                            if 'vulnerabilities' in analysis:
                                for vuln in analysis['vulnerabilities']:
                                    severity = vuln.get('severity', 'low')
                                    if severity == 'high':
                                        total_risk += 3.0
                                    elif severity == 'medium':
                                        total_risk += 2.0
                                    else:
                                        total_risk += 1.0
                                    risk_count += 1
        
        # 检查项目级风险
        if 'project_level' in ai_analysis:
            project_data = ai_analysis['project_level']
            if 'overall_risk' in project_data:
                overall_risk = project_data['overall_risk']
                if overall_risk == 'High':
                    total_risk += 5.0
                elif overall_risk == 'Medium':
                    total_risk += 3.0
                else:
                    total_risk += 1.0
                risk_count += 1
        
        if risk_count > 0:
            # 归一化到 0-100
            ai_score = min((total_risk / (risk_count * 3.0)) * 100, 100)
        else:
            ai_score = 0.0
        
        return ai_score
    
    def assess_risk(self, traditional_issues: List[Dict[str, Any]], ai_analysis: Dict[str, Any]) -> Dict[str, Any]:
        """
        评估整体风险
        
        Args:
            traditional_issues: 传统规则检测到的问题列表
            ai_analysis: AI 语义分析结果
            
        Returns:
            风险评估结果
        """
        # 计算传统规则评分
        traditional_score = self.calculate_traditional_score(traditional_issues)
        
        # 计算 AI 语义评分
        ai_score = self.calculate_ai_score(ai_analysis)
        
        # 计算混合风险评分
        hybrid_score = self.calculate_hybrid_score(traditional_score, ai_score)
        
        # 确定风险等级
        risk_level = self._get_risk_level(hybrid_score)
        
        # 生成风险评估结果
        assessment = {
            'traditional_score': traditional_score,
            'ai_score': ai_score,
            'hybrid_score': hybrid_score,
            'risk_level': risk_level,
            'timestamp': time.time(),
            'weighting': {
                'traditional': self.traditional_weight,
                'ai': self.ai_weight
            }
        }
        
        return assessment
    
    def _get_risk_level(self, score: float) -> str:
        """
        根据评分确定风险等级
        
        Args:
            score: 风险评分
            
        Returns:
            风险等级
        """
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "None"
    
    def generate_risk_report(self, assessment: Dict[str, Any], output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        生成风险评估报告
        
        Args:
            assessment: 风险评估结果
            output_path: 输出文件路径
            
        Returns:
            风险评估报告
        """
        report = {
            "risk_assessment": assessment,
            "recommendations": self._generate_recommendations(assessment),
            "timestamp": time.time()
        }
        
        # 保存报告
        if output_path:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"风险评估报告已保存到：{output_path}")
        
        return report
    
    def _generate_recommendations(self, assessment: Dict[str, Any]) -> List[str]:
        """
        生成安全建议
        
        Args:
            assessment: 风险评估结果
            
        Returns:
            安全建议列表
        """
        risk_level = assessment.get('risk_level', 'None')
        recommendations = []
        
        if risk_level == "Critical":
            recommendations.append("立即修复所有高风险漏洞")
            recommendations.append("进行全面的安全审计")
            recommendations.append("实施更严格的安全测试流程")
            recommendations.append("考虑引入专业安全团队进行评估")
        elif risk_level == "High":
            recommendations.append("优先修复高风险漏洞")
            recommendations.append("加强安全测试")
            recommendations.append("定期进行安全扫描")
        elif risk_level == "Medium":
            recommendations.append("修复中风险漏洞")
            recommendations.append("改进安全编码实践")
            recommendations.append("定期进行安全培训")
        elif risk_level == "Low":
            recommendations.append("修复低风险漏洞")
            recommendations.append("保持安全意识")
        else:
            recommendations.append("保持当前的安全实践")
            recommendations.append("定期进行安全检查")
        
        return recommendations
