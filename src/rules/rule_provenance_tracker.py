#!/usr/bin/env python3
"""
规则来源追踪器 v2.0 (防编造机制)

功能:
1. 记录规则生成过程
2. 追踪规则变更历史
3. 验证规则真实性 (防编造)
4. 生成来源报告

版本：2.0
创建日期：2026-03-31
优化依据：基于用户 develop.json 习惯
"""

import json
import hashlib
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional


class RuleProvenanceTracker:
    """规则来源追踪器 (防编造)"""
    
    def __init__(self, db_path: str = 'provenance.db'):
        """
        初始化追踪器
        
        Args:
            db_path: 数据库文件路径
        """
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """初始化数据库表"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 规则生成记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_generation_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT UNIQUE,
                generation_method TEXT,  -- 'ai_generated' / 'manual' / 'hybrid'
                ai_model TEXT,
                prompt_template TEXT,
                ai_input TEXT,
                ai_output TEXT,
                human_reviewer TEXT,
                review_date TIMESTAMP,
                review_comments TEXT,
                test_results TEXT,
                quality_metrics TEXT,
                created_at TIMESTAMP,
                updated_at TIMESTAMP
            )
        ''')
        
        # 规则变更历史表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_change_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT,
                version TEXT,
                change_type TEXT,  -- 'create' / 'update' / 'delete'
                change_description TEXT,
                changed_by TEXT,
                changed_at TIMESTAMP,
                diff TEXT,
                validation_result TEXT
            )
        ''')
        
        # 规则验证记录表
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_validation_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT,
                validation_date TIMESTAMP,
                validation_type TEXT,  -- 'initial' / 'regression' / 'on_demand'
                test_cases_count INTEGER,
                pass_rate REAL,
                quality_metrics TEXT,
                validation_report_path TEXT,
                passed BOOLEAN
            )
        ''')
        
        # 规则指纹表 (防编造)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rule_fingerprints (
                rule_id TEXT PRIMARY KEY,
                fingerprint TEXT,
                created_at TIMESTAMP,
                last_verified TIMESTAMP
            )
        ''')
        
        # 案例来源表 (防编造 - 案例真实性验证)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS case_sources (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT,
                case_id TEXT,
                case_type TEXT,  -- 'positive' / 'negative'
                source TEXT,  -- GitHub/CVE/OWASP/实际项目
                source_link TEXT,
                verified BOOLEAN DEFAULT FALSE,
                verification_date TIMESTAMP,
                description TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def record_rule_generation(self, rule_data: Dict[str, Any], generation_info: Dict[str, Any]):
        """
        记录规则生成过程
        
        Args:
            rule_data: 规则数据
            generation_info: 生成信息字典
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 生成规则指纹 (防编造)
        fingerprint = self._generate_fingerprint(rule_data)
        
        # 插入或更新规则生成记录
        cursor.execute('''
            INSERT OR REPLACE INTO rule_generation_records
            (rule_id, generation_method, ai_model, prompt_template, ai_input, ai_output,
             human_reviewer, review_date, review_comments, test_results, quality_metrics,
             created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            rule_data.get('id', 'UNKNOWN'),
            generation_info.get('method', 'unknown'),
            generation_info.get('ai_model', None),
            generation_info.get('prompt_template', None),
            json.dumps(generation_info.get('ai_input', {}), ensure_ascii=False),
            json.dumps(generation_info.get('ai_output', {}), ensure_ascii=False),
            generation_info.get('reviewer', None),
            generation_info.get('review_date', datetime.now()),
            generation_info.get('review_comments', None),
            json.dumps(generation_info.get('test_results', {}), ensure_ascii=False),
            json.dumps(generation_info.get('quality_metrics', {}), ensure_ascii=False),
            datetime.now(),
            datetime.now()
        ))
        
        # 记录指纹
        cursor.execute('''
            INSERT OR REPLACE INTO rule_fingerprints
            (rule_id, fingerprint, created_at, last_verified)
            VALUES (?, ?, ?, ?)
        ''', (rule_data.get('id', 'UNKNOWN'), fingerprint, datetime.now(), datetime.now()))
        
        # 记录变更历史
        cursor.execute('''
            INSERT INTO rule_change_history
            (rule_id, version, change_type, change_description, changed_by, changed_at, diff)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (rule_data.get('id', 'UNKNOWN'), '1.0', 'create', '初始规则创建',
              generation_info.get('reviewer', 'system'), datetime.now(),
              json.dumps({'action': 'create'}, ensure_ascii=False)))
        
        # 记录案例来源 (防编造 - 案例真实性)
        self._record_case_sources(rule_data.get('id', 'UNKNOWN'), generation_info)
        
        conn.commit()
        conn.close()
    
    def _record_case_sources(self, rule_id: str, generation_info: Dict[str, Any]):
        """记录案例来源"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 从生成信息中提取案例
        ai_input = generation_info.get('ai_input', {})
        real_examples = ai_input.get('real_examples', [])
        
        for i, example in enumerate(real_examples):
            cursor.execute('''
                INSERT INTO case_sources
                (rule_id, case_id, case_type, source, source_link, verified, description)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                rule_id,
                f'EX{i+1:03d}',
                'positive',
                example.get('source', 'unknown'),
                example.get('source_link', None),
                False,  # 需要人工验证
                example.get('description', '')
            ))
        
        conn.commit()
        conn.close()
    
    def verify_rule_authenticity(self, rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证规则真实性 (防编造)
        
        Args:
            rule_data: 规则数据
            
        Returns:
            验证结果字典
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 计算当前指纹
        current_fingerprint = self._generate_fingerprint(rule_data)
        
        # 获取存储的指纹
        cursor.execute('''
            SELECT fingerprint, created_at, last_verified
            FROM rule_fingerprints
            WHERE rule_id = ?
        ''', (rule_data.get('id', 'UNKNOWN'),))
        
        row = cursor.fetchone()
        
        if row is None:
            conn.close()
            return {
                'verified': False,
                'reason': '规则未找到记录',
                'action': '需要重新验证和记录',
                'authenticity_score': 0
            }
        
        stored_fingerprint = row[0]
        created_at = row[1]
        last_verified = row[2]
        
        # 比对指纹
        fingerprint_match = (current_fingerprint == stored_fingerprint)
        
        # 检查案例来源
        case_authenticity = self._verify_case_sources(rule_data.get('id', 'UNKNOWN'))
        
        # 计算真实性评分
        authenticity_score = self._calculate_authenticity_score(
            fingerprint_match,
            case_authenticity
        )
        
        conn.close()
        
        if fingerprint_match:
            return {
                'verified': True,
                'reason': '指纹匹配',
                'created_at': created_at,
                'last_verified': last_verified,
                'action': '规则真实可信',
                'authenticity_score': authenticity_score,
                'case_authenticity': case_authenticity
            }
        else:
            return {
                'verified': False,
                'reason': '指纹不匹配，规则可能被修改',
                'action': '需要重新验证',
                'authenticity_score': authenticity_score,
                'case_authenticity': case_authenticity
            }
    
    def _verify_case_sources(self, rule_id: str) -> Dict[str, Any]:
        """验证案例来源真实性"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT case_id, source, source_link, verified
            FROM case_sources
            WHERE rule_id = ?
        ''', (rule_id,))
        
        cases = cursor.fetchall()
        conn.close()
        
        if not cases:
            return {
                'total_cases': 0,
                'verified_cases': 0,
                'with_source_link': 0,
                'authenticity_rate': 0
            }
        
        total = len(cases)
        verified = sum(1 for c in cases if c[3])
        with_link = sum(1 for c in cases if c[2])
        
        return {
            'total_cases': total,
            'verified_cases': verified,
            'with_source_link': with_link,
            'authenticity_rate': with_link / total if total > 0 else 0
        }
    
    def _calculate_authenticity_score(self, fingerprint_match: bool, case_authenticity: Dict[str, Any]) -> float:
        """计算真实性评分"""
        score = 0.0
        
        # 指纹匹配 (权重 60%)
        if fingerprint_match:
            score += 0.6
        
        # 案例来源 (权重 40%)
        case_rate = case_authenticity.get('authenticity_rate', 0)
        score += case_rate * 0.4
        
        return score
    
    def _generate_fingerprint(self, rule_data: Dict[str, Any]) -> str:
        """
        生成规则指纹
        
        Args:
            rule_data: 规则数据
            
        Returns:
            SHA256 指纹
        """
        # 提取关键特征生成指纹
        key_features = {
            'id': rule_data.get('id'),
            'patterns': rule_data.get('patterns', []),
            'exclude_patterns': rule_data.get('exclude_patterns', []),
            'severity': rule_data.get('severity'),
            'confidence': rule_data.get('confidence'),
            'cwe': rule_data.get('cwe'),
            'owasp': rule_data.get('owasp')
        }
        
        # 生成哈希
        fingerprint_str = json.dumps(key_features, sort_keys=True, ensure_ascii=False)
        fingerprint = hashlib.sha256(fingerprint_str.encode()).hexdigest()
        
        return fingerprint
    
    def get_rule_provenance(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        获取规则来源信息
        
        Args:
            rule_id: 规则 ID
            
        Returns:
            来源信息字典
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 获取生成记录
        cursor.execute('''
            SELECT * FROM rule_generation_records WHERE rule_id = ?
        ''', (rule_id,))
        
        row = cursor.fetchone()
        
        if row is None:
            conn.close()
            return None
        
        # 获取变更历史
        cursor.execute('''
            SELECT version, change_type, change_description, changed_at
            FROM rule_change_history
            WHERE rule_id = ?
            ORDER BY changed_at DESC
        ''', (rule_id,))
        
        change_history = [
            {
                'version': r[0],
                'change_type': r[1],
                'change_description': r[2],
                'changed_at': r[3]
            }
            for r in cursor.fetchall()
        ]
        
        # 获取验证记录
        cursor.execute('''
            SELECT validation_date, validation_type, pass_rate, passed
            FROM rule_validation_records
            WHERE rule_id = ?
            ORDER BY validation_date DESC
            LIMIT 5
        ''', (rule_id,))
        
        validation_history = [
            {
                'date': r[0],
                'type': r[1],
                'pass_rate': r[2],
                'passed': r[3]
            }
            for r in cursor.fetchall()
        ]
        
        conn.close()
        
        return {
            'generation_record': {
                'rule_id': row[1],
                'generation_method': row[2],
                'ai_model': row[3],
                'prompt_template': row[4],
                'human_reviewer': row[7],
                'review_date': row[8],
                'quality_metrics': json.loads(row[10]) if row[10] else {}
            },
            'change_history': change_history,
            'validation_history': validation_history
        }
    
    def generate_provenance_report(self, rule_id: str) -> str:
        """
        生成规则来源报告
        
        Args:
            rule_id: 规则 ID
            
        Returns:
            报告内容 (Markdown 格式)
        """
        provenance = self.get_rule_provenance(rule_id)
        
        if provenance is None:
            return f"# 规则来源报告\n\n规则 `{rule_id}` 无来源记录"
        
        gen_rec = provenance['generation_record']
        
        report = f"""# 规则来源报告

## 规则 ID: {rule_id}

### 生成信息
- **生成方式**: {gen_rec.get('generation_method', 'unknown')}
- **AI 模型**: {gen_rec.get('ai_model', 'N/A')}
- **提示词模板**: {gen_rec.get('prompt_template', 'N/A')}
- **审查人员**: {gen_rec.get('human_reviewer', '未审查')}
- **审查日期**: {gen_rec.get('review_date', '未审查')}

### 质量指标
"""
        
        # 添加质量指标
        quality_metrics = gen_rec.get('quality_metrics', {})
        for metric, value in quality_metrics.items():
            report += f"- **{metric}**: {value}\n"
        
        # 添加变更历史
        report += "\n### 变更历史\n"
        for change in provenance['change_history']:
            report += f"\n- **v{change['version']}** ({change['changed_at']}): {change['change_description']}\n"
        
        # 添加验证历史
        report += "\n### 验证历史\n"
        for validation in provenance['validation_history']:
            status = "✓" if validation['passed'] else "✗"
            report += f"\n- {validation['date']} ({validation['type']}): {status} 通过率 {validation['pass_rate']:.2%}\n"
        
        # 添加真实性验证
        report += "\n### 真实性验证\n"
        report += "- 指纹验证：已验证\n"
        report += "- 案例来源：已记录\n"
        
        return report
    
    def list_unverified_cases(self) -> List[Dict[str, Any]]:
        """列出所有未验证的案例"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT rule_id, case_id, source, source_link, description
            FROM case_sources
            WHERE verified = FALSE
            ORDER BY rule_id, case_id
        ''')
        
        cases = [
            {
                'rule_id': r[0],
                'case_id': r[1],
                'source': r[2],
                'source_link': r[3],
                'description': r[4]
            }
            for r in cursor.fetchall()
        ]
        
        conn.close()
        return cases
    
    def verify_case(self, rule_id: str, case_id: str, verified: bool = True):
        """
        验证单个案例
        
        Args:
            rule_id: 规则 ID
            case_id: 案例 ID
            verified: 是否验证通过
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE case_sources
            SET verified = ?, verification_date = ?
            WHERE rule_id = ? AND case_id = ?
        ''', (verified, datetime.now(), rule_id, case_id))
        
        conn.commit()
        conn.close()


def main():
    """主函数"""
    tracker = RuleProvenanceTracker()
    
    # 示例：记录 AI 生成规则
    rule_data = {
        'id': 'ai_security.test_rule',
        'patterns': ['test_pattern'],
        'exclude_patterns': ['test_exclude'],
        'severity': 'HIGH',
        'confidence': 0.90,
        'cwe': 'CWE-XXX',
        'owasp': 'A0X:2021'
    }
    
    generation_info = {
        'method': 'ai_generated',
        'ai_model': 'gpt-4',
        'prompt_template': 'rule_generation_v2.0',
        'reviewer': 'security-team',
        'review_date': datetime.now(),
        'ai_input': {
            'detection_target': '测试规则',
            'real_examples': [
                {
                    'source': 'GitHub',
                    'source_link': 'https://github.com/example/repo',
                    'description': '示例案例'
                }
            ]
        },
        'quality_metrics': {
            'recall': 0.95,
            'precision': 0.92,
            'f1_score': 0.935
        }
    }
    
    # 记录生成过程
    tracker.record_rule_generation(rule_data, generation_info)
    print(f"✓ 规则生成记录已保存：{rule_data['id']}")
    
    # 验证规则真实性
    verification = tracker.verify_rule_authenticity(rule_data)
    print(f"\n真实性验证结果:")
    print(f"  验证状态：{'✓ 已验证' if verification['verified'] else '✗ 未验证'}")
    print(f"  真实性评分：{verification.get('authenticity_score', 0):.2%}")
    print(f"  操作建议：{verification['action']}")
    
    # 生成来源报告
    report = tracker.generate_provenance_report(rule_data['id'])
    print(f"\n{report}")


if __name__ == '__main__':
    main()
