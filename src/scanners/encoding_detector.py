#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
编码检测模块

功能：
1. Base64 编码识别与解码
2. Hex 编码识别
3. URL 编码识别
4. 多重编码检测
5. 编码后敏感信息检测
"""

import re
import base64
import binascii
from typing import List, Tuple, Optional, Dict, Any


class EncodingDetector:
    """编码检测器"""
    
    def __init__(self):
        # Base64 模式（标准、URL-safe）
        self.base64_patterns = [
            r'[A-Za-z0-9+/]{20,}={0,2}',  # 标准 Base64
            r'[A-Za-z0-9-_]{20,}={0,2}',  # URL-safe Base64
        ]
        
        # Hex 模式
        self.hex_patterns = [
            r'\b0x[0-9a-fA-F]{32,}\b',
            r'\b[0-9a-fA-F]{32,}\b',
        ]
        
        # URL 编码模式
        self.url_patterns = [
            r'%[0-9a-fA-F]{2}',
        ]
        
        # 敏感信息模式（用于解码后检测）
        self.secret_patterns = [
            r'(?i)(api[_\s-]?key|api[_\s-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']',
            r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']([^"\']{4,})["\']',
            r'(?i)(secret|private[_\s-]?key)\s*[:=]\s*["\']([^"\']{8,})["\']',
        ]
    
    def detect_base64(self, content: str) -> List[Dict[str, Any]]:
        """检测 Base64 编码"""
        results = []
        
        for pattern in self.base64_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                encoded_str = match.group(0)
                
                # 尝试解码
                try:
                    # 标准 Base64
                    decoded = base64.b64decode(encoded_str).decode('utf-8', errors='ignore')
                    
                    # 检查解码后是否包含敏感信息
                    if self._contains_secret(decoded):
                        results.append({
                            'type': 'base64',
                            'encoded': encoded_str,
                            'decoded': decoded,
                            'line': content[:match.start()].count('\n') + 1,
                            'confidence': 0.85,
                            'issue': 'Base64 编码的敏感信息'
                        })
                except Exception:
                    pass
                
                # 尝试 URL-safe Base64
                try:
                    decoded = base64.urlsafe_b64decode(encoded_str).decode('utf-8', errors='ignore')
                    if self._contains_secret(decoded):
                        results.append({
                            'type': 'urlsafe_base64',
                            'encoded': encoded_str,
                            'decoded': decoded,
                            'line': content[:match.start()].count('\n') + 1,
                            'confidence': 0.85,
                            'issue': 'URL-safe Base64 编码的敏感信息'
                        })
                except Exception:
                    pass
        
        return results
    
    def detect_hex(self, content: str) -> List[Dict[str, Any]]:
        """检测 Hex 编码"""
        results = []
        
        for pattern in self.hex_patterns:
            matches = re.finditer(pattern, content)
            for match in matches:
                hex_str = match.group(0)
                
                # 移除 0x 前缀
                if hex_str.startswith('0x'):
                    hex_str = hex_str[2:]
                
                try:
                    decoded = bytes.fromhex(hex_str).decode('utf-8', errors='ignore')
                    
                    if self._contains_secret(decoded):
                        results.append({
                            'type': 'hex',
                            'encoded': match.group(0),
                            'decoded': decoded,
                            'line': content[:match.start()].count('\n') + 1,
                            'confidence': 0.80,
                            'issue': 'Hex 编码的敏感信息'
                        })
                except Exception:
                    pass
        
        return results
    
    def detect_url_encoding(self, content: str) -> List[Dict[str, Any]]:
        """检测 URL 编码"""
        results = []
        
        # 查找连续的 URL 编码
        pattern = r'(%[0-9a-fA-F]{2}){3,}'
        matches = re.finditer(pattern, content)
        
        for match in matches:
            url_encoded = match.group(0)
            
            try:
                from urllib.parse import unquote
                decoded = unquote(url_encoded)
                
                if self._contains_secret(decoded):
                    results.append({
                        'type': 'url',
                        'encoded': url_encoded,
                        'decoded': decoded,
                        'line': content[:match.start()].count('\n') + 1,
                        'confidence': 0.75,
                        'issue': 'URL 编码的敏感信息'
                    })
            except Exception:
                pass
        
        return results
    
    def detect_multiple_encoding(self, content: str) -> List[Dict[str, Any]]:
        """检测多重编码"""
        results = []
        
        # 检测 Base64 + Hex
        base64_results = self.detect_base64(content)
        for result in base64_results:
            decoded = result['decoded']
            
            # 检查解码后是否还有 Hex 编码
            hex_results = self.detect_hex(decoded)
            if hex_results:
                result['multiple_encoding'] = ['base64', 'hex']
                result['final_decoded'] = hex_results[0]['decoded']
                result['confidence'] = 0.90
                results.append(result)
        
        return results
    
    def _contains_secret(self, text: str) -> bool:
        """检查文本是否包含敏感信息"""
        for pattern in self.secret_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def scan(self, content: str) -> List[Dict[str, Any]]:
        """执行完整编码扫描"""
        all_results = []
        
        # 检测各种编码
        all_results.extend(self.detect_base64(content))
        all_results.extend(self.detect_hex(content))
        all_results.extend(self.detect_url_encoding(content))
        all_results.extend(self.detect_multiple_encoding(content))
        
        return all_results


if __name__ == '__main__':
    # 测试编码检测器
    test_content = """
    # Base64 编码的 API Key
    api_key = base64.b64decode("c2tfdGVzdF9hcGlfa2V5XzEyMzQ1Njc4OTA=").decode()
    
    # Hex 编码的密码
    password = bytes.fromhex("746573745f70617373776f7264").decode()
    """
    
    detector = EncodingDetector()
    results = detector.scan(test_content)
    
    for result in results:
        print(f"类型：{result['type']}")
        print(f"编码：{result['encoded']}")
        print(f"解码：{result['decoded']}")
        print(f"问题：{result['issue']}")
        print(f"置信度：{result['confidence']}")
        print()
