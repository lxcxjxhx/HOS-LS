import asyncio
import httpx
import difflib
from typing import List, Dict, Any, Optional

class Validator:
    def __init__(self):
        """
        初始化验证器
        """
        self.client = httpx.AsyncClient(timeout=30.0)
    
    async def validate_vulnerabilities(self, exploits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        验证漏洞
        
        Args:
            exploits: exploit列表
            
        Returns:
            验证结果
        """
        tasks = []
        for exploit in exploits:
            task = self._validate_exploit(exploit)
            tasks.append(task)
        
        results = await asyncio.gather(*tasks)
        return results
    
    async def _validate_exploit(self, exploit: Dict[str, Any]) -> Dict[str, Any]:
        """
        验证单个exploit
        """
        vuln_type = exploit.get("vulnerability_type")
        payloads = exploit.get("payloads", [])
        exploit_code = exploit.get("exploit_code")
        
        # 根据漏洞类型选择验证方法
        if vuln_type == "sqli":
            result = await self._validate_sqli(payloads)
        elif vuln_type == "xss":
            result = await self._validate_xss(payloads)
        elif vuln_type == "command_injection":
            result = await self._validate_command_injection(payloads)
        elif vuln_type == "eval_injection":
            result = await self._validate_eval_injection(payloads)
        else:
            result = {
                "valid": False,
                "message": f"No validation method for {vuln_type}",
                "details": []
            }
        
        return {
            **exploit,
            "validation": result
        }
    
    async def _validate_sqli(self, payloads: List[str]) -> Dict[str, Any]:
        """
        验证SQL注入漏洞
        """
        # 这里使用示例目标，实际使用时需要从exploit中提取
        target_url = "http://target.com/vulnerable.php"
        
        details = []
        valid = False
        
        for payload in payloads:
            # 发送正常请求
            normal_response = await self.client.get(target_url, params={"id": "1"})
            normal_content = normal_response.text
            
            # 发送攻击请求
            attack_response = await self.client.get(target_url, params={"id": payload})
            attack_content = attack_response.text
            
            # 比较响应
            diff_ratio = difflib.SequenceMatcher(None, normal_content, attack_content).ratio()
            
            # 检查是否有明显差异
            if diff_ratio < 0.9 or "error" in attack_content.lower() or len(attack_content) > len(normal_content) * 1.5:
                details.append({
                    "payload": payload,
                    "valid": True,
                    "diff_ratio": diff_ratio,
                    "response_length": len(attack_content)
                })
                valid = True
            else:
                details.append({
                    "payload": payload,
                    "valid": False,
                    "diff_ratio": diff_ratio,
                    "response_length": len(attack_content)
                })
        
        return {
            "valid": valid,
            "message": "SQL injection validation completed",
            "details": details
        }
    
    async def _validate_xss(self, payloads: List[str]) -> Dict[str, Any]:
        """
        验证XSS漏洞
        """
        target_url = "http://target.com/vulnerable.php"
        
        details = []
        valid = False
        
        for payload in payloads:
            # 发送攻击请求
            response = await self.client.get(target_url, params={"search": payload})
            content = response.text
            
            # 检查payload是否在响应中
            if payload in content:
                details.append({
                    "payload": payload,
                    "valid": True,
                    "found_in_response": True
                })
                valid = True
            else:
                details.append({
                    "payload": payload,
                    "valid": False,
                    "found_in_response": False
                })
        
        return {
            "valid": valid,
            "message": "XSS validation completed",
            "details": details
        }
    
    async def _validate_command_injection(self, payloads: List[str]) -> Dict[str, Any]:
        """
        验证命令注入漏洞
        """
        target_url = "http://target.com/vulnerable.php"
        
        details = []
        valid = False
        
        for payload in payloads:
            # 发送攻击请求
            response = await self.client.get(target_url, params={"ip": f"127.0.0.1{payload}"})
            content = response.text
            
            # 检查是否有命令执行的迹象
            if "root" in content or "www-data" in content or "uid=" in content or "gid=" in content:
                details.append({
                    "payload": payload,
                    "valid": True,
                    "command_executed": True
                })
                valid = True
            else:
                details.append({
                    "payload": payload,
                    "valid": False,
                    "command_executed": False
                })
        
        return {
            "valid": valid,
            "message": "Command injection validation completed",
            "details": details
        }
    
    async def _validate_eval_injection(self, payloads: List[str]) -> Dict[str, Any]:
        """
        验证eval注入漏洞
        """
        target_url = "http://target.com/vulnerable.php"
        
        details = []
        valid = False
        
        for payload in payloads:
            # 发送攻击请求
            response = await self.client.get(target_url, params={"code": payload})
            content = response.text
            
            # 检查是否有命令执行的迹象
            if "root" in content or "www-data" in content or "uid=" in content or "gid=" in content:
                details.append({
                    "payload": payload,
                    "valid": True,
                    "command_executed": True
                })
                valid = True
            else:
                details.append({
                    "payload": payload,
                    "valid": False,
                    "command_executed": False
                })
        
        return {
            "valid": valid,
            "message": "Eval injection validation completed",
            "details": details
        }
    
    def validate_local_code(self, code: str, vuln_type: str) -> Dict[str, Any]:
        """
        验证本地代码中的漏洞
        
        Args:
            code: 代码内容
            vuln_type: 漏洞类型
            
        Returns:
            验证结果
        """
        details = []
        valid = False
        
        if vuln_type == "sqli":
            # 检查SQL注入
            if "execute(" in code and "%s" not in code and "?" not in code:
                details.append({
                    "pattern": "Direct SQL execution without parameterization",
                    "found": True
                })
                valid = True
        elif vuln_type == "xss":
            # 检查XSS
            if "echo" in code and "htmlspecialchars" not in code:
                details.append({
                    "pattern": "Direct output without HTML escaping",
                    "found": True
                })
                valid = True
        elif vuln_type == "command_injection":
            # 检查命令注入
            if "system(" in code or "exec(" in code or "shell_exec(" in code:
                details.append({
                    "pattern": "Direct command execution",
                    "found": True
                })
                valid = True
        elif vuln_type == "eval_injection":
            # 检查eval注入
            if "eval(" in code or "exec(" in code:
                details.append({
                    "pattern": "Direct eval/exec execution",
                    "found": True
                })
                valid = True
        
        return {
            "valid": valid,
            "message": "Local code validation completed",
            "details": details
        }
    
    async def close(self):
        """
        关闭HTTP客户端
        """
        await self.client.aclose()
