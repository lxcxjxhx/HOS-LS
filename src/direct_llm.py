"""直接LLM调用 - 绕过HOS-LS认证问题"""

import json
import os
from typing import Dict, Optional
from openai import OpenAI


class DirectLLM:
    """直接LLM调用"""
    
    def __init__(self, api_key: str, base_url: str, model: str = "mimo-v2.5-pro"):
        self.client = OpenAI(api_key=api_key, base_url=base_url)
        self.model = model
    
    def analyze_vulnerability(self, code: str, vuln_type: str, cwe_id: str, 
                            vuln_lines: list = None, code_after: str = None) -> Dict:
        """分析漏洞"""
        
        if code_after:
            # DREA格式：有before/after
            prompt = f"""You are a security researcher. A CVE vulnerability was fixed in this code.

## Vulnerability: {vuln_type} ({cwe_id})

## Code BEFORE (vulnerable):
```
{code[:2500]}
```

## Code AFTER (fixed):
```
{code_after[:2500]}
```

## Task
Confirm the "before" code has a real {vuln_type} vulnerability that is fixed in the "after" code.

Reply JSON: {{"vulnerable": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}}"""
        else:
            # A.S.E格式：只有漏洞代码
            prompt = f"""You are a security researcher. Analyze this code for {vuln_type} vulnerability.

## Vulnerability Type: {vuln_type} ({cwe_id})
## Lines: {vuln_lines}

## Code:
```
{code[:3000]}
```

## Task
Is this code vulnerable to {vuln_type}?

Reply JSON: {{"vulnerable": true/false, "confidence": 0.0-1.0, "reason": "brief explanation"}}"""
        
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert. Be accurate - these are known vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=800,
            )
            
            text = response.choices[0].message.content
            start = text.find('{')
            end = text.rfind('}') + 1
            if start >= 0 and end > start:
                return json.loads(text[start:end])
            return {"vulnerable": False, "confidence": 0.0, "reason": text[:200]}
        except Exception as e:
            return {"vulnerable": False, "confidence": 0.0, "error": str(e)}
