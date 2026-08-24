"""测试API连接"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.orchestrator import LLMClient


async def test():
    client = LLMClient(
        api_key=os.getenv('DEEPSEEK_API_KEY'),
        base_url='https://token-plan-cn.xiaomimimo.com/v1',
        model='mimo-v2.5-pro',
    )
    
    prompt = """Analyze this code patch for security vulnerabilities:

--- a/cmd.py
+++ b/cmd.py
-    os.system(cmd)
+    subprocess.run(cmd.split())

Does this patch introduce or fix a vulnerability?"""
    
    print('Testing LLM client...')
    response = await client.generate(prompt)
    print(f'Response: {response[:500]}')


if __name__ == "__main__":
    asyncio.run(test())
