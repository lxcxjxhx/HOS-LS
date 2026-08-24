"""简单测试"""

import asyncio
import os
import sys
from pathlib import Path

# 添加项目路径
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.orchestrator import Orchestrator, PatchTriplet, AnalysisMode


async def test():
    """测试简单分析"""
    orchestrator = Orchestrator(
        api_key=os.getenv('DEEPSEEK_API_KEY'),
        base_url='https://token-plan-cn.xiaomimimo.com/v1',
        model='mimo-v2.5-pro',
        mode=AnalysisMode.LOCATOR_ONLY,  # 只运行定位员
    )
    
    delta_ai = "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,3 @@\n def query(user_input):\n-    sql = \"SELECT * FROM users WHERE name = '\" + user_input + \"'\"\n+    sql = \"SELECT * FROM users WHERE name = %s\"\n+    return execute(sql, (user_input,))"
    
    triplet = PatchTriplet(
        r_before='/tmp/test',
        task_desc='Fix SQL injection vulnerability in user query function',
        delta_ai=delta_ai,
        sample_id='test_001',
    )
    
    print('Running analysis...')
    report = await orchestrator.analyze(triplet)
    print(f'Vulnerability found: {report.vulnerability_found}')
    print(f'Confidence: {report.confidence}')
    print(f'Summary: {report.summary[:200]}')
    print(f'Cache stats: {orchestrator.get_cache_stats()}')


if __name__ == "__main__":
    asyncio.run(test())
