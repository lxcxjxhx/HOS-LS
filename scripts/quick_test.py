"""快速测试止损实验"""

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scripts.run_stoploss_experiment import run_experiment, generate_mock_samples
from src.orchestrator import AnalysisMode
from eval.metrics import format_metrics_report


async def main():
    # 生成10个样本测试
    samples = generate_mock_samples(10)
    print(f'Generated {len(samples)} samples')
    
    # 运行实验
    results = await run_experiment(samples, mode=AnalysisMode.FULL)
    
    print('\nResults:')
    print(format_metrics_report(results['metrics'], 'Quick Test'))


if __name__ == "__main__":
    asyncio.run(main())
