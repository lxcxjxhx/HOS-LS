"""cost_estimator 与 balance 模块单元测试。"""

import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, ".")

from src.ai.cost_estimator import (
    DEFAULT_AVG_TOKENS_PER_FILE,
    CostEstimate,
    CostEstimator,
    get_cost_estimator,
)
from src.ai.balance import BalanceInfo, _is_loop_running


class TestCostEstimator(unittest.TestCase):
    def test_estimate_defaults(self):
        est = get_cost_estimator().estimate(10, "deepseek", "deepseek-v4-flash")
        self.assertIsInstance(est, CostEstimate)
        self.assertEqual(est.file_count, 10)
        self.assertEqual(est.avg_tokens_per_file, DEFAULT_AVG_TOKENS_PER_FILE)
        # 10 文件 × 默认均值（2026-08-16 实测校准 70,807）
        self.assertEqual(est.estimated_total_tokens, DEFAULT_AVG_TOKENS_PER_FILE * 10)
        self.assertGreater(est.estimated_total_cost_usd, 0)
        # 兼容 scanner 的字段名
        self.assertEqual(est.estimated_total_cost, est.estimated_total_cost_usd)
        self.assertIn("deepseek-v4-flash", est.pricing_source)
        # 费用上界说明（缓存未命中）
        self.assertIn("缓存", est.pricing_source)

    def test_estimate_custom_avg(self):
        est = CostEstimator().estimate(5, "deepseek", "deepseek-chat", avg_tokens_per_file=1000)
        self.assertEqual(est.estimated_total_tokens, 5000)
        self.assertFalse(est.using_history)

    def test_estimate_history_calibration(self):
        """有历史统计时用历史均值校准。"""
        fake_stats = {"avg_total_tokens": 12345}
        with patch.object(
            CostEstimator, "_history_avg_tokens_per_file", return_value=12345.0
        ):
            est = CostEstimator().estimate(3, "deepseek", "deepseek-v4-flash")
            self.assertEqual(est.avg_tokens_per_file, 12345)
            self.assertEqual(est.estimated_total_tokens, 37035)
            self.assertTrue(est.using_history)

    def test_estimate_zero_files(self):
        est = get_cost_estimator().estimate(0, "deepseek", "deepseek-v4-flash")
        self.assertEqual(est.estimated_total_tokens, 0)
        self.assertEqual(est.estimated_total_cost_usd, 0.0)

    def test_unknown_model_falls_back(self):
        est = get_cost_estimator().estimate(1, "openai", "no-such-model")
        self.assertEqual(est.model, "no-such-model")
        self.assertGreater(est.estimated_total_cost_usd, 0)


class TestBalance(unittest.TestCase):
    def test_balance_info_low(self):
        info = BalanceInfo(
            provider="deepseek", available=True, is_active=True,
            currency="CNY", total_balance=1.0,
        )
        self.assertTrue(info.low_balance)
        self.assertIn("余额不足", info.display_text)

    def test_balance_info_ok(self):
        info = BalanceInfo(
            provider="deepseek", available=True, is_active=True,
            currency="CNY", total_balance=100.0,
        )
        self.assertFalse(info.low_balance)

    def test_balance_info_unavailable(self):
        info = BalanceInfo(provider="deepseek", available=False, message="查询失败")
        self.assertFalse(info.low_balance)
        self.assertIn("查询失败", info.display_text)
        self.assertIn("deepseek", info.display_text)

    def test_loop_running_detection(self):
        # 同步上下文不应判定为运行中
        import asyncio

        self.assertFalse(_is_loop_running())
        # 异步上下文应判定为运行中
        async def _check():
            self.assertTrue(_is_loop_running())

        asyncio.run(_check())


if __name__ == "__main__":
    unittest.main()
