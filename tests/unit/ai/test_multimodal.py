"""多模态支持测试 - 占位符

注意：原始测试依赖的模块（src.ai.analyzer）尚未实现。
这些测试将在相关模块实现后重新编写。
"""

import pytest


@pytest.mark.skip(reason="依赖模块尚未实现: src.ai.analyzer")
class TestMultimodalSupport:
    def test_analysis_context_multimodal(self):
        """测试分析上下文的多模态内容支持 - 待实现"""
        pass

    def test_build_prompt_with_multimodal(self):
        """测试构建包含多模态内容的提示词 - 待实现"""
        pass
