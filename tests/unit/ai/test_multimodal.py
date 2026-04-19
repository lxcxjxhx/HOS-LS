"""多模态支持测试"""

import pytest
from src.ai.models import AnalysisContext, AIContent
from src.ai.analyzer import AIAnalyzer


class TestMultimodalSupport:
    def test_analysis_context_multimodal(self):
        """测试分析上下文的多模态内容支持"""
        # 创建多模态内容
        multimodal_content = [
            AIContent(type="image", content="base64_image_data"),
            AIContent(type="text", content="附加文本内容")
        ]
        
        # 创建分析上下文
        context = AnalysisContext(
            file_path="test.py",
            code_content="print('hello world')",
            language="python",
            multimodal_content=multimodal_content
        )
        
        assert context.multimodal_content is not None
        assert len(context.multimodal_content) == 2
        assert context.multimodal_content[0].type == "image"
        assert context.multimodal_content[1].type == "text"

    def test_build_prompt_with_multimodal(self):
        """测试构建包含多模态内容的提示词"""
        # 创建多模态内容
        multimodal_content = [
            AIContent(type="image", content="base64_image_data"),
            AIContent(type="text", content="附加文本内容")
        ]
        
        # 创建分析上下文
        context = AnalysisContext(
            file_path="test.py",
            code_content="print('hello world')",
            language="python",
            multimodal_content=multimodal_content
        )
        
        # 创建分析器
        analyzer = AIAnalyzer()
        
        # 构建提示词
        prompt = analyzer._build_prompt(context)
        
        # 验证提示词包含多模态内容的描述
        assert "## 图像 1" in prompt
        assert "分析此图像中可能包含的安全相关信息" in prompt
        assert "## 附加文本 2" in prompt
        assert "附加文本内容" in prompt
