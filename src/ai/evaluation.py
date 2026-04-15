import os
from typing import Dict, Any, Optional
from langsmith import Client as LangSmithClient

# 尝试导入DeepEval
try:
    from depeval import DeepEval
    has_depeval = True
except ImportError:
    has_depeval = False


class HOSLSEvaluator:
    """HOS-LS评估器"""
    
    def __init__(self):
        """初始化评估器"""
        # 初始化LangSmith客户端
        self.langsmith_client = None
        if os.getenv('LANGSMITH_API_KEY'):
            self.langsmith_client = LangSmithClient()
        
        # 初始化DeepEval（如果可用）
        self.depeval = None
        if has_depeval:
            try:
                self.depeval = DeepEval()
            except Exception as e:
                print(f"DeepEval初始化失败: {e}")
                self.depeval = None
    
    def trace_with_langsmith(self, run_name: str, inputs: Dict[str, Any], outputs: Dict[str, Any]):
        """使用LangSmith追踪运行"""
        if self.langsmith_client:
            try:
                self.langsmith_client.create_run(
                    run_name=run_name,
                    inputs=inputs,
                    outputs=outputs,
                    project_name="HOS-LS"
                )
            except Exception as e:
                print(f"LangSmith追踪失败: {e}")
    
    def evaluate_with_depeval(self, analysis_result: str, ground_truth: Optional[str] = None) -> Dict[str, Any]:
        """使用DeepEval评估分析结果"""
        # 如果DeepEval不可用，返回默认评估结果
        if not self.depeval:
            print("DeepEval不可用，使用默认评估结果")
            return {
                "accuracy": 0.5,
                "robustness": 0.5,
                "toxicity": 0.5,
                "overall": 0.5
            }
        
        try:
            # 评估准确性
            accuracy_score = self.depeval.evaluate_accuracy(
                analysis_result,
                ground_truth or ""
            )
            
            # 评估鲁棒性
            robustness_score = self.depeval.evaluate_robustness(
                analysis_result
            )
            
            # 评估毒性
            toxicity_score = self.depeval.evaluate_toxicity(
                analysis_result
            )
            
            return {
                "accuracy": accuracy_score,
                "robustness": robustness_score,
                "toxicity": toxicity_score,
                "overall": (accuracy_score + robustness_score + (1 - toxicity_score)) / 3
            }
        except Exception as e:
            print(f"DeepEval评估失败: {e}")
            return {
                "accuracy": 0.5,
                "robustness": 0.5,
                "toxicity": 0.5,
                "overall": 0.5
            }
    
    def evaluate_analysis(self, input_code: str, analysis_result: str, ground_truth: Optional[str] = None) -> Dict[str, Any]:
        """评估分析结果"""
        # 使用LangSmith追踪
        self.trace_with_langsmith(
            "vulnerability_analysis",
            {"input_code": input_code},
            {"analysis_result": analysis_result}
        )
        
        # 使用DeepEval评估
        evaluation = self.evaluate_with_depeval(analysis_result, ground_truth)
        
        # 生成评估报告
        report = {
            "input_code": input_code[:200] + "..." if len(input_code) > 200 else input_code,
            "analysis_result": analysis_result[:500] + "..." if len(analysis_result) > 500 else analysis_result,
            "evaluation": evaluation,
            "timestamp": "2024-01-01T00:00:00Z"  # 实际应用中应该使用真实的时间戳
        }
        
        return report
    
    def generate_feedback(self, evaluation: Dict[str, Any]) -> str:
        """基于评估结果生成反馈"""
        overall = evaluation.get("overall", 0.0)
        
        if overall >= 0.8:
            return "分析结果质量优秀，继续保持"
        elif overall >= 0.6:
            return "分析结果质量良好，但仍有改进空间"
        elif overall >= 0.4:
            return "分析结果质量一般，需要改进"
        else:
            return "分析结果质量较差，需要大幅改进"
    
    def optimize_from_feedback(self, feedback: str, current_config: Dict[str, Any]) -> Dict[str, Any]:
        """基于反馈优化系统配置"""
        new_config = current_config.copy()
        
        if "较差" in feedback:
            # 大幅改进
            new_config["top_k"] = min(new_config.get("top_k", 5) + 5, 20)
            new_config["batch_size"] = min(new_config.get("batch_size", 32) + 32, 128)
        elif "一般" in feedback:
            # 中等改进
            new_config["top_k"] = min(new_config.get("top_k", 5) + 2, 15)
            new_config["batch_size"] = min(new_config.get("batch_size", 32) + 16, 64)
        elif "良好" in feedback:
            # 小幅改进
            new_config["top_k"] = min(new_config.get("top_k", 5) + 1, 10)
        
        return new_config


def get_evaluator() -> HOSLSEvaluator:
    """获取评估器实例"""
    return HOSLSEvaluator()
