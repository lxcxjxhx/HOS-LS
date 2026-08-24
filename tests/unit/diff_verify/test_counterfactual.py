"""反事实验证器单元测试"""

import pytest
from src.dep.counterfactual import (
    CounterfactualVerifier, 
    VerificationResult, 
    VerificationStatus,
    VerificationEvidence
)
from src.dep.differ import SuspiciousPath, DiffReason
from src.sal.path_explorer import CandidatePath, SinkCategory


class TestCounterfactualVerifier:
    """反事实验证器测试"""
    
    def setup_method(self):
        """测试前准备"""
        self.verifier = CounterfactualVerifier()
    
    def _create_suspicious_path(self, entry, sink, chain):
        """辅助方法：创建可疑路径"""
        path = CandidatePath(
            entry_point=entry,
            sink=sink,
            call_chain=chain,
            modified_functions=[],
            files_involved=["test.py"],
            sink_category=SinkCategory.SQL_INJECTION,
            confidence=0.8
        )
        return SuspiciousPath(
            path=path,
            reason=DiffReason.NEW_PATH,
            description="Test path",
            confidence=0.9
        )
    
    def test_verification_evidence_to_dict(self):
        """测试验证证据转换为字典"""
        evidence = VerificationEvidence(
            path_before_unreachable=True,
            path_after_reachable=True,
            counterfactual_disappeared=True,
            before_reachability_proof="Path not found in before",
            after_reachability_proof="Path found in after",
            counterfactual_proof="Path disappeared after revert"
        )
        
        result = evidence.to_dict()
        
        assert result["path_before_unreachable"] == True
        assert result["path_after_reachable"] == True
        assert result["counterfactual_disappeared"] == True
        assert "Path not found" in result["before_reachability_proof"]
    
    def test_verification_result_to_dict(self):
        """测试验证结果转换为字典"""
        path = CandidatePath(
            entry_point="handler",
            sink="execute",
            call_chain=["handler", "execute"],
            modified_functions=[],
            files_involved=["test.py"],
            sink_category=SinkCategory.SQL_INJECTION,
            confidence=0.8
        )
        
        suspicious = SuspiciousPath(
            path=path,
            reason=DiffReason.NEW_PATH,
            description="Test",
            confidence=0.9
        )
        
        evidence = VerificationEvidence(
            path_before_unreachable=True,
            path_after_reachable=True,
            counterfactual_disappeared=True
        )
        
        result_obj = VerificationResult(
            status=VerificationStatus.CONFIRMED,
            suspicious_path=suspicious,
            evidence=evidence,
            confidence=0.95,
            description="Confirmed vulnerability"
        )
        
        result = result_obj.to_dict()
        
        assert result["status"] == "confirmed"
        assert result["confidence"] == 0.95
        assert "Confirmed" in result["description"]
    
    def test_determine_status_confirmed(self):
        """测试确认状态判断"""
        before = {"unreachable": True}
        after = {"reachable": True}
        counterfactual = {"disappeared": True}
        
        status = self.verifier._determine_status(before, after, counterfactual)
        assert status == VerificationStatus.CONFIRMED
    
    def test_determine_status_rejected_before_exists(self):
        """测试拒绝状态（改前就存在）"""
        before = {"unreachable": False}  # 改前就存在
        after = {"reachable": True}
        counterfactual = {"disappeared": True}
        
        status = self.verifier._determine_status(before, after, counterfactual)
        assert status == VerificationStatus.REJECTED
    
    def test_determine_status_rejected_still_exists(self):
        """测试拒绝状态（回退后仍存在）"""
        before = {"unreachable": True}
        after = {"reachable": True}
        counterfactual = {"disappeared": False}  # 回退后仍存在
        
        status = self.verifier._determine_status(before, after, counterfactual)
        assert status == VerificationStatus.REJECTED
    
    def test_calculate_confidence_confirmed(self):
        """测试确认情况的置信度计算"""
        before = {"unreachable": True}
        after = {"reachable": True}
        counterfactual = {"disappeared": True}
        
        confidence = self.verifier._calculate_confidence(
            VerificationStatus.CONFIRMED, before, after, counterfactual
        )
        
        assert confidence >= 0.8  # 确认情况应该有高置信度
    
    def test_calculate_confidence_rejected(self):
        """测试拒绝情况的置信度计算"""
        before = {"unreachable": False}
        after = {"reachable": True}
        counterfactual = {"disappeared": False}
        
        confidence = self.verifier._calculate_confidence(
            VerificationStatus.REJECTED, before, after, counterfactual
        )
        
        assert confidence <= 0.5  # 拒绝情况应该有低置信度
    
    def test_generate_description_confirmed(self):
        """测试生成确认描述"""
        path = CandidatePath(
            entry_point="handler",
            sink="execute",
            call_chain=["handler", "execute"],
            modified_functions=[],
            files_involved=["test.py"],
            sink_category=SinkCategory.SQL_INJECTION,
            confidence=0.8
        )
        
        suspicious = SuspiciousPath(
            path=path,
            reason=DiffReason.NEW_PATH,
            description="Test",
            confidence=0.9
        )
        
        description = self.verifier._generate_description(
            VerificationStatus.CONFIRMED, suspicious
        )
        
        assert "确认漏洞" in description
        assert "handler" in description
        assert "execute" in description


class TestVerificationStatus:
    """验证状态枚举测试"""
    
    def test_status_values(self):
        """测试状态值"""
        assert VerificationStatus.CONFIRMED.value == "confirmed"
        assert VerificationStatus.REJECTED.value == "rejected"
        assert VerificationStatus.UNCERTAIN.value == "uncertain"
        assert VerificationStatus.ERROR.value == "error"
