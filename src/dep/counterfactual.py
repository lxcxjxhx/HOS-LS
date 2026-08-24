"""反事实验证器

通过回退补丁或生成正确补丁，验证漏洞路径是否消失。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
import subprocess
import tempfile
import shutil

from src.dep.differ import SuspiciousPath
from src.sal.path_explorer import CandidatePath, SALExplorer, CallGraph


class VerificationStatus(str, Enum):
    """验证状态枚举"""
    CONFIRMED = "confirmed"  # 确认漏洞（路径消失）
    REJECTED = "rejected"  # 拒绝（路径仍存在）
    UNCERTAIN = "uncertain"  # 不确定
    ERROR = "error"  # 验证出错


@dataclass
class VerificationEvidence:
    """验证证据"""
    path_before_unreachable: bool = False  # 改前该路径不可达
    path_after_reachable: bool = False  # 改后该路径可达
    counterfactual_disappeared: bool = False  # 反事实修复后路径消失
    before_reachability_proof: str = ""  # 改前可达性证明
    after_reachability_proof: str = ""  # 改后可达性证明
    counterfactual_proof: str = ""  # 反事实证明
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_before_unreachable": self.path_before_unreachable,
            "path_after_reachable": self.path_after_reachable,
            "counterfactual_disappeared": self.counterfactual_disappeared,
            "before_reachability_proof": self.before_reachability_proof,
            "after_reachability_proof": self.after_reachability_proof,
            "counterfactual_proof": self.counterfactual_proof,
        }


@dataclass
class VerificationResult:
    """验证结果"""
    status: VerificationStatus
    suspicious_path: SuspiciousPath
    evidence: VerificationEvidence
    confidence: float = 0.0
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status.value,
            "suspicious_path": self.suspicious_path.to_dict(),
            "evidence": self.evidence.to_dict(),
            "confidence": self.confidence,
            "description": self.description,
            "metadata": self.metadata,
        }


class CounterfactualVerifier:
    """反事实验证器
    
    通过回退补丁或生成正确补丁，验证漏洞路径是否消失。
    
    验证流程：
    1. 回退AI补丁（或生成正确补丁）
    2. 重新扫描路径
    3. 检查路径是否消失
    4. 如果消失 → 确认漏洞；如果仍存在 → 误报
    """
    
    def __init__(self, sal_explorer: Optional[SALExplorer] = None):
        self.sal_explorer = sal_explorer or SALExplorer()
    
    def verify(
        self,
        suspicious_path: SuspiciousPath,
        r_before: str,
        r_after: str,
        delta_ai: str,
        modified_funcs: List[str],
    ) -> VerificationResult:
        """反事实验证
        
        Args:
            suspicious_path: 可疑路径
            r_before: 改前仓库路径
            r_after: 改后仓库路径
            delta_ai: AI生成的补丁
            modified_funcs: 修改的函数列表
            
        Returns:
            验证结果
        """
        try:
            # Step 1: 验证改前路径不可达
            before_unreachable = self._verify_before_unreachable(
                suspicious_path.path, r_before, modified_funcs
            )
            
            # Step 2: 验证改后路径可达
            after_reachable = self._verify_after_reachable(
                suspicious_path.path, r_after, modified_funcs
            )
            
            # Step 3: 反事实验证 - 回退补丁后路径是否消失
            counterfactual_result = self._counterfactual_verify(
                suspicious_path.path, r_before, delta_ai, modified_funcs
            )
            
            # 构建证据
            evidence = VerificationEvidence(
                path_before_unreachable=before_unreachable,
                path_after_reachable=after_reachable,
                counterfactual_disappeared=counterfactual_result["disappeared"],
                before_reachability_proof=before_unreachable.get("proof", ""),
                after_reachability_proof=after_reachable.get("proof", ""),
                counterfactual_proof=counterfactual_result.get("proof", ""),
            )
            
            # 判断验证状态
            status = self._determine_status(
                before_unreachable, after_reachable, counterfactual_result
            )
            
            # 计算置信度
            confidence = self._calculate_confidence(
                status, before_unreachable, after_reachable, counterfactual_result
            )
            
            return VerificationResult(
                status=status,
                suspicious_path=suspicious_path,
                evidence=evidence,
                confidence=confidence,
                description=self._generate_description(status, suspicious_path),
            )
            
        except Exception as e:
            return VerificationResult(
                status=VerificationStatus.ERROR,
                suspicious_path=suspicious_path,
                evidence=VerificationEvidence(),
                confidence=0.0,
                description=f"验证出错: {str(e)}",
                metadata={"error": str(e)},
            )
    
    def _verify_before_unreachable(
        self,
        path: CandidatePath,
        r_before: str,
        modified_funcs: List[str],
    ) -> Dict[str, Any]:
        """验证改前路径不可达
        
        在改前版本中，检查该路径是否不存在。
        """
        # 构建改前调用图
        graph_before = self._build_call_graph(r_before)
        
        # 探索改前路径
        paths_before = self.sal_explorer.explore_paths(
            modified_funcs, graph_before
        )
        
        # 检查目标路径是否在改前存在
        path_exists = self._path_exists_in(path, paths_before)
        
        return {
            "unreachable": not path_exists,
            "proof": f"改前版本中{'不存在' if not path_exists else '存在'}该路径",
            "paths_before_count": len(paths_before),
        }
    
    def _verify_after_reachable(
        self,
        path: CandidatePath,
        r_after: str,
        modified_funcs: List[str],
    ) -> Dict[str, Any]:
        """验证改后路径可达
        
        在改后版本中，检查该路径是否存在。
        """
        # 构建改后调用图
        graph_after = self._build_call_graph(r_after)
        
        # 探索改后路径
        paths_after = self.sal_explorer.explore_paths(
            modified_funcs, graph_after
        )
        
        # 检查目标路径是否在改后存在
        path_exists = self._path_exists_in(path, paths_after)
        
        return {
            "reachable": path_exists,
            "proof": f"改后版本中{'存在' if path_exists else '不存在'}该路径",
            "paths_after_count": len(paths_after),
        }
    
    def _counterfactual_verify(
        self,
        path: CandidatePath,
        r_before: str,
        delta_ai: str,
        modified_funcs: List[str],
    ) -> Dict[str, Any]:
        """反事实验证
        
        回退AI补丁，检查路径是否消失。
        """
        # 创建临时目录用于回退版本
        with tempfile.TemporaryDirectory() as temp_dir:
            r_reverted = Path(temp_dir) / "reverted"
            
            # 复制改前版本
            shutil.copytree(r_before, r_reverted)
            
            # 应用AI补丁
            self._apply_patch(r_reverted, delta_ai)
            
            # 构建回退版本的调用图
            graph_reverted = self._build_call_graph(str(r_reverted))
            
            # 探索回退版本的路径
            paths_reverted = self.sal_explorer.explore_paths(
                modified_funcs, graph_reverted
            )
            
            # 检查目标路径是否在回退版本中存在
            path_exists = self._path_exists_in(path, paths_reverted)
            
            return {
                "disappeared": not path_exists,
                "proof": f"回退补丁后路径{'消失' if not path_exists else '仍存在'}",
                "paths_reverted_count": len(paths_reverted),
            }
    
    def _apply_patch(self, repo_path: Path, patch: str):
        """应用补丁"""
        # 写入补丁文件
        patch_file = repo_path / "temp.patch"
        patch_file.write_text(patch)
        
        try:
            # 应用补丁
            subprocess.run(
                ["git", "apply", str(patch_file)],
                cwd=repo_path,
                check=True,
                capture_output=True,
            )
        except subprocess.CalledProcessError as e:
            # 如果git apply失败，尝试使用patch命令
            try:
                subprocess.run(
                    ["patch", "-p1", "-i", str(patch_file)],
                    cwd=repo_path,
                    check=True,
                    capture_output=True,
                )
            except Exception:
                raise RuntimeError(f"无法应用补丁: {e}")
        finally:
            # 清理补丁文件
            if patch_file.exists():
                patch_file.unlink()
    
    def _build_call_graph(self, repo_path: str) -> CallGraph:
        """构建调用图
        
        这里需要集成tree-sitter来构建调用图。
        暂时返回空图，实际实现需要调用CFGBuilder。
        """
        # TODO: 集成tree-sitter调用图构建
        return CallGraph()
    
    def _path_exists_in(
        self, target: CandidatePath, paths: List[CandidatePath]
    ) -> bool:
        """检查目标路径是否在路径列表中"""
        target_chain = tuple(target.call_chain)
        
        for path in paths:
            if tuple(path.call_chain) == target_chain:
                return True
            # 也检查是否是子路径
            if self._is_subpath(target_chain, tuple(path.call_chain)):
                return True
        
        return False
    
    def _is_subpath(self, subpath: tuple, fullpath: tuple) -> bool:
        """检查subpath是否是fullpath的子路径"""
        if len(subpath) > len(fullpath):
            return False
        
        for i in range(len(fullpath) - len(subpath) + 1):
            if fullpath[i:i+len(subpath)] == subpath:
                return True
        
        return False
    
    def _determine_status(
        self,
        before_unreachable: Dict[str, Any],
        after_reachable: Dict[str, Any],
        counterfactual_result: Dict[str, Any],
    ) -> VerificationStatus:
        """判断验证状态"""
        # 确认漏洞的条件：
        # 1. 改前路径不可达
        # 2. 改后路径可达
        # 3. 反事实修复后路径消失
        if (before_unreachable.get("unreachable", False) and
            after_reachable.get("reachable", False) and
            counterfactual_result.get("disappeared", False)):
            return VerificationStatus.CONFIRMED
        
        # 拒绝的条件：
        # 改前路径就存在（不是AI引入的）
        if not before_unreachable.get("unreachable", True):
            return VerificationStatus.REJECTED
        
        # 不确定的条件：
        # 反事实验证失败或路径仍存在
        if not counterfactual_result.get("disappeared", True):
            return VerificationStatus.REJECTED
        
        return VerificationStatus.UNCERTAIN
    
    def _calculate_confidence(
        self,
        status: VerificationStatus,
        before_unreachable: Dict[str, Any],
        after_reachable: Dict[str, Any],
        counterfactual_result: Dict[str, Any],
    ) -> float:
        """计算置信度"""
        if status == VerificationStatus.CONFIRMED:
            # 确认漏洞：高置信度
            base = 0.8
            # 如果所有证据都支持，增加置信度
            if (before_unreachable.get("unreachable", False) and
                after_reachable.get("reachable", False) and
                counterfactual_result.get("disappeared", False)):
                base = 0.95
            return base
        
        elif status == VerificationStatus.REJECTED:
            # 拒绝：低置信度
            return 0.3
        
        else:
            # 不确定：中等置信度
            return 0.5
    
    def _generate_description(
        self, status: VerificationStatus, suspicious_path: SuspiciousPath
    ) -> str:
        """生成描述"""
        if status == VerificationStatus.CONFIRMED:
            return (
                f"确认漏洞：AI补丁新增了从 {suspicious_path.path.entry_point} "
                f"到 {suspicious_path.path.sink} 的路径，该路径在改前不存在，"
                f"回退补丁后路径消失。"
            )
        elif status == VerificationStatus.REJECTED:
            return (
                f"拒绝：该路径在改前就存在，或回退补丁后路径仍存在，"
                f"不是AI引入的漏洞。"
            )
        else:
            return "验证不确定，需要人工复核。"
