"""增量索引管理器（Incremental Index Manager）

提供智能的文件变更检测和增量扫描能力：
- 首次全量索引建立基线
- 后续只分析变更文件（新增/修改/删除）
- 透明集成到现有扫描流程
- 索引持久化与一致性保证

性能目标：
- 变更检测: < 100ms (1000文件)
- 增量扫描提速: ≥ 3x (对于小变更)
- 索引存储: < 1MB (1000文件)
"""

import os
import hashlib
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field, asdict
from enum import Enum


class ChangeType(Enum):
    """变更类型"""
    ADDED = "added"
    MODIFIED = "modified"
    DELETED = "deleted"


@dataclass
class FileIndexEntry:
    """文件索引条目
    
    记录单个文件的元数据和分析状态。
    
    Attributes:
        path: 文件路径（相对路径）
        absolute_path: 绝对路径
        size: 文件大小（字节）
        mtime: 最后修改时间戳
        content_hash: 内容MD5前16位
        language: 编程语言
        last_analyzed_at: 最后分析时间
        analysis_result_hash: 分析结果的hash（用于判断是否需要重分析）
        risk_score: 风险评分（0-10）
        has_issues: 是否有问题
        last_issue_count: 上次发现的问题数量
    """
    path: str = ""
    absolute_path: str = ""
    size: int = 0
    mtime: float = 0.0
    content_hash: str = ""
    language: str = ""
    last_analyzed_at: Optional[datetime] = None
    analysis_result_hash: str = ""
    risk_score: float = 0.0
    has_issues: bool = False
    last_issue_count: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'path': self.path,
            'absolute_path': self.absolute_path,
            'size': self.size,
            'mtime': self.mtime,
            'content_hash': self.content_hash,
            'language': self.language,
            'last_analyzed_at': self.last_analyzed_at.isoformat() if self.last_analyzed_at else None,
            'analysis_result_hash': self.analysis_result_hash,
            'risk_score': self.risk_score,
            'has_issues': self.has_issues,
            'last_issue_count': self.last_issue_count
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'FileIndexEntry':
        """从字典创建实例"""
        return cls(
            path=data.get('path', ''),
            absolute_path=data.get('absolute_path', ''),
            size=data.get('size', 0),
            mtime=data.get('mtime', 0.0),
            content_hash=data.get('content_hash', ''),
            language=data.get('language', ''),
            last_analyzed_at=datetime.fromisoformat(data['last_analyzed_at']) if data.get('last_analyzed_at') else None,
            analysis_result_hash=data.get('analysis_result_hash', ''),
            risk_score=data.get('risk_score', 0.0),
            has_issues=data.get('has_issues', False),
            last_issue_count=data.get('last_issue_count', 0)
        )
    
    def is_changed(self, current_mtime: float, current_size: int) -> bool:
        """检查文件是否已变更"""
        return self.mtime != current_mtime or self.size != current_size


@dataclass
class ProjectIndexState:
    """项目索引状态
    
    维护整个项目的文件索引信息。
    
    Attributes:
        project_root: 项目根目录
        index_version: 索引版本号
        created_at: 创建时间
        last_updated: 最后更新时间
        total_files_indexed: 已索引文件总数
        files: 路径 → 索引条目的映射
    """
    project_root: str = "."
    index_version: int = 1
    created_at: datetime = field(default_factory=datetime.now)
    last_updated: datetime = field(default_factory=datetime.now)
    total_files_indexed: int = 0
    files: Dict[str, FileIndexEntry] = field(default_factory=dict)
    
    def get_changed_files(self, base_path: str = None) -> Tuple[List[str], List[str], List[str]]:
        """检测变更文件
        
        Args:
            base_path: 基础路径（默认使用project_root）
            
        Returns:
            (added_files, modified_files, deleted_files) 元组
        """
        base_path = base_path or self.project_root
        
        added = []
        modified = []
        deleted = []
        
        current_files = set()
        
        # 支持的代码文件扩展名
        code_extensions = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', 
                         '.rs', '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.php'}
        
        # 遍历当前文件系统
        try:
            for root, dirs, files in os.walk(base_path):
                # 排除隐藏目录、缓存目录和虚拟环境
                dirs[:] = [d for d in dirs if not d.startswith('.') and 
                          d not in {'__pycache__', 'node_modules', '.git', 'venv', 
                                   '.venv', 'env', '.env', 'dist', 'build',
                                   '.next', '.nuxt', 'target', 'bin', 'obj'}]
                
                for filename in files:
                    # 只处理代码文件
                    ext = os.path.splitext(filename)[1].lower()
                    if ext not in code_extensions:
                        continue
                    
                    file_path = os.path.join(root, filename)
                    rel_path = os.path.relpath(file_path, base_path).replace('\\', '/')
                    current_files.add(rel_path)
                    
                    try:
                        current_mtime = os.path.getmtime(file_path)
                        current_size = os.path.getsize(file_path)
                        
                        if rel_path not in self.files:
                            added.append(rel_path)  # 新增文件
                        else:
                            entry = self.files[rel_path]
                            if entry.is_changed(current_mtime, current_size):
                                modified.append(rel_path)  # 修改文件
                    except (OSError, IOError):
                        continue  # 无法访问的文件跳过
            
        except Exception as e:
            print(f"⚠️ 遍历文件系统时出错: {e}")
        
        # 检测删除的文件
        indexed_files = set(self.files.keys())
        deleted = list(indexed_files - current_files)
        
        return added, modified, deleted
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            'project_root': self.project_root,
            'index_version': self.index_version,
            'created_at': self.created_at.isoformat(),
            'last_updated': self.last_updated.isoformat(),
            'total_files_indexed': self.total_files_indexed,
            'files': {k: v.to_dict() for k, v in self.files.items()}
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'ProjectIndexState':
        """从字典创建实例"""
        files_data = data.get('files', {})
        files = {}
        
        for path, entry_data in files_data.items():
            files[path] = FileIndexEntry.from_dict(entry_data)
        
        return cls(
            project_root=data.get('project_root', '.'),
            index_version=data.get('index_version', 1),
            created_at=datetime.fromisoformat(data['created_at']) if data.get('created_at') else datetime.now(),
            last_updated=datetime.fromisoformat(data['last_updated']) if data.get('last_updated') else datetime.now(),
            total_files_indexed=data.get('total_files_indexed', 0),
            files=files
        )


@dataclass
class ChangeDetectionResult:
    """变更检测结果"""
    added_files: List[str] = field(default_factory=list)
    modified_files: List[str] = field(default_factory=list)
    deleted_files: List[str] = field(default_factory=list)
    total_changes: int = 0
    suggested_action: str = "full_scan"  # full_scan / incremental_scan / skip
    
    @property
    def has_changes(self) -> bool:
        return self.total_changes > 0
    
    def to_summary(self) -> str:
        """生成摘要文本"""
        parts = []
        if self.added_files:
            parts.append(f"📁 新增: {len(self.added_files)}")
        if self.modified_files:
            parts.append(f"✏️  修改: {len(self.modified_files)}")
        if self.deleted_files:
            parts.append(f"🗑️  删除: {len(self.deleted_files)}")
        
        return f"变更检测: {' | '.join(parts)} (共{self.total_changes}个)" if parts else "无变更"


@dataclass
class IncrementalScanPlan:
    """增量扫描计划"""
    files_to_scan: List[str] = field(default_factory=list)
    files_to_skip: List[str] = field(default_factory=list)
    change_stats: Optional[ChangeDetectionResult] = None
    estimated_time_saving: float = 0.0  # 预估节省的时间（秒）
    
    @property
    def should_use_incremental(self) -> bool:
        """判断是否应该使用增量模式"""
        # 如果跳过的文件超过总文件的50%，使用增量模式
        total = len(self.files_to_scan) + len(self.files_to_skip)
        return total > 0 and len(self.files_to_skip) / total > 0.3


class IncrementalIndexManager:
    """增量索引管理器
    
    管理项目的文件索引，支持智能的增量扫描。
    
    使用示例:
        manager = IncrementalIndexManager()
        
        # 初始化
        await manager.initialize_for_project("./my-project")
        
        # 检测变更
        changes = await manager.detect_changes()
        print(changes.to_summary())
        
        # 获取增量扫描计划
        scan_plan = await manager.get_incremental_scan_plan()
        print(f"需扫描: {len(scan_plan.files_to_scan)}, 可跳过: {len(scan_plan.files_to_skip)}")
    """
    
    # 支持的代码文件扩展名
    CODE_EXTENSIONS = {'.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.go', 
                     '.rs', '.c', '.cpp', '.h', '.hpp', '.cs', '.rb', '.php'}
    
    # 排除的目录
    EXCLUDE_DIRS = {'.', '__pycache__', 'node_modules', '.git', 'venv', '.venv',
                   'env', '.env', 'dist', 'build', '.next', '.nuxt', 'target', 
                   'bin', 'obj', '.hos-ls', '.idea', '.vscode'}
    
    def __init__(self, index_dir: str = ".hos-ls/index"):
        """
        Args:
            index_dir: 索引存储目录
        """
        self.index_dir = Path(index_dir)
        self.index_file = self.index_dir / "project_index.json"
        self.index_dir.mkdir(parents=True, exist_ok=True)
        
        self.project_index: Optional[ProjectIndexState] = None
        
        # 复用Phase 1的文件缓存系统
        try:
            from src.utils.file_cache import get_global_cache_system
            self.file_cache_system = get_global_cache_system()
        except ImportError:
            self.file_cache_system = None
        
        # 统计信息
        self._detect_count: int = 0
        self._total_detect_time: float = 0.0
    
    async def initialize_for_project(self, project_path: str) -> ProjectIndexState:
        """初始化或加载项目索引
        
        Args:
            project_path: 项目根路径
            
        Returns:
            ProjectIndexState 对象
        """
        project_path = os.path.abspath(project_path)
        
        # 尝试加载已有索引
        if self.index_file.exists():
            try:
                self.project_index = await self._load_index()
                if self.project_index:
                    print(f"✅ 加载已有索引 ({self.project_index.total_files_indexed} 个文件)")
                    print(f"   📅 最后更新: {self.project_index.last_updated.strftime('%Y-%m-%d %H:%M:%S')}")
                    return self.project_index
            except Exception as e:
                print(f"⚠️ 加载索引失败，将重建: {e}")
        
        # 创建新索引
        self.project_index = ProjectIndexState(
            project_root=project_path,
            index_version=1,
            created_at=datetime.now(),
            last_updated=datetime.now(),
            total_files_indexed=0,
            files={}
        )
        
        print("🆕 创建新项目索引")
        return self.project_index
    
    async def detect_changes(self) -> ChangeDetectionResult:
        """检测文件变更
        
        Returns:
            ChangeDetectionResult 变更检测结果
        """
        start_time = time.time()
        
        if not self.project_index:
            raise Exception("项目索引未初始化，请先调用 initialize_for_project()")
        
        added, modified, deleted = self.project_index.get_changed_files()
        
        result = ChangeDetectionResult(
            added_files=added,
            modified_files=modified,
            deleted_files=deleted,
            total_changes=len(added) + len(modified) + len(deleted),
            suggested_action=self._suggest_action(len(added), len(modified), len(deleted))
        )
        
        # 更新统计
        self._detect_count += 1
        elapsed = time.time() - start_time
        self._total_detect_time += elapsed
        
        return result
    
    async def get_incremental_scan_plan(self) -> IncrementalScanPlan:
        """获取增量扫描计划
        
        Returns:
            IncrementalScanPlan 包含需要扫描和可跳过的文件列表
        """
        changes = await self.detect_changes()
        
        # 需要重新分析的文件 = 新增 + 修改
        files_to_rescan = changes.added_files + changes.modified_files
        
        # 可以跳过的文件（未变更且上次分析成功且无问题）
        files_to_skip = [
            path for path, entry in self.project_index.files.items()
            if path not in files_to_rescan and path not in changes.deleted_files
            and not entry.has_issues  # 有问题的文件仍需检查
        ]
        
        # 估算节省的时间（假设每个文件平均2秒）
        estimated_saving = len(files_to_skip) * 2
        
        return IncrementalScanPlan(
            files_to_scan=files_to_rescan,
            files_to_skip=files_to_skip,
            change_stats=changes,
            estimated_time_saving=estimated_saving
        )
    
    async def update_index_after_scan(
        self,
        analyzed_files: List[str],
        results: Dict[str, Any]
    ):
        """扫描完成后更新索引
        
        Args:
            analyzed_files: 已分析的文件列表
            results: 分析结果字典 {file_path: result_data}
        """
        if not self.project_index:
            return
        
        for file_path in analyzed_files:
            try:
                abs_path = os.path.join(self.project_index.project_root, file_path)
                
                # 计算内容哈希
                content_hash = ""
                if self.file_cache_system:
                    try:
                        content_hash = self.file_cache_system.l1_cache._compute_file_hash(abs_path)
                    except Exception:
                        pass
                
                if not content_hash:
                    content_hash = self._compute_file_hash_simple(abs_path)
                
                # 提取结果信息
                file_result = results.get(file_path, {})
                issues = file_result.get('issues', [])
                risk_score = file_result.get('risk_score', 0.0)
                
                # 更新或创建索引条目
                entry = FileIndexEntry(
                    path=file_path,
                    absolute_path=abs_path,
                    size=os.path.getsize(abs_path) if os.path.exists(abs_path) else 0,
                    mtime=os.path.getmtime(abs_path) if os.path.exists(abs_path) else 0,
                    content_hash=content_hash,
                    language=self._detect_language(file_path),
                    last_analyzed_at=datetime.now(),
                    analysis_result_hash=self._compute_result_hash(issues),
                    risk_score=risk_score,
                    has_issues=len(issues) > 0,
                    last_issue_count=len(issues)
                )
                
                self.project_index.files[file_path] = entry
                
            except Exception as e:
                print(f"⚠️ 更新索引失败 [{file_path}]: {e}")
        
        # 更新元数据
        self.project_index.last_updated = datetime.now()
        self.project_index.total_files_indexed = len(self.project_index.files)
        self.project_index.index_version += 1
        
        # 持久化到磁盘
        await self._save_index()
        
        print(f"💾 索引已更新 ({len(analyzed_files)} 个文件, 总计{self.project_index.total_files_indexed}个)")
    
    async def rebuild_index(self, force: bool = False):
        """重建索引
        
        Args:
            force: 是否强制重建（忽略已有索引）
        """
        if not self.project_index:
            raise Exception("项目索引未初始化")
        
        print(f"🔄 正在重建索引...")
        start_time = time.time()
        
        # 清空现有索引
        if force:
            self.project_index.files.clear()
        
        # 全量遍历并建立索引
        added, _, _ = self.project_index.get_changed_files()
        
        for file_path in added:
            abs_path = os.path.join(self.project_index.project_root, file_path)
            
            try:
                entry = FileIndexEntry(
                    path=file_path,
                    absolute_path=abs_path,
                    size=os.path.getsize(abs_path),
                    mtime=os.path.getmtime(abs_path),
                    content_hash=self._compute_file_hash_simple(abs_path),
                    language=self._detect_language(file_path),
                    last_analyzed_at=None  # 尚未分析
                )
                
                self.project_index.files[file_path] = entry
                
            except Exception as e:
                print(f"⚠️ 索引文件失败 [{file_path}]: {e}")
        
        # 更新元数据
        self.project_index.last_updated = datetime.now()
        self.project_index.total_files_indexed = len(self.project_index.files)
        self.project_index.index_version += 1
        
        # 保存
        await self._save_index()
        
        elapsed = time.time() - start_time
        print(f"✅ 索引重建完成 ({self.project_index.total_files_indexed} 个文件, 耗时{elapsed:.2f}秒)")
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取统计信息"""
        avg_detect_time = (self._total_detect_time / self._detect_count) if self._detect_count > 0 else 0
        
        stats = {
            'index_exists': self.project_index is not None,
            'total_files_indexed': self.project_index.total_files_indexed if self.project_index else 0,
            'index_version': self.project_index.index_version if self.project_index else 0,
            'last_updated': self.project_index.last_updated.isoformat() if self.project_index else None,
            'index_file_size_kb': self.index_file.stat().st_size / 1024 if self.index_file.exists() else 0,
            'change_detections': self._detect_count,
            'avg_detect_time_ms': avg_detect_time * 1000
        }
        
        return stats
    
    def get_index_status(self) -> str:
        """获取索引状态的可读描述"""
        if not self.project_index:
            return "❌ 索引未初始化"
        
        age = (datetime.now() - self.project_index.last_updated).total_seconds()
        age_str = f"{age/3600:.1f}小时前" if age > 3600 else f"{age/60:.1f}分钟前"
        
        return (
            f"📚 项目索引状态:\n"
            f"   文件数: {self.project_index.total_files_indexed}\n"
            f"   版本: v{self.project_index.index_version}\n"
            f"   最后更新: {age_str}\n"
            f"   存储位置: {self.index_file}"
        )
    
    # ========== 私有方法 ==========
    
    async def _save_index(self):
        """保存索引到磁盘"""
        if not self.project_index:
            return
        
        data = self.project_index.to_dict()
        
        with open(self.index_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)
    
    async def _load_index(self) -> Optional[ProjectIndexState]:
        """从磁盘加载索引"""
        try:
            with open(self.index_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            return ProjectIndexState.from_dict(data)
            
        except Exception as e:
            print(f"⚠️ 加载索引失败: {e}")
            return None
    
    def _compute_file_hash_simple(self, file_path: str) -> str:
        """简单计算文件哈希（仅读取部分内容）"""
        try:
            with open(file_path, 'rb') as f:
                # 读取前8KB用于快速哈希
                content = f.read(8192)
                return hashlib.md5(content).hexdigest()[:16]
        except Exception:
            return ""
    
    @staticmethod
    def _detect_language(file_path: str) -> str:
        """根据文件扩展名检测编程语言"""
        ext = os.path.splitext(file_path)[1].lower()
        
        lang_map = {
            '.py': 'python',
            '.js': 'javascript',
            '.ts': 'typescript',
            '.jsx': 'react',
            '.tsx': 'reacttypescript',
            '.java': 'java',
            '.go': 'golang',
            '.rs': 'rust',
            '.c': 'c',
            '.cpp': 'cplusplus',
            '.h': 'cheader',
            '.hpp': 'cplusplusheader',
            '.cs': 'csharp',
            '.rb': 'ruby',
            '.php': 'php'
        }
        
        return lang_map.get(ext, 'unknown')
    
    @staticmethod
    def _compute_result_hash(issues: List[Any]) -> str:
        """计算分析结果的哈希"""
        try:
            issues_str = json.dumps(issues, sort_keys=True, default=str)
            return hashlib.md5(issues_str.encode()).hexdigest()[:16]
        except Exception:
            return ""
    
    @staticmethod
    def _suggest_action(added: int, modified: int, deleted: int) -> str:
        """根据变更情况建议操作"""
        total = added + modified + deleted
        
        if total == 0:
            return "skip"  # 无变更，可以跳过
        elif total <= 10:
            return "incremental_scan"  # 小范围变更，增量扫描
        else:
            return "full_scan"  # 大范围变更，建议全量扫描


# ========== 全局单例 ==========
_global_index_manager: Optional[IncrementalIndexManager] = None


def get_incremental_index_manager() -> IncrementalIndexManager:
    """获取全局IncrementalIndexManager实例（单例模式）"""
    global _global_index_manager
    
    if _global_index_manager is None:
        _global_index_manager = IncrementalIndexManager()
    
    return _global_index_manager


# ========== 测试代码 ==========
if __name__ == "__main__":
    import asyncio
    
    async def test_incremental_index():
        """测试增量索引系统"""
        manager = IncrementalIndexManager(test_dir=".test_index")
        
        print("=== 🧪 增量索引系统测试 ===\n")
        
        # 初始化
        print("📂 初始化项目索引...")
        state = await manager.initialize_for_project(".")
        print(f"   ✅ 项目根: {state.project_root}")
        print()
        
        # 首次构建索引
        print("🔨 首次构建索引（模拟）...")
        test_files = [
            ("src/main.py", "python"),
            ("src/auth/login.py", "python"),
            ("src/api/users.js", "javascript"),
            ("config.yaml", "unknown")  # 应该被过滤
        ]
        
        for rel_path, lang in test_files:
            abs_path = os.path.join(".", rel_path)
            if os.path.exists(abs_path):
                entry = FileIndexEntry(
                    path=rel_path,
                    absolute_path=abs_path,
                    size=os.path.getsize(abs_path),
                    mtime=os.path.getmtime(abs_path),
                    content_hash=f"hash_{rel_path}",
                    language=lang,
                    last_analyzed_at=datetime.now()
                )
                manager.project_index.files[rel_path] = entry
        
        manager.project_index.total_files_indexed = len(manager.project_index.files)
        await manager._save_index()
        print(f"   ✅ 索引已建立 ({manager.project_index.total_files_indexed} 个文件)")
        print()
        
        # 检测变更
        print("🔍 检测文件变更...")
        changes = await manager.detect_changes()
        print(f"   {changes.to_summary()}")
        print()
        
        # 获取增量扫描计划
        print("📋 生成增量扫描计划...")
        scan_plan = await manager.get_incremental_scan_plan()
        print(f"   需要扫描: {len(scan_plan.files_to_scan)} 个文件")
        print(f"   可跳过: {len(scan_plan.files_to_skip)} 个文件")
        print(f"   预计节省: {scan_plan.estimated_time_saving:.0f}秒")
        print(f"   使用增量模式: {'是' if scan_plan.should_use_incremental else '否'}")
        print()
        
        # 统计信息
        print("📊 统计信息:")
        stats = manager.get_statistics()
        for key, value in stats.items():
            print(f"   {key}: {value}")
        print()
        
        # 状态
        print(manager.get_index_status())
        
        # 清理
        print("\n🧹 清理测试数据...")
        import shutil
        if Path(".test_index").exists():
            shutil.rmtree(".test_index")
        print("   ✅ 清理完成")
    
    asyncio.run(test_incremental_index())
