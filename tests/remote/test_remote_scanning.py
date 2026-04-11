"""
远程扫描模块单元测试

覆盖目标抽象层、连接器、扫描器等核心功能。
"""

import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock
from datetime import datetime
from pathlib import Path

from src.remote.target import (
    BaseTarget,
    TargetInfo,
    LocalTarget,
    RemoteServerTarget,
    WebTarget,
    DirectConnectTarget,
    TargetFactory,
    FileInfo,
    create_target_from_config
)


class TestFileInfo:
    """测试 FileInfo 数据类"""
    
    def test_create_file_info(self):
        """测试创建文件信息对象"""
        info = FileInfo(
            path="/test/file.py",
            name="file.py",
            size=1024,
            is_file=True
        )
        
        assert info.path == "/test/file.py"
        assert info.name == "file.py"
        assert info.size == 1024
        assert info.is_file is True
    
    def test_extension_property(self):
        """测试文件扩展名属性"""
        py_info = FileInfo(path="/test.py", name="test.py")
        js_info = FileInfo(path="/test.js", name="test.js")
        
        assert py_info.extension == ".py"
        assert js_info.extension == ".js"
    
    def test_detect_language(self):
        """测试语言检测"""
        python_file = FileInfo(path="/app/main.py", name="main.py")
        javascript_file = FileInfo(path="/app/index.js", name="index.js")
        unknown_file = FileInfo(path="/app/README", name="README")
        
        python_file.detect_language()
        javascript_file.detect_language()
        unknown_file.detect_language()
        
        assert python_file.language == 'python'
        assert javascript_file.language == 'javascript'
        assert unknown_file.language is None


class TestTargetInfo:
    """测试 TargetInfo 数据类"""
    
    def test_create_target_info(self):
        """测试创建目标信息"""
        info = TargetInfo(
            target_type='local',
            target_uri='file:///home/user/project'
        )
        
        assert info.target_type == 'local'
        assert info.target_uri == 'file:///home/user/project'
        assert info.credentials is None
        assert isinstance(info.metadata, dict)
    
    def test_to_dict_and_from_dict(self):
        """测试序列化和反序列化"""
        original = TargetInfo(
            target_type='remote-server',
            target_uri='ssh://admin@192.168.1.100',
            credentials={'username': 'admin'},
            metadata={'version': '1.0'}
        )
        
        data = original.to_dict()
        restored = TargetInfo.from_dict(data)
        
        assert restored.target_type == original.target_type
        assert restored.target_uri == original.target_uri
        assert restored.credentials == original.credentials


class TestLocalTarget:
    """测试本地目标"""
    
    @pytest.mark.asyncio
    async def test_connect_local_directory(self, tmp_path):
        """测试连接本地目录"""
        target = LocalTarget(base_path=tmp_path)
        
        result = await target.connect()
        
        assert result is True
        assert target.is_connected
        
        await target.disconnect()
    
    @pytest.mark.asyncio
    async def test_connect_nonexistent_path(self):
        """测试连接不存在的路径"""
        target = LocalTarget(base_path="/nonexistent/path/12345")
        
        result = await target.connect()
        
        assert result is False
        assert not target.is_connected
    
    @pytest.mark.asyncio
    async def test_list_files(self, tmp_path):
        """测试列出本地文件"""
        (tmp_path / "test.py").write_text("print('hello')")
        (tmp_path / "app.js").write_text("console.log('hi')")
        (tmp_path / "subdir").mkdir()
        
        target = LocalTarget(base_path=tmp_path)
        await target.connect()
        
        files = await target.list_files(recursive=True)
        
        assert len(files) >= 2
        file_names = [f.name for f in files]
        assert 'test.py' in file_names
        assert 'app.js' in file_names
        
        await target.disconnect()
    
    @pytest.mark.asyncio
    async def test_read_file(self, tmp_path):
        """测试读取本地文件"""
        test_content = "def hello():\n    print('world')"
        test_file = tmp_path / "example.py"
        test_file.write_text(test_content)
        
        target = LocalTarget(base_path=tmp_path)
        await target.connect()
        
        content = await target.read_file("example.py")
        
        assert content == test_content
        
        await target.disconnect()
    
    @pytest.mark.asyncio
    async def test_context_manager(self, tmp_path):
        """测试异步上下文管理器"""
        target = LocalTarget(base_path=tmp_path)
        
        async with target as t:
            assert t.is_connected
        
        assert not target.is_connected


class TestTargetFactory:
    """测试目标工厂"""
    
    def test_create_local_target(self):
        """测试创建本地目标"""
        target = TargetFactory.create("./my-project")
        
        assert isinstance(target, LocalTarget)
    
    def test_create_local_target_from_file_uri(self):
        """测试从file:// URI创建本地目标"""
        target = TargetFactory.create("file:///home/user/project")
        
        assert isinstance(target, LocalTarget)
    
    def test_detect_target_type_local(self):
        """检测本地目标类型"""
        assert TargetFactory.detect_target_type("./project") == 'local'
        assert TargetFactory.detect_target_type("/var/www") == 'local'
        assert TargetFactory.detect_target_type("C:\\Users\\test") == 'local'
    
    def test_detect_target_type_remote(self):
        """检测远程目标类型"""
        assert TargetFactory.detect_target_type("ssh://user@host") == 'remote-server'
        assert TargetFactory.detect_target_type("https://example.com") == 'website'
        assert TargetFactory.detect_target_type("serial:///dev/ttyUSB0") == 'direct-connect'


class TestBaseConnector:
    """测试连接器基类"""
    
    def test_connector_initialization(self):
        """测试连接器初始化"""
        from src.remote.connectors.base_connector import (
            BaseConnector,
            ConnectionConfig,
            ConnectionStatus
        )
        
        config = ConnectionConfig(timeout=60)
        connector = MockConnector(config=config)
        
        assert connector.config.timeout == 60
        assert connector.status == ConnectionStatus.DISCONNECTED
        assert not connector.is_connected
    
    @pytest.mark.asyncio
    async def test_connect_with_retry(self):
        """测试带重试的连接"""
        connector = MockConnector(config=ConnectionConfig(max_retries=2))
        
        result = await connector.connect()
        
        assert result.success
        assert connector.is_connected
        assert connector.connection_duration > 0
        
        await connector.disconnect()


class MockConnector(BaseConnector):
    """模拟连接器用于测试"""
    
    connector_type = "mock"
    
    def __init__(self, config=None, **kwargs):
        super().__init__(config=config, **kwargs)
        self._mock_connected = False
    
    async def _do_connect(self):
        from src.remote.connectors.base_connector import ConnectionResult, ConnectionStatus
        self._mock_connected = True
        return ConnectionResult(
            success=True,
            status=ConnectionStatus.CONNECTED,
            message="Mock connection successful"
        )
    
    async def _do_disconnect(self):
        self._mock_connected = False
    
    async def list_files(self, **kwargs):
        return []
    
    async def read_file(self, **kwargs):
        return ""
    
    async def get_file_info(self, **kwargs):
        return FileInfo(path="/mock", name="mock.txt")
    
    async def execute_command(self, **kwargs):
        return {'stdout': '', 'stderr': '', 'exit_code': 0, 'success': True}


class TestConnectionResult:
    """测试连接结果数据类"""
    
    def test_success_result(self):
        from src.remote.connectors.base_connector import (
            ConnectionResult,
            ConnectionStatus
        )
        
        result = ConnectionResult(
            success=True,
            status=ConnectionStatus.CONNECTED,
            message="Connected successfully",
            latency_ms=50.5
        )
        
        assert result.is_success
        assert result.latency_ms == 50.5
    
    def test_failure_result(self):
        from src.remote.connectors.base_connector import (
            ConnectionResult,
            ConnectionStatus
        )
        
        error = Exception("Connection refused")
        result = ConnectionResult(
            success=False,
            status=ConnectionStatus.ERROR,
            message="Failed to connect",
            error=error
        )
        
        assert not result.is_success
        assert result.error == error


class TestCredentialManager:
    """测试凭证管理器"""
    
    def test_credential_creation(self):
        from src.remote.security import Credential
        
        cred = Credential(
            name="test-ssh",
            credential_type="password",
            value="secret123",
            username="admin",
            host="192.168.1.100"
        )
        
        assert cred.name == "test-ssh"
        assert cred.credential_type == "password"
        assert cred.username == "admin"
        assert not cred.is_expired()
    
    def test_expired_credential(self):
        from src.remote.security import Credential
        
        expired_cred = Credential(
            name="expired-token",
            credential_type="token",
            value="old_token",
            expires_at=datetime.now() - timedelta(days=1)
        )
        
        assert expired_cred.is_expired()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
