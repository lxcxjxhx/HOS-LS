"""LSP插件模块

为IDE提供HOS-LS的LSP集成功能。
"""

import os
import subprocess
import sys
import json
from typing import Dict, Any, Optional

from src.plugins.base import Plugin


class LSPPlugin(Plugin):
    """LSP插件"""
    
    def __init__(self):
        super().__init__(
            name="lsp",
            description="为IDE提供实时漏洞检测功能",
            version="1.0.0"
        )
        self.server_process = None
    
    def activate(self) -> bool:
        """激活插件"""
        try:
            # 检查依赖
            self._check_dependencies()
            
            # 启动LSP服务器
            self._start_lsp_server()
            
            self.logger.info("LSP插件激活成功")
            return True
        except Exception as e:
            self.logger.error(f"LSP插件激活失败: {e}")
            return False
    
    def deactivate(self) -> bool:
        """停用插件"""
        try:
            # 停止LSP服务器
            self._stop_lsp_server()
            
            self.logger.info("LSP插件停用成功")
            return True
        except Exception as e:
            self.logger.error(f"LSP插件停用失败: {e}")
            return False
    
    def _check_dependencies(self) -> None:
        """检查依赖"""
        try:
            import pygls
            self.logger.info("pygls依赖检查通过")
        except ImportError:
            self.logger.error("缺少pygls依赖，请运行: pip install pygls")
            raise
    
    def _start_lsp_server(self) -> None:
        """启动LSP服务器"""
        # 构建LSP服务器命令
        server_script = os.path.join(os.path.dirname(__file__), "..", "integration", "lsp_server.py")
        server_script = os.path.abspath(server_script)
        
        # 启动服务器进程
        self.server_process = subprocess.Popen(
            [sys.executable, server_script],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        
        self.logger.info(f"LSP服务器已启动，进程ID: {self.server_process.pid}")
    
    def _stop_lsp_server(self) -> None:
        """停止LSP服务器"""
        if self.server_process:
            try:
                self.server_process.terminate()
                self.server_process.wait(timeout=5)
                self.logger.info("LSP服务器已停止")
            except Exception as e:
                self.logger.error(f"停止LSP服务器时出错: {e}")
            finally:
                self.server_process = None
    
    def get_configuration(self) -> Dict[str, Any]:
        """获取插件配置"""
        return {
            "lsp": {
                "enabled": True,
                "server_path": os.path.join(os.path.dirname(__file__), "..", "integration", "lsp_server.py"),
                "port": 2087,
                "timeout": 30
            }
        }
    
    def set_configuration(self, config: Dict[str, Any]) -> bool:
        """设置插件配置"""
        try:
            self.config.update(config.get("lsp", {}))
            self.logger.info("LSP插件配置已更新")
            return True
        except Exception as e:
            self.logger.error(f"设置LSP插件配置失败: {e}")
            return False
    
    def run(self, **kwargs) -> Dict[str, Any]:
        """运行插件"""
        # LSP插件主要通过后台服务器运行，这里返回服务器状态
        return {
            "status": "running" if self.server_process and self.server_process.poll() is None else "stopped",
            "pid": self.server_process.pid if self.server_process else None
        }


# 插件入口
def create_plugin():
    """创建插件实例"""
    return LSPPlugin()
