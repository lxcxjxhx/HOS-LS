import os
import logging
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from .sandbox_manager import SandboxEnvironmentManager, SandboxInfo

logger = logging.getLogger(__name__)


class SandboxIntegration:
    def __init__(
        self,
        sandbox_root: Optional[str] = None,
        auto_cleanup: bool = True,
        enabled: bool = True
    ):
        self._manager = SandboxEnvironmentManager(sandbox_root)
        self._auto_cleanup = auto_cleanup
        self._enabled = enabled
        self._active_sandbox_id: Optional[str] = None
        self._active_sandbox_path: Optional[str] = None
        self._started_services: List[str] = []

    @property
    def enabled(self) -> bool:
        return self._enabled

    @enabled.setter
    def enabled(self, value: bool) -> None:
        self._enabled = value

    @property
    def auto_cleanup(self) -> bool:
        return self._auto_cleanup

    @auto_cleanup.setter
    def auto_cleanup(self, value: bool) -> None:
        self._auto_cleanup = value

    @property
    def active_sandbox_path(self) -> Optional[str]:
        return self._active_sandbox_path

    @property
    def active_sandbox_id(self) -> Optional[str]:
        return self._active_sandbox_id

    def copy_project_to_sandbox(self, project_path: str) -> str:
        if not self._enabled:
            return project_path

        if not os.path.exists(project_path):
            raise FileNotFoundError(f"Project path does not exist: {project_path}")

        try:
            sandbox_path = self._manager.copy_project_to_sandbox(project_path)
            self._active_sandbox_path = sandbox_path

            for sandbox_info in self._manager.list_sandboxes():
                if sandbox_info.sandbox_path == sandbox_path:
                    self._active_sandbox_id = sandbox_info.sandbox_id
                    break

            logger.info(f"Project copied to sandbox: {sandbox_path}")
            return sandbox_path

        except Exception as e:
            logger.error(f"Failed to copy project to sandbox: {e}")
            raise RuntimeError(f"Failed to copy project to sandbox: {e}") from e

    def start_service(self, sandbox_path: Optional[str] = None, port: int = 8080) -> str:
        if not self._enabled:
            raise RuntimeError("Sandbox is disabled, cannot start service")

        target_path = sandbox_path or self._active_sandbox_path
        if not target_path:
            raise ValueError("No sandbox path available, call copy_project_to_sandbox first")

        try:
            service_id = self._manager.start_isolated_service(target_path, port)
            self._started_services.append(service_id)
            logger.info(f"Started service in sandbox: {service_id}")
            return service_id

        except Exception as e:
            logger.error(f"Failed to start service in sandbox: {e}")
            raise RuntimeError(f"Failed to start service in sandbox: {e}") from e

    def stop_service(self, service_id: str) -> bool:
        if not self._enabled:
            return False

        try:
            result = self._manager.stop_isolated_service(service_id)
            if service_id in self._started_services:
                self._started_services.remove(service_id)
            return result

        except Exception as e:
            logger.error(f"Failed to stop service {service_id}: {e}")
            return False

    def cleanup(self) -> bool:
        if not self._enabled:
            return True

        if self._active_sandbox_id:
            try:
                for service_id in list(self._started_services):
                    self._manager.stop_isolated_service(service_id)
                self._started_services.clear()

                result = self._manager.cleanup_sandbox(self._active_sandbox_id)
                if result:
                    logger.info(f"Cleaned up sandbox: {self._active_sandbox_id}")
                self._active_sandbox_id = None
                self._active_sandbox_path = None
                return result

            except Exception as e:
                logger.error(f"Failed to cleanup sandbox: {e}")
                return False

        return True

    def get_sandbox_info(self, sandbox_id: Optional[str] = None) -> Optional[SandboxInfo]:
        target_id = sandbox_id or self._active_sandbox_id
        if not target_id:
            return None
        return self._manager.get_sandbox_info(target_id)

    def list_sandboxes(self) -> List[SandboxInfo]:
        return self._manager.list_sandboxes()

    def __enter__(self) -> 'SandboxIntegration':
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> bool:
        if self._auto_cleanup:
            self.cleanup()
        return False

    @contextmanager
    def run_scan_in_sandbox(self, project_path: str):
        if not self._enabled:
            yield project_path
            return

        try:
            sandbox_path = self.copy_project_to_sandbox(project_path)
            yield sandbox_path

        except Exception as e:
            logger.error(f"Sandbox scan failed: {e}")
            yield project_path

        finally:
            if self._auto_cleanup:
                self.cleanup()


def create_sandbox_integration(
    config: Optional[Dict[str, Any]] = None,
    sandbox_root: Optional[str] = None
) -> SandboxIntegration:
    if config:
        enabled = config.get('sandbox_enabled', True)
        auto_cleanup = config.get('auto_cleanup', True)
        root = config.get('sandbox_root', sandbox_root)
    else:
        enabled = True
        auto_cleanup = True
        root = sandbox_root

    return SandboxIntegration(
        sandbox_root=root,
        auto_cleanup=auto_cleanup,
        enabled=enabled
    )
