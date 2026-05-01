"""
NetworkManager - 容器网络管理器

管理Docker容器网络的创建、隔离和清理。
"""

import docker
import logging
from typing import Optional, List, Dict


logger = logging.getLogger(__name__)


class NetworkManager:
    """Docker网络管理器"""

    DEFAULT_NETWORK_NAME = "hos-ls-network"
    NETWORK_SUBNET = "172.20.0.0/16"

    def __init__(self, network_name: Optional[str] = None):
        self.network_name = network_name or self.DEFAULT_NETWORK_NAME
        self.network: Optional[docker.models.networks.Network] = None
        self._client_initialized = False
        self._client = None

    def _get_client(self):
        """获取Docker客户端（延迟初始化）"""
        if not self._client_initialized:
            try:
                self._client = docker.from_env()
                self._client_initialized = True
            except Exception as e:
                logger.warning(f"Failed to initialize Docker client: {e}")
                self._client = None
                self._client_initialized = True
        return self._client

    @property
    def client(self):
        """获取Docker客户端（兼容属性）"""
        return self._get_client()

    def is_available(self) -> bool:
        """检查Docker是否可用"""
        try:
            client = self._get_client()
            if client is None:
                return False
            client.ping()
            return True
        except Exception as e:
            logger.warning(f"Docker is not available: {e}")
            return False

    def ensure_network(self) -> docker.models.networks.Network:
        """确保网络存在"""
        try:
            client = self._get_client()
            if client is None:
                raise RuntimeError("Docker client is not available")
            self.network = client.networks.get(self.network_name)
            logger.info(f"Using existing network: {self.network_name}")
            return self.network
        except docker.errors.NotFound:
            logger.info(f"Creating new network: {self.network_name}")
            return self._create_network()
        except Exception as e:
            logger.error(f"Error getting network: {e}")
            raise

    def _create_network(self) -> docker.models.networks.Network:
        """创建网络"""
        try:
            client = self._get_client()
            if client is None:
                raise RuntimeError("Docker client is not available")
            self.network = client.networks.create(
                self.network_name,
                driver="bridge",
                enable_ipv6=False,
                check_duplicate=True,
            )
            logger.info(f"Created network: {self.network_name}")
            return self.network
        except Exception as e:
            logger.error(f"Failed to create network: {e}")
            raise

    def get_network(self) -> Optional[docker.models.networks.Network]:
        """获取当前网络对象"""
        if self.network:
            return self.network

        try:
            client = self._get_client()
            if client is None:
                return None
            self.network = client.networks.get(self.network_name)
            return self.network
        except docker.errors.NotFound:
            return None
        except Exception as e:
            logger.error(f"Error getting network: {e}")
            return None

    def connect_container(self, container: docker.models.containers.Container) -> bool:
        """将容器连接到网络"""
        try:
            network = self.ensure_network()
            network.connect(container)
            logger.info(f"Connected container {container.id[:12]} to network {self.network_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect container to network: {e}")
            return False

    def disconnect_container(self, container: docker.models.containers.Container) -> bool:
        """将容器从网络断开"""
        try:
            network = self.get_network()
            if network:
                network.disconnect(container)
                logger.info(f"Disconnected container {container.id[:12]} from network {self.network_name}")
            return True
        except Exception as e:
            logger.warning(f"Failed to disconnect container from network: {e}")
            return False

    def cleanup_network(self) -> bool:
        """清理网络（如果有容器则跳过）"""
        try:
            network = self.get_network()
            if not network:
                return True

            containers = network.containers
            if containers:
                logger.warning(f"Cannot remove network {self.network_name}: {len(containers)} containers still connected")
                return False

            network.remove()
            self.network = None
            logger.info(f"Removed network: {self.network_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to cleanup network: {e}")
            return False

    def list_connected_containers(self) -> List[Dict]:
        """列出网络中的容器"""
        try:
            network = self.get_network()
            if not network:
                return []

            containers = network.containers
            return [
                {
                    "id": c.id[:12],
                    "name": c.name,
                    "status": c.status,
                }
                for c in containers
            ]
        except Exception as e:
            logger.error(f"Failed to list connected containers: {e}")
            return []

    def get_network_info(self) -> Optional[Dict]:
        """获取网络信息"""
        try:
            network = self.get_network()
            if not network:
                return None

            return {
                "name": network.name,
                "id": network.id,
                "driver": network.driver,
                "ipam": network.attrs.get("IPAM", {}),
                "containers": len(network.containers),
            }
        except Exception as e:
            logger.error(f"Failed to get network info: {e}")
            return None
