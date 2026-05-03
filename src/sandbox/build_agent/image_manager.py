"""
ImageManager - Docker镜像管理器

管理Docker镜像的拉取、缓存和清理。
"""

import docker
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass


logger = logging.getLogger(__name__)


@dataclass
class RuntimeImage:
    """运行时镜像配置"""
    language: str
    image: str
    tag: str
    variants: Dict[str, str]


RUNTIME_IMAGES: Dict[str, RuntimeImage] = {
    "java_maven": RuntimeImage(
        language="java",
        image="maven",
        tag="3.9-eclipse-temurin-11",
        variants={
            "8": "maven:3.9-eclipse-temurin-8",
            "11": "maven:3.9-eclipse-temurin-11",
            "17": "maven:3.9-eclipse-temurin-17",
            "21": "maven:3.9-eclipse-temurin-21",
        }
    ),
    "java_gradle": RuntimeImage(
        language="java",
        image="gradle",
        tag="8.5-eclipse-temurin-11",
        variants={
            "8": "gradle:8.5-eclipse-temurin-8",
            "11": "gradle:8.5-eclipse-temurin-11",
            "17": "gradle:8.5-eclipse-temurin-17",
            "21": "gradle:8.5-eclipse-temurin-21",
        }
    ),
    "node_js": RuntimeImage(
        language="node",
        image="node",
        tag="20-alpine",
        variants={
            "18": "node:18-alpine",
            "20": "node:20-alpine",
            "21": "node:21-alpine",
        }
    ),
    "python": RuntimeImage(
        language="python",
        image="python",
        tag="3.11-slim",
        variants={
            "3.9": "python:3.9-slim",
            "3.10": "python:3.10-slim",
            "3.11": "python:3.11-slim",
            "3.12": "python:3.12-slim",
        }
    ),
    "go": RuntimeImage(
        language="go",
        image="golang",
        tag="1.21-alpine",
        variants={
            "1.20": "golang:1.20-alpine",
            "1.21": "golang:1.21-alpine",
            "1.22": "golang:1.22-alpine",
        }
    ),
    "rust": RuntimeImage(
        language="rust",
        image="rust",
        tag="1.75-slim",
        variants={
            "1.70": "rust:1.70-slim",
            "1.75": "rust:1.75-slim",
            "1.76": "rust:1.76-slim",
        }
    ),
}


class ImageManager:
    """Docker镜像管理器"""

    def __init__(self, auto_pull: bool = True, registry_auth: Optional[Dict] = None):
        self.auto_pull = auto_pull
        self.registry_auth = registry_auth
        self._cached_images: Dict[str, bool] = {}
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

    def pull_image(self, image: str, tag: str = "latest") -> bool:
        """拉取镜像"""
        full_image = f"{image}:{tag}"
        try:
            logger.info(f"Pulling image: {full_image}")
            self.client.images.pull(image, tag=tag)
            logger.info(f"Successfully pulled: {full_image}")
            return True
        except Exception as e:
            logger.error(f"Failed to pull {full_image}: {e}")
            return False

    def ensure_image(self, project_type: str, version: Optional[str] = None) -> Optional[str]:
        """确保所需镜像存在"""
        if project_type not in RUNTIME_IMAGES:
            logger.error(f"Unknown project type: {project_type}")
            return None

        runtime_image = RUNTIME_IMAGES[project_type]

        if version and version in runtime_image.variants:
            full_image = runtime_image.variants[version]
        else:
            full_image = f"{runtime_image.image}:{runtime_image.tag}"

        cache_key = f"{project_type}:{version or 'default'}"
        if cache_key in self._cached_images:
            return full_image

        if not self._image_exists(full_image):
            if self.auto_pull:
                tag_to_pull = version or runtime_image.tag
                if not self.pull_image(runtime_image.image, tag=tag_to_pull):
                    return None
            else:
                logger.error(f"Required image not found: {full_image}")
                return None

        self._cached_images[cache_key] = True
        return full_image

    def _image_exists(self, full_image: str) -> bool:
        """检查镜像是否存在"""
        try:
            self.client.images.get(full_image)
            return True
        except docker.errors.NotFound:
            return False
        except Exception as e:
            logger.warning(f"Error checking image {full_image}: {e}")
            return False

    def list_cached_images(self) -> List[str]:
        """列出已缓存的镜像"""
        return list(self._cached_images.keys())

    def cleanup_unused(self) -> int:
        """清理未使用的镜像"""
        try:
            pruned, _ = self.client.images.prune()
            return len(pruned.get("ImagesDeleted", []))
        except Exception as e:
            logger.error(f"Failed to cleanup images: {e}")
            return 0

    def get_image_info(self, full_image: str) -> Optional[Dict]:
        """获取镜像信息"""
        try:
            image = self.client.images.get(full_image)
            return {
                "id": image.id,
                "tags": image.tags,
                "size": image.attrs.get("Size", 0),
                "created": image.attrs.get("Created", ""),
            }
        except Exception as e:
            logger.error(f"Failed to get image info for {full_image}: {e}")
            return None

    def list_all_images(self) -> List[Dict]:
        """列出所有镜像"""
        try:
            images = self.client.images.list()
            return [
                {
                    "id": img.id,
                    "tags": img.tags,
                    "size": img.attrs.get("Size", 0),
                }
                for img in images
            ]
        except Exception as e:
            logger.error(f"Failed to list images: {e}")
            return []
