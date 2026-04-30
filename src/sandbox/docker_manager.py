import logging
try:
    import docker
    from docker.errors import DockerException, ImageNotFound
    DOCKER_AVAILABLE = True
except ImportError:
    docker = None
    DockerException = Exception
    ImageNotFound = Exception
    DOCKER_AVAILABLE = False

logger = logging.getLogger(__name__)


class DockerManager:
    RUNTIME_IMAGES = {
        'java': 'eclipse-temurin:11-jdk',
        'go': 'golang:1.21-alpine',
        'rust': 'rust:1.75-slim',
        'c': 'gcc:13-bookworm',
        'typescript': 'node:20-alpine',
        'python': 'python:3.11-slim',
        'javascript': 'node:20-alpine'
    }

    def __init__(self, auto_pull: bool = True):
        try:
            self.client = docker.from_env()
            self.auto_pull = auto_pull
            if self.auto_pull:
                self._ensure_images()
        except DockerException as e:
            logger.warning(f"Failed to initialize Docker client: {e}")
            self.client = None

    def _ensure_images(self):
        if not self.client:
            return
        for lang, image in self.RUNTIME_IMAGES.items():
            if not self._image_exists(image):
                try:
                    logger.info(f"Pulling image for {lang}: {image}")
                    self.client.images.pull(image)
                except DockerException as e:
                    logger.warning(f"Failed to pull image {image}: {e}")

    def _image_exists(self, image: str) -> bool:
        if not self.client:
            return False
        try:
            self.client.images.get(image)
            return True
        except (DockerException, ImageNotFound):
            return False

    def is_available(self) -> bool:
        if not self.client:
            return False
        try:
            self.client.ping()
            return True
        except DockerException:
            return False

    def execute(self, language: str, code: str, timeout: int = 30) -> dict:
        image = self.RUNTIME_IMAGES.get(language)
        if not image:
            return {'success': False, 'error': f'Unsupported language: {language}'}

        if not self.is_available():
            return {'success': False, 'error': 'Docker is not available'}

        if not self._image_exists(image):
            if self.auto_pull:
                try:
                    logger.info(f"Pulling image: {image}")
                    self.client.images.pull(image)
                except DockerException as e:
                    return {'success': False, 'error': f'Failed to pull image: {e}'}
            else:
                return {'success': False, 'error': f'Image not found: {image}'}

        try:
            container = self.client.containers.run(
                image,
                f'sh -c "echo \'{code}\' | /bin/sh"',
                detach=True,
                network_disabled=True,
                mem_limit='512m',
                auto_remove=True
            )
            result = container.wait(timeout=timeout)
            logs = container.logs().decode('utf-8')
            return {
                'success': result.get('StatusCode', 1) == 0,
                'output': logs,
                'exit_code': result.get('StatusCode', 1)
            }
        except Exception as e:
            return {'success': False, 'error': str(e)}
