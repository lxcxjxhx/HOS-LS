"""Go 工具管理器

负责 Go 运行时安装、Go 工具安装、GOPROXY 换源，带 tqdm 进度条。
"""

import logging
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

import httpx
from tqdm import tqdm

from .mirror import MirrorManager, find_fastest_goproxy_mirror

logger = logging.getLogger(__name__)

DEFAULT_GO_VERSION = "1.22.5"
GO_TOOLS = {
    "nuclei": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "httpx": "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "ffuf": "github.com/ffuf/ffuf/v2@latest",
    "subfinder": "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
}


class GoManager:
    """Go 工具管理器"""

    def __init__(
        self,
        mirror_manager: Optional[MirrorManager] = None,
        go_proxy: Optional[str] = None,
        go_version: str = DEFAULT_GO_VERSION,
    ):
        self.mirror_manager = mirror_manager or MirrorManager()
        self._go_proxy = go_proxy
        self.go_version = go_version

    @property
    def go_proxy(self) -> str:
        """获取 GOPROXY 值"""
        if self._go_proxy:
            return self._go_proxy
        return self.mirror_manager.get_go_proxy()

    def _go_env(self) -> dict[str, str]:
        """构建 Go 命令环境变量"""
        env = os.environ.copy()
        env["GOPROXY"] = self.go_proxy
        env["GO111MODULE"] = "on"
        env["CGO_ENABLED"] = "0"
        return env

    def is_go_installed(self) -> bool:
        """检测 Go 是否已安装"""
        return shutil.which("go") is not None

    def get_go_version(self) -> Optional[str]:
        """获取已安装 Go 版本"""
        try:
            result = subprocess.run(
                ["go", "version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                parts = output.split()
                if len(parts) >= 3:
                    return parts[2].replace("go", "")
        except Exception:
            pass
        return None

    def _get_go_download_url(self) -> tuple[str, str]:
        """获取 Go 下载 URL 和文件名

        Returns:
            (下载URL, 文件名)
        """
        system = platform.system().lower()
        machine = platform.machine().lower()

        arch_map = {
            "x86_64": "amd64",
            "amd64": "amd64",
            "aarch64": "arm64",
            "arm64": "arm64",
            "i386": "386",
            "i686": "386",
        }
        arch = arch_map.get(machine, "amd64")

        if system == "windows":
            filename = f"go{self.go_version}.windows-{arch}.zip"
            url = f"https://golang.google.cn/dl/{filename}"
        elif system == "linux":
            filename = f"go{self.go_version}.linux-{arch}.tar.gz"
            url = f"https://golang.google.cn/dl/{filename}"
        elif system == "darwin":
            filename = f"go{self.go_version}.darwin-{arch}.tar.gz"
            url = f"https://golang.google.cn/dl/{filename}"
        else:
            raise OSError(f"不支持的操作系统: {system}")

        return url, filename

    def install_go(self, target_dir: Optional[str] = None) -> bool:
        """安装 Go 运行时

        Args:
            target_dir: 安装目录（默认 /usr/local/go 或用户目录）

        Returns:
            是否成功
        """
        if self.is_go_installed():
            current = self.get_go_version()
            logger.info("[GO] Go 已安装 (版本: %s)", current)
            return True

        url, filename = self._get_go_download_url()
        logger.info("[GO] 下载 Go %s: %s", self.go_version, url)

        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, filename)

            try:
                self._download_with_progress(url, filepath)
            except Exception as e:
                logger.error("[GO] 下载失败: %s", e)
                return False

            install_dir = target_dir or self._default_install_dir()
            return self._extract_go(filepath, install_dir)

    def _download_with_progress(self, url: str, filepath: str) -> None:
        """下载文件（带 tqdm 进度条）"""
        with httpx.stream("GET", url, follow_redirects=True, timeout=60) as response:
            response.raise_for_status()
            total = int(response.headers.get("content-length", 0))

            with open(filepath, "wb") as f:
                with tqdm(
                    total=total,
                    unit="B",
                    unit_scale=True,
                    unit_divisor=1024,
                    desc=f"下载 {os.path.basename(filepath)}",
                ) as pbar:
                    for chunk in response.iter_bytes(chunk_size=8192):
                        f.write(chunk)
                        pbar.update(len(chunk))

    def _extract_go(self, archive_path: str, install_dir: str) -> bool:
        """解压 Go 安装包"""
        logger.info("[GO] 解压到 %s", install_dir)

        try:
            if archive_path.endswith(".zip"):
                import zipfile

                with zipfile.ZipFile(archive_path, "r") as zf:
                    zf.extractall(install_dir)
            else:
                import tarfile

                with tarfile.open(archive_path, "r:gz") as tf:
                    tf.extractall(install_dir)

            go_bin = os.path.join(install_dir, "go", "bin", "go")
            if os.name == "nt":
                go_bin += ".exe"

            if os.path.exists(go_bin):
                logger.info("[GO] Go 安装成功: %s", go_bin)
                self._add_to_path(os.path.join(install_dir, "go", "bin"))
                return True

            logger.error("[GO] 安装后未找到 go 可执行文件")
            return False

        except Exception as e:
            logger.error("[GO] 解压失败: %s", e)
            return False

    def _default_install_dir(self) -> str:
        """获取默认安装目录"""
        if os.name == "nt":
            return os.path.expanduser("~\\GoInstall")
        return "/usr/local"

    def _add_to_path(self, bin_dir: str) -> None:
        """将目录添加到 PATH（当前进程）"""
        if bin_dir not in os.environ.get("PATH", ""):
            os.environ["PATH"] = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}"
            logger.info("[GO] 已添加到 PATH: %s", bin_dir)

    def install_go_tool(self, name: str, module_path: Optional[str] = None) -> bool:
        """安装单个 Go 工具

        Args:
            name: 工具名称
            module_path: Go module 路径（如不指定则使用预定义映射）

        Returns:
            是否成功
        """
        if not self.is_go_installed():
            logger.error("[GO] Go 未安装，无法安装工具: %s", name)
            return False

        module = module_path or GO_TOOLS.get(name)
        if not module:
            logger.error("[GO] 未知的 Go 工具: %s", name)
            return False

        logger.info("[GO] 安装 %s (GOPROXY=%s) ...", name, self.go_proxy)

        cmd = ["go", "install", "-v", module]
        env = self._go_env()

        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                encoding="utf-8",
                errors="replace",
            )

            with tqdm(desc=f"安装 {name}", unit="step", leave=True) as pbar:
                for line in process.stdout:
                    line = line.strip()
                    if line:
                        logger.debug("[GO] %s", line)
                    pbar.update(1)

            process.wait()
            success = process.returncode == 0

            if success:
                gopath = self._get_gopath()
                self._add_to_path(os.path.join(gopath, "bin"))
                logger.info("[GO] ✓ %s 安装成功", name)
            else:
                logger.error("[GO] ✗ %s 安装失败", name)

            return success

        except FileNotFoundError:
            logger.error("[GO] 找不到 go 命令，请确认 Go 已安装并添加到 PATH")
            return False
        except Exception as e:
            logger.error("[GO] 安装 %s 失败: %s", name, e)
            return False

    def install_go_tools(
        self,
        tools: Optional[list[str]] = None,
    ) -> dict[str, bool]:
        """批量安装 Go 工具

        Args:
            tools: 工具名列表，为 None 时安装所有预定义工具

        Returns:
            {工具名: 是否成功}
        """
        tool_list = tools or list(GO_TOOLS.keys())
        results = {}

        for name in tool_list:
            results[name] = self.install_go_tool(name)

        success_count = sum(1 for v in results.values() if v)
        logger.info(
            "[GO] 工具安装完成: %d/%d 成功",
            success_count,
            len(results),
        )

        # 安装 nuclei 后预下载模板
        if "nuclei" in tool_list and results.get("nuclei"):
            self._download_nuclei_templates()

        return results

    def _download_nuclei_templates(self, timeout: int = 300) -> bool:
        """预下载 nuclei 模板（首次安装后自动执行）

        Args:
            timeout: 超时时间（秒）

        Returns:
            是否成功
        """
        logger.info("[GO] 预下载 nuclei 模板（约8000+模板）...")
        try:
            cmd = ["nuclei", "-update-templates", "-silent"]
            env = self._go_env()
            # 设置代理环境变量让nuclei也能使用代理下载模板
            env["HTTP_PROXY"] = self.go_proxy
            env["HTTPS_PROXY"] = self.go_proxy

            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                env=env,
                encoding="utf-8",
                errors="replace",
            )

            with tqdm(desc="下载 nuclei 模板", unit="line", leave=True) as pbar:
                for line in process.stdout:
                    line = line.strip()
                    if line:
                        logger.debug("[NUCLEI-TPL] %s", line)
                    pbar.update(1)

            process.wait()
            success = process.returncode == 0

            if success:
                logger.info("[GO] ✓ nuclei 模板下载完成")
            else:
                logger.warning("[GO] nuclei 模板下载可能未完成，后续扫描会自动下载")

            return success

        except FileNotFoundError:
            logger.warning("[GO] 找不到 nuclei 命令，跳过模板预下载")
            return False
        except Exception as e:
            logger.error("[GO] nuclei 模板下载失败: %s", e)
            return False

    def _get_gopath(self) -> str:
        """获取 GOPATH"""
        gopath = os.environ.get("GOPATH")
        if gopath:
            return gopath
        return os.path.join(os.path.expanduser("~"), "go")

    def auto_detect_proxy(self, timeout: float = 5.0) -> bool:
        """自动检测最快 Go 代理并切换

        Args:
            timeout: 超时时间（秒）

        Returns:
            是否成功找到可用代理
        """
        logger.info("[GO] 自动检测最快 GOPROXY...")
        fastest = find_fastest_goproxy_mirror(timeout=timeout)
        if fastest:
            self._go_proxy = fastest
            logger.info("[GO] 已切换到代理: %s", fastest)
            return True
        self._go_proxy = "https://goproxy.cn"
        logger.info("[GO] 使用默认代理: %s", self._go_proxy)
        return True
