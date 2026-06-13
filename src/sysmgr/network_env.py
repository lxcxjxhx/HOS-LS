"""网络环境管理器

处理 VPN、代理、镜像换源、网络连通性检测等。
支持多种渗透测试场景：
- 公网直连
- 公网代理（HTTP/HTTPS/SOCKS）
- VPN 内网渗透
- 离线/隔离网络
"""

import logging
import os
import platform
import socket
import subprocess
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from .smart_network import SmartNetworkOrchestrator

logger = logging.getLogger(__name__)


class NetworkMode(Enum):
    """网络模式"""
    AUTO = "auto"           # 自动检测
    DIRECT = "direct"       # 强制直连（无代理）
    PROXY = "proxy"         # 强制代理
    VPN = "vpn"             # VPN 内网模式
    OFFLINE = "offline"     # 离线模式（使用本地工具）


@dataclass
class NetworkConfig:
    """网络配置"""
    mode: NetworkMode = NetworkMode.AUTO
    proxy_url: Optional[str] = None
    vpn_interface: Optional[str] = None
    no_proxy: list[str] = field(default_factory=list)
    dns_servers: list[str] = field(default_factory=list)
    timeout: float = 10.0


class NetworkEnvManager:
    """网络环境管理器"""

    # 常用代理/镜像检测列表
    PROXY_MIRRORS = {
        "goproxy": [
            "https://goproxy.cn",
            "https://goproxy.io",
            "https://proxy.golang.org",
            "https://mirrors.aliyun.com/goproxy",
        ],
        "pypi": [
            "https://pypi.org/simple",
            "https://mirrors.aliyun.com/pypi/simple",
            "https://pypi.tuna.tsinghua.edu.cn/simple",
            "https://pypi.mirrors.ustc.edu.cn/simple",
        ],
        "npm": [
            "https://registry.npmjs.org",
            "https://registry.npmmirror.com",
            "https://mirrors.cloud.tencent.com/npm",
        ],
    }

    # 网络连通性检测目标
    CONNECTIVITY_CHECKS = {
        "baidu": ("www.baidu.com", 443),
        "google": ("www.google.com", 443),
        "cloudflare": ("1.1.1.1", 443),
        "dns": ("8.8.8.8", 53),
    }

    def __init__(self, config: Optional[NetworkConfig] = None):
        self.config = config or NetworkConfig()
        self._detected_env: dict = {}
        self._orchestrator = SmartNetworkOrchestrator()

    def detect_network_mode(self) -> NetworkMode:
        """自动检测当前网络环境"""
        t0 = time.time()
        logger.info("[NET] 检测网络环境...")

        # 1. 检查环境变量代理设置
        t1 = time.time()
        proxy_env = self._detect_proxy_env()
        if proxy_env:
            logger.info("[NET] 检测到代理环境变量: %s", proxy_env)
            self.config.proxy_url = proxy_env
        logger.debug("[NET] 代理检测耗时: %.0fms", (time.time() - t1) * 1000)

        # 2. 检测 VPN 连接
        t2 = time.time()
        vpn_detected = self._detect_vpn()
        if vpn_detected:
            logger.info("[NET] 检测到 VPN 连接: %s", vpn_detected)
            self.config.vpn_interface = vpn_detected
        logger.debug("[NET] VPN 检测耗时: %.0fms", (time.time() - t2) * 1000)

        # 3. 测试网络连通性
        t3 = time.time()
        connectivity = self.test_connectivity()
        logger.debug("[NET] 连通性测试耗时: %.0fms", (time.time() - t3) * 1000)

        # 4. 判断模式
        if not connectivity.get("internet", False):
            if connectivity.get("local", False):
                logger.info("[NET] 模式: 本地网络/内网")
                mode = NetworkMode.VPN
            else:
                logger.info("[NET] 模式: 离线/无网络")
                mode = NetworkMode.OFFLINE
        elif self.config.proxy_url:
            logger.info("[NET] 模式: 代理模式")
            mode = NetworkMode.PROXY
        else:
            logger.info("[NET] 模式: 直连")
            mode = NetworkMode.DIRECT

        logger.debug("[NET] 网络环境检测总耗时: %.0fms, 结果: %s", (time.time() - t0) * 1000, mode.value)
        return mode

    def _detect_proxy_env(self) -> Optional[str]:
        """检测代理环境变量"""
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"]:
            val = os.environ.get(var)
            if val and not val.startswith("localhost"):
                return val
        # Windows 注册表代理
        if platform.system() == "Windows":
            try:
                import winreg
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
                )
                proxy_enable, _ = winreg.QueryValueEx(key, "ProxyEnable")
                if proxy_enable:
                    proxy_server, _ = winreg.QueryValueEx(key, "ProxyServer")
                    return f"http://{proxy_server}"
            except Exception:
                pass
        return None

    def _detect_vpn(self) -> Optional[str]:
        """检测 VPN 连接"""
        system = platform.system()

        if system == "Windows":
            return self._detect_vpn_windows()
        elif system == "Linux":
            return self._detect_vpn_linux()
        elif system == "Darwin":
            return self._detect_vpn_macos()
        return None

    def _detect_vpn_windows(self) -> Optional[str]:
        """检测 Windows VPN"""
        try:
            # 检查路由表是否有 VPN 特征
            result = subprocess.run(
                ["route", "print", "0.0.0.0"],
                capture_output=True, text=True, timeout=10,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            output = result.stdout
            # 检测常见的 VPN 接口特征
            vpn_indicators = ["WireGuard", "OpenVPN", "TAP", "TUN", "Cisco", "GlobalProtect", "Pulse", "FortiSSL"]
            for indicator in vpn_indicators:
                if indicator.lower() in output.lower():
                    return f"Windows VPN ({indicator})"
            # 检查非本地网关
            for line in output.split("\n"):
                if "0.0.0.0" in line and "127.0.0.1" not in line:
                    parts = line.split()
                    if len(parts) >= 4 and not parts[3].startswith("192.168.") and not parts[3].startswith("10."):
                        return f"Windows VPN (gateway: {parts[3]})"
        except Exception as e:
            logger.debug("[NET] VPN 检测失败: %s", e)
        return None

    def _detect_vpn_linux(self) -> Optional[str]:
        """检测 Linux VPN"""
        try:
            # 检查 tun/tap 接口
            result = subprocess.run(
                ["ip", "link", "show"],
                capture_output=True, text=True, timeout=10,
            )
            for line in result.stdout.split("\n"):
                if "tun" in line.lower() or "tap" in line.lower() or "wg" in line.lower():
                    parts = line.split(":")
                    if len(parts) >= 2:
                        return f"Linux VPN ({parts[1].strip()})"
        except Exception:
            pass
        return None

    def _detect_vpn_macos(self) -> Optional[str]:
        """检测 macOS VPN"""
        try:
            result = subprocess.run(
                ["scutil", "--nethost"],
                capture_output=True, text=True, timeout=10,
            )
            if "utun" in result.stdout.lower():
                return "macOS VPN (utun)"
        except Exception:
            pass
        return None

    def test_connectivity(self) -> dict:
        """测试网络连通性"""
        t0 = time.time()
        results = {"internet": False, "local": False, "dns": False, "details": {}}

        # 测试 DNS
        t_dns = time.time()
        try:
            socket.setdefaulttimeout(3)
            socket.gethostbyname("www.baidu.com")
            results["dns"] = True
            logger.debug("[NET] DNS 测试成功: www.baidu.com (耗时: %.0fms)", (time.time() - t_dns) * 1000)
        except Exception:
            logger.debug("[NET] DNS 测试失败: www.baidu.com (耗时: %.0fms)", (time.time() - t_dns) * 1000)

        # 测试外网连通
        for name, (host, port) in self.CONNECTIVITY_CHECKS.items():
            t_conn = time.time()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((host, port))
                sock.close()
                elapsed = (time.time() - t_conn) * 1000
                results["details"][name] = result == 0
                if result == 0:
                    results["internet"] = True
                    logger.debug("[NET] 外网连通 %s:%d OK (耗时: %.0fms)", host, port, elapsed)
                else:
                    logger.debug("[NET] 外网连通 %s:%d FAIL (耗时: %.0fms)", host, port, elapsed)
            except Exception:
                elapsed = (time.time() - t_conn) * 1000
                results["details"][name] = False
                logger.debug("[NET] 外网连通 %s:%d 异常 (耗时: %.0fms)", host, port, elapsed)

        # 测试本地/内网连通
        local_targets = ["127.0.0.1", "192.168.1.1", "10.0.0.1", "172.16.0.1"]
        for target in local_targets:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target, 80))
                sock.close()
                if result == 0:
                    results["local"] = True
                    logger.debug("[NET] 本地连通 %s:80 OK", target)
                    break
                else:
                    logger.debug("[NET] 本地连通 %s:80 FAIL", target)
            except Exception:
                continue

        logger.debug("[NET] 连通性测试总耗时: %.0fms (internet=%s, local=%s, dns=%s)",
                     (time.time() - t0) * 1000, results["internet"], results["local"], results["dns"])
        return results

    def configure_for_pentest(
        self,
        mode: Optional[NetworkMode] = None,
        target: Optional[str] = None,
        tool: Optional[str] = None,
    ) -> NetworkConfig:
        """为渗透测试配置网络环境

        Args:
            mode: 强制指定网络模式，为 None 时自动检测
            target: 目标地址（AUTO 模式时使用）
            tool: 工具名称（AUTO 模式时使用）

        Returns:
            配置好的 NetworkConfig
        """
        t0 = time.time()
        if mode is None:
            t_detect = time.time()
            mode = self.detect_network_mode()
            logger.debug("[NET] 模式检测耗时: %.0fms, 结果: %s", (time.time() - t_detect) * 1000, mode.value)

        self.config.mode = mode

        if mode == NetworkMode.AUTO:
            # 智能编排模式：根据目标类型和工具需求自动决策
            logger.debug("[NET] 进入智能编排模式 (AUTO), target=%s, tool=%s", target, tool)
            t_auto = time.time()
            self._configure_auto_mode(target, tool)
            logger.debug("[NET] 智能编排耗时: %.0fms", (time.time() - t_auto) * 1000)

        elif mode == NetworkMode.DIRECT:
            # 直连模式：彻底清除所有代理设置（包括配置中的代理URL）
            logger.debug("[NET] 进入直连模式")
            self._clear_proxy()
            self.config.proxy_url = None  # 关键：清除配置中的代理URL
            logger.info("[NET] 已配置直连模式（所有代理已清除）")

        elif mode == NetworkMode.PROXY:
            # 代理模式：设置代理
            logger.debug("[NET] 进入代理模式, proxy_url=%s", self.config.proxy_url)
            if not self.config.proxy_url:
                self.config.proxy_url = self._detect_proxy_env()
            if self.config.proxy_url:
                self._apply_proxy(self.config.proxy_url)
                logger.info("[NET] 已配置代理模式: %s", self.config.proxy_url)
            else:
                logger.debug("[NET] 代理模式但无代理配置")

        elif mode == NetworkMode.VPN:
            # VPN 模式：内网目标直连，外网目标走代理（如有）
            logger.debug("[NET] 进入 VPN 模式")
            self._clear_proxy()
            self.config.proxy_url = None
            logger.info("[NET] 已配置 VPN 模式（内网直连）")

        elif mode == NetworkMode.OFFLINE:
            # 离线模式：清除代理
            logger.debug("[NET] 进入离线模式")
            self._clear_proxy()
            self.config.proxy_url = None
            logger.info("[NET] 已配置离线模式")

        logger.debug("[NET] 网络配置总耗时: %.0fms, 最终模式: %s", (time.time() - t0) * 1000, self.config.mode.value)
        return self.config

    def _configure_auto_mode(self, target: Optional[str], tool: Optional[str]) -> None:
        """智能编排模式：使用 SmartNetworkOrchestrator 决策

        Args:
            target: 目标地址
            tool: 工具名称
        """
        t0 = time.time()
        if not target:
            logger.warning("[NET] AUTO 模式缺少 target，回退到传统自动检测")
            detected = self.detect_network_mode()
            self.config.mode = detected
            self.configure_for_pentest(mode=detected)
            return

        t_classify = time.time()
        recommended = self._orchestrator.get_recommended_mode(target, tool or "unknown")
        logger.info("[NET] AUTO 模式决策: target=%s tool=%s recommended=%s", target, tool, recommended)
        logger.debug("[NET] 目标分类与推荐耗时: %.0fms", (time.time() - t_classify) * 1000)

        if recommended == "direct":
            logger.debug("[NET] AUTO 推荐直连")
            self._clear_proxy()
            self.config.proxy_url = None
            logger.info("[NET] AUTO 已配置直连模式（所有代理已清除）")
        else:
            # proxy 模式：先检测代理是否真正可用
            logger.debug("[NET] AUTO 推荐代理，检测代理可用性")
            if not self.config.proxy_url:
                self.config.proxy_url = self._detect_proxy_env()
            if self.config.proxy_url:
                # 关键改进：应用代理前先检测是否真正可达
                t_reach = time.time()
                if self._is_proxy_reachable(self.config.proxy_url):
                    logger.debug("[NET] 代理可达性验证通过 (耗时: %.0fms)", (time.time() - t_reach) * 1000)
                    self._apply_proxy(self.config.proxy_url)
                    logger.info("[NET] AUTO 已配置代理模式: %s (已验证可达)", self.config.proxy_url)
                else:
                    logger.debug("[NET] 代理可达性验证失败 (耗时: %.0fms)", (time.time() - t_reach) * 1000)
                    self._clear_proxy()
                    self.config.proxy_url = None
                    logger.warning("[NET] AUTO 代理不可达 (%s)，回退直连", self.config.proxy_url)
            else:
                self._clear_proxy()
                self.config.proxy_url = None
                logger.warning("[NET] AUTO 推荐代理模式但无代理配置，回退直连")

        logger.debug("[NET] AUTO 模式配置总耗时: %.0fms", (time.time() - t0) * 1000)

    def _is_proxy_reachable(self, proxy_url: str, timeout: float = 5.0) -> bool:
        """检测代理是否真正可达

        不仅检测端口是否开放，还通过代理发送实际HTTP请求验证转发能力。

        Args:
            proxy_url: 代理地址 (如 http://127.0.0.1:7897)
            timeout: 超时时间

        Returns:
            True if proxy is reachable and can forward traffic, False otherwise
        """
        t0 = time.time()
        try:
            # 1. 先检测端口是否开放
            t_port = time.time()
            url = proxy_url.replace("http://", "").replace("https://", "").replace("socks://", "").replace("socks5://", "")
            if ":" in url:
                host, port = url.rsplit(":", 1)
                port = int(port)
            else:
                host = url
                port = 80

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            result = sock.connect_ex((host, port))
            sock.close()
            port_elapsed = (time.time() - t_port) * 1000
            if result != 0:
                logger.debug("[NET] 代理端口不可达 %s (耗时: %.0fms)", proxy_url, port_elapsed)
                return False
            logger.debug("[NET] 代理端口可达 %s:%d (耗时: %.0fms)", host, port, port_elapsed)

            # 2. 通过代理发送实际HTTP请求验证转发能力
            t_http = time.time()
            import urllib.request
            proxy_handler = urllib.request.ProxyHandler({
                "http": proxy_url,
                "https": proxy_url,
            })
            opener = urllib.request.build_opener(proxy_handler)
            opener.addheaders = [("User-Agent", "HOS-LS/1.0")]
            
            # 尝试访问一个简单的外部目标
            response = opener.open("https://www.baidu.com", timeout=timeout)
            status = response.getcode()
            response.close()
            http_elapsed = (time.time() - t_http) * 1000
            
            if 200 <= status < 400:
                logger.debug("[NET] 代理转发验证成功 %s (status=%d, HTTP耗时: %.0fms)", proxy_url, status, http_elapsed)
                logger.debug("[NET] 代理可达性验证总耗时: %.0fms", (time.time() - t0) * 1000)
                return True
            else:
                logger.debug("[NET] 代理转发返回异常状态 %s (status=%d, HTTP耗时: %.0fms)", proxy_url, status, http_elapsed)
                logger.debug("[NET] 代理可达性验证总耗时: %.0fms", (time.time() - t0) * 1000)
                return False
                
        except Exception as e:
            logger.debug("[NET] 代理可达性验证失败 %s: %s (总耗时: %.0fms)", proxy_url, e, (time.time() - t0) * 1000)
            return False

    def record_tool_success(self, tool: str, network_mode: str) -> None:
        """记录工具执行成功（用于智能网络编排）"""
        self._orchestrator.record_success(tool, network_mode)

    def record_tool_failure(self, tool: str, network_mode: str, error: str) -> None:
        """记录工具执行失败（用于智能网络编排）"""
        self._orchestrator.record_failure(tool, network_mode, error)

    @property
    def orchestrator(self) -> SmartNetworkOrchestrator:
        """获取智能网络编排器实例"""
        return self._orchestrator

    def _clear_proxy(self) -> None:
        """清除代理设置（当前进程）"""
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
                    "http_proxy", "https_proxy", "all_proxy"]:
            os.environ.pop(var, None)

    def _apply_proxy(self, proxy_url: str) -> None:
        """应用代理设置"""
        os.environ["HTTP_PROXY"] = proxy_url
        os.environ["HTTPS_PROXY"] = proxy_url
        os.environ["ALL_PROXY"] = proxy_url

    def get_fastest_mirror(self, mirror_type: str = "pypi", timeout: float = 3.0) -> Optional[str]:
        """检测最快的镜像源

        Args:
            mirror_type: 镜像类型 (pypi/goproxy/npm)
            timeout: 超时时间

        Returns:
            最快的镜像 URL
        """
        mirrors = self.PROXY_MIRRORS.get(mirror_type, [])
        if not mirrors:
            return None

        logger.info("[NET] 检测最快 %s 镜像...", mirror_type)
        fastest = None
        min_latency = float("inf")

        for url in mirrors:
            try:
                host = url.split("//")[-1].split("/")[0]
                start = time.time()
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                result = sock.connect_ex((host, 443))
                latency = (time.time() - start) * 1000
                sock.close()

                if result == 0:
                    logger.debug("[NET] %s: %.0fms", url, latency)
                    if latency < min_latency:
                        min_latency = latency
                        fastest = url
            except Exception:
                continue

        if fastest:
            logger.info("[NET] 最快 %s 镜像: %s (%.0fms)", mirror_type, fastest, min_latency)
        else:
            logger.warning("[NET] 未找到可用的 %s 镜像", mirror_type)

        return fastest

    def generate_network_report(self) -> str:
        """生成网络环境报告"""
        lines = [
            "=" * 60,
            "网络环境报告",
            "=" * 60,
            "",
            f"模式: {self.config.mode.value}",
            f"代理: {self.config.proxy_url or '无'}",
            f"VPN: {self.config.vpn_interface or '未检测到'}",
            f"超时: {self.config.timeout}s",
            "",
            "--- 连通性测试 ---",
        ]

        connectivity = self.test_connectivity()
        for name, status in connectivity.get("details", {}).items():
            lines.append(f"  {name}: {'OK' if status else 'FAIL'}")

        lines.append("")
        lines.append(f"外网: {'OK' if connectivity['internet'] else 'FAIL'}")
        lines.append(f"本地: {'OK' if connectivity['local'] else 'FAIL'}")
        lines.append(f"DNS: {'OK' if connectivity['dns'] else 'FAIL'}")

        lines.append("")
        lines.append("--- 环境变量 ---")
        for var in ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "GOPROXY", "PIP_INDEX_URL"]:
            val = os.environ.get(var)
            if val:
                lines.append(f"  {var}: {val}")

        lines.append("")
        lines.append("=" * 60)

        return "\n".join(lines)
