"""VSCode 扩展市场集成

搜索、下载并集成 VSCode 市场中安全相关扩展。
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import httpx
from tqdm import tqdm

logger = logging.getLogger(__name__)

VSCODE_MARKETPLACE_API = "https://marketplace.visualstudio.com/_apis/public/gallery"
VSCODE_EXTENSION_ENDPOINT = f"{VSCODE_MARKETPLACE_API}/extensionquery"

SECURITY_EXTENSION_KEYWORDS = [
    "security",
    "pentest",
    "vulnerability",
    "scanner",
    "cybersecurity",
    "threat",
    "exploit",
    "nmap",
    "burpsuite",
    "metasploit",
]


@dataclass
class VSCodeExtension:
    """VSCode 扩展信息"""

    name: str
    publisher: str
    display_name: str
    description: str
    version: str
    download_count: int
    rating: float
    categories: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    asset_uri: str = ""
    install_url: str = ""


class VSCodeMarketplace:
    """VSCode 扩展市场集成"""

    def __init__(
        self,
        proxy_url: Optional[str] = None,
    ):
        self.proxy_url = proxy_url
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json;api-version=7.2-preview.1",
        }

    def _get_http_client(self) -> httpx.Client:
        """获取 HTTP 客户端（支持代理）"""
        kwargs: dict[str, Any] = {
            "headers": self._headers,
            "timeout": 30.0,
            "follow_redirects": True,
        }
        if self.proxy_url:
            kwargs["proxy"] = self.proxy_url
        return httpx.Client(**kwargs)

    def search_security_extensions(
        self,
        keywords: Optional[list[str]] = None,
        max_results: int = 50,
    ) -> list[VSCodeExtension]:
        """搜索 VSCode 市场中安全相关扩展

        Args:
            keywords: 搜索关键词列表
            max_results: 最大结果数

        Returns:
            安全相关扩展列表
        """
        keywords = keywords or SECURITY_EXTENSION_KEYWORDS
        all_extensions: list[VSCodeExtension] = []
        seen: set[str] = set()

        with self._get_http_client() as client:
            for keyword in tqdm(keywords, desc="搜索 VSCode 安全扩展", unit="keyword"):
                logger.info("[VSCODE] 搜索关键词: %s", keyword)

                payload = {
                    "filters": [
                        {
                            "criteria": [
                                {
                                    "filterType": 8,  # Target
                                    "value": "Microsoft.VisualStudio.Code",
                                },
                                {
                                    "filterType": 10,  # Search text
                                    "value": keyword,
                                },
                            ],
                            "pageNumber": 1,
                            "pageSize": max_results,
                            "sortBy": 4,  # Install count
                            "sortOrder": 0,  # Descending
                        }
                    ],
                    "assetTypes": [],
                    "flags": 0x914,
                }

                try:
                    resp = client.post(VSCODE_EXTENSION_ENDPOINT, json=payload)
                    resp.raise_for_status()
                    data = resp.json()

                    for ext_data in data.get("results", [{}])[0].get("extensions", []):
                        ext_id = ext_data.get("extensionId", "")
                        if ext_id in seen:
                            continue
                        seen.add(ext_id)

                        publisher = ext_data.get("publisher", {})
                        ext = VSCodeExtension(
                            name=ext_data.get("extensionName", ""),
                            publisher=publisher.get("publisherName", ""),
                            display_name=ext_data.get("displayName", ""),
                            description=ext_data.get("shortDescription", ""),
                            version=ext_data.get("versions", [{}])[0].get("version", ""),
                            download_count=ext_data.get("statistics", [{}])[0].get("value", 0),
                            rating=ext_data.get("statistics", [{}])[1].get("value", 0),
                            categories=ext_data.get("categories", []),
                            tags=ext_data.get("tags", []),
                            asset_uri=ext_data.get("assetUri", ""),
                            install_url=f"vscode:extension/{publisher.get('publisherName', '')}.{ext_data.get('extensionName', '')}",
                        )
                        all_extensions.append(ext)

                except httpx.HTTPStatusError as e:
                    logger.error(
                        "[VSCODE] 搜索失败 (%s): %s",
                        keyword,
                        e.response.status_code,
                    )
                except Exception as e:
                    logger.error("[VSCODE] 搜索异常 (%s): %s", keyword, e)

        logger.info(
            "[VSCODE] 发现 %d 个安全相关扩展",
            len(all_extensions),
        )
        return all_extensions

    def download_extension(
        self,
        extension: VSCodeExtension,
        target_dir: Optional[str] = None,
    ) -> Optional[str]:
        """下载 VSCode 扩展

        Args:
            extension: 扩展信息
            target_dir: 下载目标目录

        Returns:
            下载文件路径，失败时返回 None
        """
        if not extension.asset_uri:
            logger.warning("[VSCODE] 扩展 %s 无 asset URI", extension.name)
            return None

        target_path = Path(target_dir) if target_dir else Path.cwd() / "vscode-extensions"
        target_path.mkdir(parents=True, exist_ok=True)

        vsix_url = f"{extension.asset_uri}/Microsoft.VisualStudio.Services.VSIXPackage"
        filename = f"{extension.publisher}_{extension.name}-{extension.version}.vsix"
        filepath = target_path / filename

        logger.info("[VSCODE] 下载扩展: %s", extension.display_name)

        with self._get_http_client() as client:
            try:
                with client.stream("GET", vsix_url) as resp:
                    resp.raise_for_status()
                    total = int(resp.headers.get("content-length", 0))

                    with open(filepath, "wb") as f:
                        with tqdm(
                            total=total,
                            unit="B",
                            unit_scale=True,
                            desc=f"下载 {extension.display_name}",
                        ) as pbar:
                            for chunk in resp.iter_bytes(chunk_size=8192):
                                f.write(chunk)
                                pbar.update(len(chunk))

                logger.info("[VSCODE] 扩展已下载: %s", filepath)
                return str(filepath)

            except Exception as e:
                logger.error("[VSCODE] 下载扩展失败: %s", e)
                return None

    def install_extension(
        self,
        extension: VSCodeExtension,
        vscode_bin: Optional[str] = None,
    ) -> bool:
        """安装 VSCode 扩展

        Args:
            extension: 扩展信息
            vscode_bin: VSCode 可执行文件路径

        Returns:
            是否成功
        """
        import subprocess

        code_cmd = vscode_bin or "code"
        ext_id = f"{extension.publisher}.{extension.name}"

        logger.info("[VSCODE] 安装扩展: %s", ext_id)

        try:
            result = subprocess.run(
                [code_cmd, "--install-extension", ext_id],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                logger.info("[VSCODE] 扩展已安装: %s", ext_id)
                return True

            logger.error(
                "[VSCODE] 扩展安装失败: %s - %s",
                ext_id,
                result.stderr,
            )
            return False

        except FileNotFoundError:
            logger.error(
                "[VSCODE] 找不到 VSCode 命令: %s",
                code_cmd,
            )
            return False
        except subprocess.TimeoutExpired:
            logger.error("[VSCODE] 扩展安装超时: %s", ext_id)
            return False
        except Exception as e:
            logger.error("[VSCODE] 扩展安装异常: %s", e)
            return False

    def get_extension_details(
        self,
        publisher: str,
        name: str,
    ) -> Optional[VSCodeExtension]:
        """获取扩展详细信息

        Args:
            publisher: 发布者名称
            name: 扩展名称

        Returns:
            扩展信息，未找到时返回 None
        """
        with self._get_http_client() as client:
            payload = {
                "filters": [
                    {
                        "criteria": [
                            {
                                "filterType": 7,  # Extension name
                                "value": f"{publisher}.{name}",
                            },
                        ],
                        "pageNumber": 1,
                        "pageSize": 1,
                    }
                ],
                "assetTypes": [],
                "flags": 0x914,
            }

            try:
                resp = client.post(VSCODE_EXTENSION_ENDPOINT, json=payload)
                resp.raise_for_status()
                data = resp.json()

                for ext_data in data.get("results", [{}])[0].get("extensions", []):
                    pub = ext_data.get("publisher", {})
                    return VSCodeExtension(
                        name=ext_data.get("extensionName", ""),
                        publisher=pub.get("publisherName", ""),
                        display_name=ext_data.get("displayName", ""),
                        description=ext_data.get("shortDescription", ""),
                        version=ext_data.get("versions", [{}])[0].get("version", ""),
                        download_count=ext_data.get("statistics", [{}])[0].get("value", 0),
                        rating=ext_data.get("statistics", [{}])[1].get("value", 0),
                        categories=ext_data.get("categories", []),
                        tags=ext_data.get("tags", []),
                        asset_uri=ext_data.get("assetUri", ""),
                        install_url=f"vscode:extension/{pub.get('publisherName', '')}.{ext_data.get('extensionName', '')}",
                    )
            except Exception as e:
                logger.error("[VSCODE] 获取扩展详情失败: %s", e)

        return None

    def generate_install_script(
        self,
        extensions: list[VSCodeExtension],
        output_path: Optional[str] = None,
    ) -> str:
        """生成扩展安装脚本

        Args:
            extensions: 扩展列表
            output_path: 输出文件路径

        Returns:
            脚本内容
        """
        lines = [
            "#!/bin/bash",
            "# VSCode Security Extensions Install Script",
            f"# Generated: {__import__('datetime').datetime.now().isoformat()}",
            "",
        ]

        for ext in extensions:
            ext_id = f"{ext.publisher}.{ext.name}"
            lines.append(f"# {ext.display_name} - {ext.description}")
            lines.append(f"code --install-extension {ext_id}")
            lines.append("")

        script_content = "\n".join(lines)

        if output_path:
            script_file = Path(output_path)
            with open(script_file, "w", encoding="utf-8") as f:
                f.write(script_content)
            if os.name != "nt":
                script_file.chmod(0o755)
            logger.info("[VSCODE] 安装脚本已生成: %s", output_path)

        return script_content
