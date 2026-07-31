"""CWE专用Prompt模板选择器模块

对标 ZeroFalse 论文的 CWE 专用检测指导实现。
根据CWE编号加载对应的Jinja2模板片段，提供基于正则的代码CWE类型检测，
并与现有 PromptEngine 集成，支持将CWE专用指导注入到主分析模板中。
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from src.utils.logger import get_logger

logger = get_logger(__name__)


# CWE编号 → 模板文件名的映射表
CWE_TEMPLATE_MAP: Dict[str, str] = {
    "CWE-89": "cwe/cwe_89_sql_injection.jinja2",
    "CWE-78": "cwe/cwe_78_os_command_injection.jinja2",
    "CWE-79": "cwe/cwe_79_xss.jinja2",
    "CWE-502": "cwe/cwe_502_deserialization.jinja2",
    "CWE-611": "cwe/cwe_611_xxe.jinja2",
    "CWE-918": "cwe/cwe_918_ssrf.jinja2",
    "CWE-22": "cwe/cwe_22_path_traversal.jinja2",
    "CWE-798": "cwe/cwe_798_hardcoded_credentials.jinja2",
    "CWE-327": "cwe/cwe_327_weak_crypto.jinja2",
    "CWE-862": "cwe/cwe_862_auth_bypass.jinja2",
}

# CWE编号 → 中文名称映射
CWE_NAME_MAP: Dict[str, str] = {
    "CWE-89": "SQL注入",
    "CWE-78": "OS命令注入",
    "CWE-79": "跨站脚本攻击",
    "CWE-502": "不可信数据反序列化",
    "CWE-611": "XML外部实体注入",
    "CWE-918": "服务端请求伪造",
    "CWE-22": "路径遍历",
    "CWE-798": "硬编码凭证",
    "CWE-327": "弱加密算法",
    "CWE-862": "缺失授权",
}

# 各CWE类型的正则检测模式（用于代码启发式检测）
# 每种CWE包含多个正则表达式，匹配任意一个即认为代码中可能存在该CWE类型的漏洞
_CWE_DETECTION_PATTERNS: Dict[str, List[str]] = {
    "CWE-89": [
        # SQL字符串拼接
        r'(?:execute(?:Query|Update|)?)\s*\(\s*["\'].*?(?:\+|%|\.\s*format|f["\'])',
        r'(?:createSQLQuery|createNativeQuery)\s*\(',
        r'\$\{.*?\}',  # MyBatis ${} 占位符
        r'(?:cursor\.execute|db\.execute)\s*\(\s*(?:f["\']|.*?\+|.*?\.format)',
        r'(?:RawSQL|\.raw\()\s*\(',
        r'(?:sequelize\.query|knex\.raw)\s*\(',
        r'(?:\$where\s*:\s*)',  # MongoDB $where
        r'(?:prepareStatement|createStatement)\s*\(\s*["\'].*?(?:\+|")',
        r'(?:JdbcTemplate|NamedParameterJdbcTemplate)\.\w+\s*\(\s*(?:.*?\+|.*?\.format)',
    ],
    "CWE-78": [
        # OS命令注入
        r'(?:Runtime\.getRuntime\(\)\.exec|ProcessBuilder)\s*\(',
        r'(?:os\.system|os\.popen)\s*\(',
        r'subprocess\.\w+\s*\(.*?shell\s*=\s*True',
        r'subprocess\.(?:getoutput|getstatusoutput)\s*\(',
        r'(?:child_process\.(?:exec|execSync))\s*\(',
        r'spawn\s*\(.*?shell\s*:\s*true',
        r'(?:eval|exec)\s*\(\s*(?:.*?\+|.*?input)',
        r'ScriptEngine\.eval\s*\(',
    ],
    "CWE-79": [
        # XSS
        r'(?:innerHTML|outerHTML)\s*=',
        r'document\.write\s*\(',
        r'(?:res\.send|response\.getWriter\(\)\.write)\s*\(',
        r'(?:render_template_string)\s*\(',
        r'(?:mark_safe)\s*\(',
        r'\|\s*safe\s*\}\}',  # Django |safe 过滤器
        r'th:utext\s*=',  # Thymeleaf 非转义输出
        r'dangerouslySetInnerHTML',  # React
        r'v-html\s*=',  # Vue
        r'(?:\$\(.*?\)\.appendTo|jQuery.*?\.html)\s*\(',
    ],
    "CWE-502": [
        # 反序列化
        r'ObjectInputStream\s*[\.(]',
        r'\.readObject\s*\(',
        r'XMLDecoder\s*[\.(]',
        r'XStream\s*[\.(]',
        r'(?:pickle\.loads?|pickle\.load)\s*\(',
        r'yaml\.load\s*\(',
        r'yaml\.unsafe_load\s*\(',
        r'(?:JSON\.parseObject|JSON\.parse)\s*\(',  # Fastjson
        r'enableDefaultTyping',  # Jackson 多态
        r'@JsonTypeInfo',
        r'node-serialize',
        r'(?:Kryo\.readObject|Hessian2Input\.readObject)\s*\(',
        r'marshal\.loads?\s*\(',
    ],
    "CWE-611": [
        # XXE
        r'DocumentBuilderFactory',
        r'SAXParserFactory',
        r'XMLInputFactory',
        r'TransformerFactory',
        r'SAXReader',
        r'(?:xml\.etree\.ElementTree\.(?:parse|fromstring))\s*\(',
        r'lxml\.etree\.(?:parse|fromstring)\s*\(',
        r'xml\.dom\.minidom\.parse\s*\(',
        r'xml\.sax\.parse\s*\(',
        r'libxmljs\.parseXml\s*\(',
        r'xmldom.*?parseFromString\s*\(',
        r'Unmarshaller\.unmarshal\s*\(',
    ],
    "CWE-918": [
        # SSRF
        r'(?:HttpClient|OkHttpClient|RestTemplate|WebClient)\.\w+\s*\(',
        r'URL\s*\(.*?\)\s*\.openConnection\s*\(',
        r'(?:requests\.(?:get|post|put|delete|head|patch))\s*\(',
        r'urllib\.request\.urlopen\s*\(',
        r'httpx\.(?:get|post|AsyncClient)\s*\(',
        r'aiohttp\.ClientSession\s*\(',
        r'(?:axios\.(?:get|post|put|delete))\s*\(',
        r'(?:fetch|http\.get|https\.get)\s*\(',
        r'(?:RestTemplate\.getForObject|RestTemplate\.exchange)\s*\(',
    ],
    "CWE-22": [
        # 路径遍历
        r'(?:new\s+File|FileInputStream|FileOutputStream)\s*\(',
        r'(?:Paths\.get|Path\.of)\s*\(',
        r'(?:Files\.(?:readString|write|copy|delete|readAllLines))\s*\(',
        r'(?:open)\s*\(\s*(?:.*?\+|.*?\.format|f["\'])',
        r'os\.path\.join\s*\(.*?(?:request|input|param|arg)',
        r'(?:fs\.readFile|fs\.writeFile|fs\.createReadStream)\s*\(',
        r'(?:res\.sendFile|send_file|FileResponse)\s*\(',
        r'(?:path\.join|path\.resolve)\s*\(.*?(?:req\.|request)',
    ],
    "CWE-798": [
        # 硬编码凭证
        r'(?:password|passwd|pwd)\s*=\s*["\'][^"\']{3,}["\']',
        r'(?:api_key|apikey|api_secret|secret_key)\s*=\s*["\'][^"\']{3,}["\']',
        r'(?:access_key|access_token|auth_token)\s*=\s*["\'][^"\']{3,}["\']',
        r'(?:DRIVERMANAGER|DriverManager)\.getConnection\s*\([^)]*["\'][^"\']+["\']',
        r'(?:mongodb|mysql|postgres|redis)://\w+:\w+@',  # 连接字符串中的凭证
        r'AKIA[0-9A-Z]{16}',  # AWS Access Key
        r'ghp_[a-zA-Z0-9]{36}',  # GitHub Token
        r'xox[baprs]-[a-zA-Z0-9-]+',  # Slack Token
        r'AIza[0-9A-Za-z_-]{35}',  # Google API Key
        r'(?:jwt\.sign|createHmac)\s*\([^)]*["\'][^"\']{3,}["\']',
        r'SECRET_KEY\s*=\s*["\'][^"\']{3,}["\']',
        r'(?:aws_access_key_id|aws_secret_access_key)\s*=\s*["\']',
    ],
    "CWE-327": [
        # 弱加密算法
        r'MessageDigest\.getInstance\s*\(\s*["\'](?:MD5|SHA-1|SHA1)["\']',
        r'(?:hashlib\.md5|hashlib\.sha1)\s*\(',
        r'crypto\.createHash\s*\(\s*["\'](?:md5|sha1)["\']',
        r'Cipher\.getInstance\s*\(\s*["\'](?:DES|RC4|RC2|Blowfish)',
        r'Cipher\.getInstance\s*\(\s*["\']AES/ECB',
        r'(?:DES\.new|AES\.new.*?MODE_ECB)',
        r'crypto\.createCipher\s*\(\s*["\'](?:des|aes-\d+-ecb)',
        r'(?:new\s+Random|Math\.random)\s*\(',
        r'DES\.MODE_ECB',
        r'RSA\.generate\s*\(\s*(?:512|768|1024)\s*\)',
    ],
    "CWE-862": [
        # 缺失授权
        r'\.permitAll\s*\(\s*\)',
        r'@CrossOrigin\s*\(\s*origins\s*=\s*["\']\*["\']',
        r'permission_classes\s*=\s*\[\s*\]',
        r'permission_classes\s*=\s*\[\s*AllowAny\s*\]',
        r'antMatchers\s*\(\s*["\'].*?admin.*?["\']\s*\)\s*\.permitAll',
        r'(?:(?!@PreAuthorize|@Secured|@RolesAllowed)\s*@GetMapping|@PostMapping|@PutMapping|@DeleteMapping)',
        r'(?!.*(?:login_required|permission_required|is_authenticated)).*def\s+\w*(?:admin|manage|delete|update)\w*\s*\(',
        r'router\.\w+\s*\(\s*["\'](?:/admin|/manage)',
    ],
}


class CWEPromptSelector:
    """CWE专用Prompt模板选择器

    负责根据CWE编号加载对应的专用检测指导模板，
    并提供基于正则的代码CWE类型启发式检测功能。
    与现有 PromptEngine 集成，支持将CWE专用指导注入到主分析流程中。
    """

    def __init__(self, templates_dir: Optional[Path] = None):
        """初始化CWE Prompt选择器

        Args:
            templates_dir: 模板根目录路径，默认为项目 prompts/templates 目录
        """
        if templates_dir is None:
            # 默认模板目录：项目根目录/prompts/templates
            project_root = Path(__file__).parent.parent.parent.parent
            templates_dir = project_root / "prompts" / "templates"

        self.templates_dir = Path(templates_dir)
        self._cwe_dir = self.templates_dir / "cwe"
        self._template_cache: Dict[str, str] = {}

        logger.info(f"CWEPromptSelector 初始化完成，模板目录: {self._cwe_dir}")

    def get_cwe_template(self, cwe_id: str, **kwargs: Any) -> str:
        """根据CWE编号获取对应的专用Prompt模板内容

        加载CWE专用的Jinja2模板文件，并使用提供的变量进行渲染。
        支持模板缓存以提高重复调用性能。

        Args:
            cwe_id: CWE编号，支持 "CWE-89" 或 "89" 两种格式
            **kwargs: 模板渲染变量，如 file_path, file_content, detected_language 等

        Returns:
            渲染后的CWE专用Prompt模板字符串

        Raises:
            ValueError: CWE编号不在支持列表中
            FileNotFoundError: 模板文件不存在
        """
        # 标准化CWE编号格式
        normalized_id = self._normalize_cwe_id(cwe_id)

        if normalized_id not in CWE_TEMPLATE_MAP:
            logger.warning(f"不支持的CWE编号: {cwe_id}，支持的编号: {list(CWE_TEMPLATE_MAP.keys())}")
            raise ValueError(
                f"不支持的CWE编号: {cwe_id}。"
                f"支持的编号列表: {', '.join(sorted(CWE_TEMPLATE_MAP.keys()))}"
            )

        template_file = CWE_TEMPLATE_MAP[normalized_id]
        cache_key = f"{template_file}:{self._build_cache_key(kwargs)}"

        # 检查缓存
        if cache_key in self._template_cache:
            logger.debug(f"使用缓存的CWE模板: {normalized_id}")
            return self._template_cache[cache_key]

        # 加载模板文件
        template_path = self._cwe_dir / template_file.replace("cwe/", "")
        if not template_path.exists():
            # 尝试使用Jinja2引擎加载（支持子目录）
            try:
                rendered = self._render_with_jinja(template_file, **kwargs)
            except Exception as e:
                logger.error(f"加载CWE模板失败: {template_path}，错误: {e}")
                raise FileNotFoundError(f"CWE模板文件不存在: {template_path}")
        else:
            # 直接读取并使用简易Jinja2渲染
            try:
                rendered = self._render_with_jinja(template_file, **kwargs)
            except Exception:
                # 降级：直接读取文件内容，替换基本变量
                content = template_path.read_text(encoding="utf-8")
                rendered = self._simple_render(content, **kwargs)

        # 缓存渲染结果
        self._template_cache[cache_key] = rendered
        cwe_name = CWE_NAME_MAP.get(normalized_id, normalized_id)
        logger.info(f"已加载CWE专用模板: {normalized_id} ({cwe_name})")

        return rendered

    def detect_cwe_from_code(self, code: str) -> List[str]:
        """基于正则启发式规则检测代码中可能存在的CWE类型

        使用预定义的正则表达式模式扫描代码内容，
        返回所有匹配到的CWE类型列表。该方法用于快速预判代码中
        可能存在哪些类型的漏洞，以便选择对应的CWE专用Prompt模板。

        Args:
            code: 待检测的源代码字符串

        Returns:
            检测到的CWE编号列表，如 ["CWE-89", "CWE-798"]
            按匹配模式命中数量降序排列（命中越多越靠前）
        """
        if not code or not code.strip():
            logger.debug("代码内容为空，跳过CWE检测")
            return []

        detected_cwes: Dict[str, int] = {}  # CWE编号 → 匹配次数

        for cwe_id, patterns in _CWE_DETECTION_PATTERNS.items():
            match_count = 0
            for pattern in patterns:
                try:
                    matches = re.findall(pattern, code, re.IGNORECASE | re.MULTILINE)
                    if matches:
                        match_count += len(matches)
                except re.error as e:
                    logger.debug(f"正则表达式错误 [{cwe_id}] 模式 '{pattern}': {e}")
                    continue

            if match_count > 0:
                detected_cwes[cwe_id] = match_count

        # 按匹配次数降序排列
        sorted_cwes = sorted(detected_cwes.keys(), key=lambda c: detected_cwes[c], reverse=True)

        if sorted_cwes:
            cwe_descriptions = [
                f"{cwe} ({CWE_NAME_MAP.get(cwe, '未知')})" for cwe in sorted_cwes
            ]
            logger.info(f"CWE启发式检测结果: {', '.join(cwe_descriptions)}")
        else:
            logger.debug("未检测到任何CWE类型的匹配模式")

        return sorted_cwes

    def get_cwe_templates_for_code(
        self, code: str, max_templates: int = 3, **kwargs: Any
    ) -> List[Dict[str, str]]:
        """检测代码中的CWE类型并加载对应的Prompt模板

        组合 detect_cwe_from_code 和 get_cwe_template 的功能，
        一次性完成检测 + 模板加载。

        Args:
            code: 待检测的源代码字符串
            max_templates: 最多返回的模板数量（按匹配置信度排序）
            **kwargs: 模板渲染变量

        Returns:
            模板信息列表，每项包含:
            - cwe_id: CWE编号
            - cwe_name: CWE中文名称
            - template_content: 渲染后的模板内容
        """
        detected_cwes = self.detect_cwe_from_code(code)
        # 限制返回数量
        selected_cwes = detected_cwes[:max_templates]

        results = []
        for cwe_id in selected_cwes:
            try:
                content = self.get_cwe_template(cwe_id, **kwargs)
                results.append({
                    "cwe_id": cwe_id,
                    "cwe_name": CWE_NAME_MAP.get(cwe_id, cwe_id),
                    "template_content": content,
                })
            except (ValueError, FileNotFoundError) as e:
                logger.warning(f"加载CWE模板失败 [{cwe_id}]: {e}")
                continue

        return results

    def get_all_cwe_ids(self) -> List[str]:
        """获取所有支持的CWE编号列表

        Returns:
            CWE编号列表，如 ["CWE-22", "CWE-78", "CWE-79", ...]
        """
        return sorted(CWE_TEMPLATE_MAP.keys(), key=lambda x: int(x.split("-")[1]))

    def get_cwe_name(self, cwe_id: str) -> str:
        """获取CWE编号对应的中文名称

        Args:
            cwe_id: CWE编号

        Returns:
            CWE中文名称，如 "SQL注入"
        """
        normalized_id = self._normalize_cwe_id(cwe_id)
        return CWE_NAME_MAP.get(normalized_id, normalized_id)

    def is_supported_cwe(self, cwe_id: str) -> bool:
        """检查CWE编号是否在支持列表中

        Args:
            cwe_id: CWE编号

        Returns:
            是否支持
        """
        normalized_id = self._normalize_cwe_id(cwe_id)
        return normalized_id in CWE_TEMPLATE_MAP

    def clear_cache(self) -> None:
        """清除模板缓存"""
        self._template_cache.clear()
        logger.debug("CWE模板缓存已清除")

    def _normalize_cwe_id(self, cwe_id: str) -> str:
        """标准化CWE编号格式

        支持 "CWE-89"、"cwe-89"、"89" 等输入格式，
        统一转换为 "CWE-89" 格式。

        Args:
            cwe_id: 原始CWE编号

        Returns:
            标准化后的CWE编号，如 "CWE-89"
        """
        cwe_id = cwe_id.strip().upper()
        if not cwe_id.startswith("CWE-"):
            # 尝试纯数字格式
            if cwe_id.isdigit():
                cwe_id = f"CWE-{cwe_id}"
            else:
                # 尝试去掉 "CWE" 前缀后重新拼接
                digits = re.sub(r"[^0-9]", "", cwe_id)
                if digits:
                    cwe_id = f"CWE-{digits}"
        return cwe_id

    def _render_with_jinja(self, template_file: str, **kwargs: Any) -> str:
        """使用Jinja2引擎渲染模板

        Args:
            template_file: 模板文件名（相对于templates目录）
            **kwargs: 模板变量

        Returns:
            渲染后的字符串
        """
        from jinja2 import Environment, FileSystemLoader

        env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            trim_blocks=True,
            lstrip_blocks=True,
            keep_trailing_newline=True,
        )
        template = env.get_template(template_file)
        return template.render(**kwargs)

    def _simple_render(self, content: str, **kwargs: Any) -> str:
        """简易模板渲染（降级方案）

        当Jinja2引擎不可用时，使用简单的字符串替换。
        仅处理 {{ variable }} 格式的变量。

        Args:
            content: 模板内容
            **kwargs: 模板变量

        Returns:
            渲染后的字符串
        """
        result = content
        for key, value in kwargs.items():
            # 替换 {{ key }} 格式
            result = result.replace(f"{{{{ {key} }}}}", str(value))
            # 替换 {{key}} 格式（无空格）
            result = result.replace(f"{{{{{key}}}}}", str(value))
        return result

    def _build_cache_key(self, kwargs: Dict[str, Any]) -> str:
        """构建缓存键

        基于模板变量的关键信息生成缓存键，
        确保不同语言/文件组合使用不同的缓存条目。

        Args:
            kwargs: 模板变量

        Returns:
            缓存键字符串
        """
        # 仅使用影响输出的关键变量作为缓存键
        key_parts = []
        for k in ["detected_language", "file_path"]:
            if k in kwargs:
                key_parts.append(f"{k}={kwargs[k]}")
        return ":".join(key_parts) if key_parts else "default"


def get_cwe_prompt_selector(templates_dir: Optional[Path] = None) -> CWEPromptSelector:
    """获取CWEPromptSelector实例

    工厂方法，创建并返回CWEPromptSelector实例。

    Args:
        templates_dir: 可选的模板目录路径

    Returns:
        CWEPromptSelector实例
    """
    return CWEPromptSelector(templates_dir=templates_dir)
