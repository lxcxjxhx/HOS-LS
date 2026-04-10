"""AI配置验证器

确保AI配置正确，提供清晰的错误提示和配置指引。
零硬编码设计 - 所有配置从环境变量或Config对象动态加载。
"""

from typing import Tuple, Dict, Any, Optional
import os
from src.core.config import Config


class AIConfigValidator:
    """AI配置验证器
    
    验证AI相关配置的完整性和有效性，
    提供友好的错误提示和配置建议。
    """
    
    # 支持的提供商及其默认配置
    PROVIDER_CONFIG = {
        "deepseek": {
            "default_model": "deepseek-chat",
            "env_var": "DEEPSEEK_API_KEY",
            "base_url": "https://api.deepseek.com",
            "name": "DeepSeek"
        },
        "openai": {
            "default_model": "gpt-4",
            "env_var": "OPENAI_API_KEY",
            "base_url": "https://api.openai.com/v1",
            "name": "OpenAI"
        },
        "anthropic": {
            "default_model": "claude-3-5-sonnet-20241022",
            "env_var": "ANTHROPIC_API_KEY",
            "base_url": "https://api.anthropic.com",
            "name": "Anthropic"
        },
        "local": {
            "default_model": "local-model",
            "env_var": None,
            "base_url": "http://localhost:11434",
            "name": "Local (Ollama)"
        }
    }
    
    @classmethod
    def validate(cls, config: Config) -> Tuple[bool, str, Dict[str, Any]]:
        """验证AI配置
        
        Args:
            config: 配置对象
            
        Returns:
            (是否有效, 错误信息, 配置摘要)
        """
        issues = []
        summary = {}
        
        # 1. 检查提供商配置
        provider = getattr(config.ai, 'provider', None) if hasattr(config, 'ai') else None
        if not provider:
            # 尝试从环境变量推断
            for prov_name, prov_config in cls.PROVIDER_CONFIG.items():
                env_var = prov_config.get('env_var')
                if env_var and os.environ.get(env_var):
                    provider = prov_name
                    if hasattr(config, 'ai'):
                        config.ai.provider = provider
                    break
            
            if not provider:
                issues.append("未指定AI提供商")
                provider = "deepseek"  # 默认值
                if hasattr(config, 'ai'):
                    config.ai.provider = provider
                    
        summary["provider"] = provider
        summary["provider_name"] = cls.PROVIDER_CONFIG.get(provider, {}).get("name", provider)
        
        # 2. 检查API密钥
        api_key = getattr(config.ai, 'api_key', None) if hasattr(config, 'ai') else None
        if not api_key:
            # 尝试从环境变量获取
            env_var = cls.PROVIDER_CONFIG.get(provider, {}).get('env_var')
            if env_var:
                api_key = os.environ.get(env_var)
                if api_key and hasattr(config, 'ai'):
                    config.ai.api_key = api_key
                    
            if not api_key:
                env_hint = f"\n   环境变量: set {env_var}=your-api-key" if env_var else ""
                issues.append(f"未设置{summary['provider_name']}的API密钥{env_hint}")
                
        summary["api_key_configured"] = bool(api_key)
        
        # 3. 检查模型配置
        model = getattr(config.ai, 'model', None) if hasattr(config, 'ai') else None
        if not model:
            default_model = cls.PROVIDER_CONFIG.get(provider, {}).get('default_model')
            if default_model:
                model = default_model
                if hasattr(config, 'ai'):
                    config.ai.model = model
                    
        summary["model"] = model or "未配置"
        
        # 4. 检查Base URL
        base_url = getattr(config.ai, 'base_url', None) if hasattr(config, 'ai') else None
        if not base_url:
            default_url = cls.PROVIDER_CONFIG.get(provider, {}).get('base_url')
            if default_url:
                base_url = default_url
                if hasattr(config, 'ai'):
                    config.ai.base_url = base_url
                    
        summary["base_url"] = base_url or "使用默认值"
        
        valid = len(issues) == 0
        error_msg = "\n".join(f"❌ {issue}" for issue in issues) if issues else ""
        
        return valid, error_msg, summary
    
    @classmethod
    def get_setup_instructions(cls, provider: str) -> str:
        """获取特定提供商的配置说明
        
        Args:
            provider: 提供商名称
            
        Returns:
            配置说明字符串
        """
        instructions = {
            "deepseek": f"""
🔧 {cls.PROVIDER_CONFIG['deepseek']['name']} 配置方法：

1️⃣ 注册账号
   访问: https://platform.deepseek.com/

2️⃣ 获取API Key
   登录后在控制台创建API Key

3️⃣ 配置方式（任选其一）：
   
   📌 方式一：环境变量（推荐）
   ┌─────────────────────────────────────┐
   │ Windows:                             │
   │ set DEEPSEEK_API_KEY=sk-your-key     │
   │                                       │
   │ Linux/Mac:                           │
   │ export DEEPSEEK_API_KEY=sk-your-key  │
   └─────────────────────────────────────┘
   
   📌 方式二：配置文件
   在 .hos-ls.yaml 或 config/default.yaml 中添加：
   
   ai:
     provider: deepseek
     api_key: sk-your-key-here
     base_url: https://api.deepseek.com
     model: deepseek-chat

4️⃣ 验证配置
   运行: hos-ls chat
""",
            "openai": f"""
🔧 {cls.PROVIDER_CONFIG['openai']['name']} 配置方法：

1️⃣ 注册账号
   访问: https://platform.openai.com/

2️⃣ 获取API Key
   在 API Keys 页面创建新的密钥

3️⃣ 配置方式（任选其一）：
   
   📌 环境变量：
   set OPENAI_API_KEY=sk-your-key
   
   📌 配置文件：
   ai:
     provider: openai
     api_key: sk-your-key
     model: gpt-4
""",
            "anthropic": f"""
🔧 {cls.PROVIDER_CONFIG['anthropic']['name']} 配置方法：

1️⃣ 注册账号
   访问: https://console.anthropic.com/

2️⃣ 获取API Key
   在 API Keys 页面创建密钥

3️⃣ 配置方式：
   
   📌 环境变量：
   set ANTHROPIC_API_KEY=sk-ant-your-key
   
   📌 配置文件：
   ai:
     provider: anthropic
     api_key: sk-ant-your-key
     model: claude-3-5-sonnet-20241022
""",
            "local": f"""
🔧 {cls.PROVIDER_CONFIG['local']['name']} (Ollama) 配置方法：

1️⃣ 安装 Ollama
   访问: https://ollama.ai/
   下载并安装 Ollama

2️⃣ 启动 Ollama 服务
   终端运行: ollama serve

3️⃣ 拉取模型
   ollama pull llama2  (或其他模型)

4️⃣ 配置方式：
   
   📌 配置文件：
   ai:
     provider: local
     base_url: http://localhost:11434
     model: llama2
"""
        }
        
        return instructions.get(provider, f"未知提供商: {provider}")
    
    @classmethod
    def print_validation_result(cls, config: Config) -> bool:
        """打印验证结果并返回是否有效
        
        Args:
            config: 配置对象
            
        Returns:
            是否有效
        """
        from rich.console import Console
        from rich.panel import Panel
        
        console = Console()
        valid, error_msg, summary = cls.validate(config)
        
        if valid:
            console.print(Panel(
                f"[bold green]✅ AI配置有效[/bold green]\n\n"
                f"提供商: [cyan]{summary['provider_name']}[/cyan]\n"
                f"模型: [yellow]{summary['model']}[/yellow]\n"
                f"API密钥: {'✅ 已配置' if summary['api_key_configured'] else '❌ 未配置'}\n"
                f"Base URL: [dim]{summary['base_url']}[/dim]",
                title="🔒 AI配置检查",
                border_style="green"
            ))
        else:
            console.print(Panel(
                f"[bold red]❌ AI配置无效[/bold red]\n\n"
                f"{error_msg}\n\n"
                f"[dim]当前提供商: {summary['provider']}[/dim]",
                title="⚠️ AI配置错误",
                border_style="red"
            ))
            
            # 显示配置指引
            provider = summary.get("provider", "deepseek")
            instructions = cls.get_setup_instructions(provider)
            console.print(instructions)
            
        return valid
    
    @classmethod
    def ensure_configured(cls, config: Config) -> bool:
        """确保AI已配置，如果未配置则提示用户
        
        Args:
            config: 配置对象
            
        Returns:
            是否配置成功
        """
        valid, error_msg, summary = cls.validate(config)
        
        if not valid:
            from rich.console import Console
            console = Console()
            
            console.print("\n[bold yellow]⚠️ AI配置不完整，可能影响功能使用[/bold yellow]\n")
            cls.print_validation_result(config)
            
            return False
            
        return True
