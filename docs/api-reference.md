# API Reference

## CLI Command Reference

### Global Options

```bash
hos [OPTIONS] COMMAND [ARGS]...
```

| Option | Description |
|--------|-------------|
| `--version` | Show version |
| `-c, --config PATH` | Custom config file path |
| `-v, --verbose` | Verbose output |
| `-q, --quiet` | Quiet mode |
| `-d, --debug` | Debug mode |

---

### `hos init`

Initialize configuration and API keys.

```bash
hos init
```

**Interactive prompts**:
- AI provider selection (deepseek, anthropic, openai, aliyun)
- API key input
- Default model selection
- Scan preferences

---

### `hos scan`

Run security scan on target code.

```bash
hos scan [TARGET] [OPTIONS]
```

**Arguments**:
- `TARGET`: Target directory or file (default: current directory `.`)

**Scan Mode Options**:
| Option | Description |
|--------|-------------|
| `--mode` | Scan mode: `auto`, `pure-ai`, `fast`, `deep`, `stealth`, `vuln-lab` |
| `--pure-ai` | Enable Pure AI mode (isolated runtime, AI analysis only) |
| `--ai` | Enable AI analysis in full mode |

**AI Configuration**:
| Option | Description |
|--------|-------------|
| `--ai-provider` | AI provider: `anthropic`, `openai`, `deepseek`, `local` |
| `--ai-model` | AI model name (e.g., `deepseek-chat`, `deepseek-reasoner`) |
| `--ai-proxy` | HTTP proxy URL (auto-detects Clash proxy) |

**Performance Options**:
| Option | Description | Default |
|--------|-------------|---------|
| `-w, --workers` | Number of parallel workers | 4 |
| `--incremental` | Enable incremental scanning | - |
| `--full-scan` | Force full scan, ignore incremental index | - |
| `--index-status` | Show index status | - |
| `--no-graph` | Disable code graph building | - |

**Output Options**:
| Option | Description | Default |
|--------|-------------|---------|
| `-f, --format` | Output format: `html`, `markdown`, `json`, `sarif` | html |
| `-o, --output` | Output file path | auto-generated |

**Control Options**:
| Option | Description |
|--------|-------------|
| `--test N` | Test mode, scan only N files |
| `--resume` | Resume from checkpoint |
| `--truncate-output` | Stop at conditions but output report |
| `--max-duration` | Max scan duration in seconds (0 = unlimited) |
| `--max-files` | Max files to scan (0 = unlimited) |
| `--explain` | Show execution flow |
| `--skip-data-update` | Skip data update check |

**Audit & Verification**:
| Option | Description |
|--------|-------------|
| `--sandbox` | Enable sandbox dynamic verification (experimental) |
| `--audit-mode` | Audit mode: `static`, `dynamic`, `hybrid` |
| `--static-only` | Only static analysis |
| `--dynamic-only` | Only dynamic AI red-team POC testing |
| `--generate-poc` | Generate POC scripts for findings |
| `--run-poc` | Execute POC verification |
| `--poc-only` | Only generate POCs without scanning |

**Port Scanning**:
| Option | Description | Default |
|--------|-------------|---------|
| `--scan-ports` | Enable API port scanning | - |
| `--ports-only` | Only port scanning | - |
| `--port-range` | Port range (e.g., `1-65535`) | 1-65535 |

**Priority Strategy**:
| Option | Description |
|--------|-------------|
| `--priority` | Strategy: `api-first`, `security-first`, `performance-first`, `full-scan`, `custom` |
| `--priority-rules` | Custom priority rules file path (YAML/JSON) |

**Report Filtering**:
| Option | Description |
|--------|-------------|
| `--report-category` | Filter by category: `all`, `port-related`, `general-static`, `special-scan`, `api-security`, `auth-security`, `data-protection`, `config-security` |
| `--min-confidence` | Min confidence: `HIGH`, `MEDIUM`, `LOW`, `ALL` |

**Remote Scanning**:
| Option | Description |
|--------|-------------|
| `--remote` | Enable remote scanning |
| `--remote-type` | Connection type: `ssh`, `http`, `serial` |
| `--remote-host` | Remote host address |
| `--remote-port` | Remote port |
| `--remote-username` | Remote username (SSH) |
| `--remote-password` | Remote password (SSH) |
| `--remote-key` | SSH private key path |
| `--remote-path` | Remote scan path |
| `--serial-port` | Serial port (e.g., COM1) |
| `--serial-baudrate` | Serial baud rate | 115200 |

**Other Options**:
| Option | Description |
|--------|-------------|
| `-l, --language` | Interface language: `zh`, `en` |
| `--ask` | Lightweight question-answering |
| `--focus` | Focus analysis on specific file/directory |
| `--tool-chain` | Specify toolchain: `semgrep,trivy,gitleaks,code_vuln_scanner` |
| `--langgraph` | Use LangGraph workflow |

**Examples**:

```bash
# Quick AI scan
hos scan . --pure-ai

# Deep scan with HTML report
hos scan . --mode deep --format html --output report.html

# Test mode with 10 files
hos scan . --pure-ai --test 10

# Incremental scan with sandbox
hos scan . --incremental --sandbox

# Remote SSH scan
hos scan --remote --remote-type ssh --remote-host 192.168.1.100 --remote-user admin

# Port scanning only
hos scan . --pure-ai --scan-ports --ports-only --port-range 1-1024
```

---

### `hos config`

Display, import, or export configuration.

```bash
hos config [OPTIONS]
```

| Option | Description |
|--------|-------------|
| `-e, --export` | Export config: `yaml` or `json` |
| `-i, --import, --input` | Import config from file |
| `-o, --output` | Export file path |

**Examples**:

```bash
# Display current config
hos config

# Export to YAML
hos config --export yaml -o my-config.yaml

# Import from YAML
hos config --import my-config.yaml
```

---

### `hos nvd`

Manage NVD vulnerability database.

```bash
hos nvd COMMAND [OPTIONS]
```

**Subcommands**:

#### `hos nvd update`

Update NVD database and sync to RAG knowledge base.

| Option | Description | Default |
|--------|-------------|---------|
| `-z, --zip` | NVD zip file path | nvd-json-data-feeds-main.zip |
| `-d, --dir` | NVD data directory | - |
| `-l, --limit` | Limit files processed (for testing) | - |
| `--no-rag` | Skip RAG import, parse only | - |
| `-b, --batch-size` | Batch size | 1000 |
| `--resume` | Resume from file index | 0 |
| `--model` | Embedding model name | Qwen/Qwen3-Embedding-0.6B |

```bash
# Update from preloaded data
hos nvd update

# Update from custom directory
hos nvd update --dir /path/to/nvd-data

# Update with custom model
hos nvd update --model text-embedding-ada-002
```

#### `hos nvd show-checkpoint`

Show current checkpoint status.

```bash
hos nvd show-checkpoint
```

#### `hos nvd clean-checkpoints`

Clean checkpoint residual files.

```bash
hos nvd clean-checkpoints [--force]
```

---

### `hos report`

Generate report from scan data.

```bash
hos report [OPTIONS]
```

**Supported formats**: `html`, `json`, `sarif`, `markdown`, `csv`

---

### `hos plugin`

Manage plugins.

```bash
hos plugin list          # List available plugins
hos plugin install NAME  # Install a plugin
hos plugin remove NAME   # Remove a plugin
```

---

### `hos rule`

Manage detection rules.

```bash
hos rule list            # List all rules
hos rule show RULE_ID    # Show rule details
```

---

### `hos verify`

Verify scan report findings.

```bash
hos verify REPORT_PATH [OPTIONS]
```

---

### `hos validator`

Manage validators.

```bash
hos validator list     # List available validators
```

---

### `hos data-preload`

Manage data preloading.

```bash
hos data-preload run       # Download all preloaded data
hos data-preload status    # Check download status
```

---

### `hos index`

Manage code index.

```bash
hos index build      # Build code index
hos index status     # Show index status
hos index clear      # Clear index
```

---

### `hos model`

Manage AI models.

```bash
hos model list       # List available models
hos model test       # Test model connectivity
```

---

### `hos chat`

Interactive chat mode for code security Q&A.

```bash
hos chat [TARGET]
```

---

### `hos panel`

Interactive TUI panel.

```bash
hos panel
```

---

## Configuration File

### `hos-ls.yaml`

Place in project root directory.

```yaml
ai:
  provider: deepseek
  model: deepseek-reasoner
  api_key: ${DEEPSEEK_API_KEY}
  temperature: 0.0
  max_tokens: 4096
  timeout: 60
  
  aliyun:
    enabled: false
    api_key: ""
    model: qwen3-coder-next
  
  rag:
    enabled: true
    embedding_model: Qwen/Qwen3-Embedding-0.6B
    rerank_model: BAAI/bge-reranker-large

scan:
  max_workers: 4
  incremental: true
  cache_enabled: true
  mode: auto

rules:
  ruleset: default
  exclude_paths:
    - "node_modules/**"
    - ".git/**"
    - "*.min.js"

report:
  format: html
  output: ./security-report
  include_snippets: true
  include_fix_suggestions: true
  category_filter: all

tools:
  enabled: true
  semgrep:
    enabled: true
  trivy:
    enabled: true
  gitleaks:
    enabled: true

validation:
  auto_validate_high: true
  auto_validate_medium: false
  min_confidence_threshold: 0.7
  line_number_tolerance: 5

sandbox:
  enabled: false
  timeout: 30
  mode: hybrid

priority:
  weights:
    cvss: 0.40
    exploitability: 0.35
    reachability: 0.25
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `DEEPSEEK_API_KEY` | DeepSeek API key |
| `ANTHROPIC_API_KEY` | Anthropic API key |
| `OPENAI_API_KEY` | OpenAI API key |
| `HOS_LS_CONFIG_PATH` | Custom config file path |
| `HTTP_PROXY` | HTTP proxy for API requests |
| `HTTPS_PROXY` | HTTPS proxy for API requests |
| `HOS_LS_MODE` | Force scan mode (set to `PURE_AI`) |

---

## Programmatic API Usage

### Basic Scanner Usage

```python
from src.core.scanner import create_scanner
from src.core.config import Config

config = Config()
config.ai.enabled = True
config.ai.provider = "deepseek"
config.ai.model = "deepseek-reasoner"

scanner = create_scanner(config)
result = scanner.scan_sync("/path/to/code")

print(f"Found {len(result.findings)} issues")
for finding in result.findings:
    print(f"  [{finding.severity.value}] {finding.message}")
```

### Pure AI Mode

```python
import os
from src.core.config import Config
from src.core.scanner import create_scanner

os.environ["HOS_LS_MODE"] = "PURE_AI"

config = Config()
config.pure_ai = True
config.scan_mode = "pure-ai"
config.ai.enabled = True
config.scan.max_workers = 4

scanner = create_scanner(config)
result = scanner.scan_sync("/path/to/code")
```

### Report Generation

```python
from src.reporting.generator import ReportGenerator

generator = ReportGenerator(config)
report_path = generator.generate([result], "report.html", "html")
print(f"Report generated: {report_path}")
```

### NVD Database Operations

```python
from src.integration.nvd_update import run_update

stats = run_update(
    input_path="/path/to/nvd-data",
    rag_base=None,
    limit=None,
    batch_size=1000
)
print(f"Processed: {stats}")
```

### Configuration Management

```python
from src.core.config import ConfigManager

manager = ConfigManager()
config = manager.auto_load()

config.ai.provider = "openai"
config.ai.model = "gpt-4"
manager.save_config(config)
```

### LangGraph Workflow

```python
import asyncio
from src.core.langgraph_flow import analyze_code

async def run_analysis():
    code = """
def login(username, password):
    query = f"SELECT * FROM users WHERE username='{username}'"
    return db.execute(query)
    """
    result = await analyze_code(code)
    print(result['final_report'])

asyncio.run(run_analysis())
```

### Plugin Management

```python
from src.plugins.manager import PluginManager
from src.plugins.registry import PluginRegistry

registry = PluginRegistry()
manager = PluginManager(registry)

plugins = manager.list_plugins()
for plugin in plugins:
    print(f"{plugin.name}: {plugin.version}")
```

---

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | Scan completed, issues found |
| 2 | Scan failed (error) |

---

*Last Updated: 2026-05-25*
