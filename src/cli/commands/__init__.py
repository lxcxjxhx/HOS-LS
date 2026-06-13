"""CLI 命令模块"""

def __getattr__(name: str):
    if name == "scan":
        from .scan import scan
        return scan
    elif name == "config":
        from .config import config
        return config
    elif name == "nvd":
        from .nvd import nvd
        return nvd
    elif name == "data_preload":
        from .data_preload import data_preload
        return data_preload
    elif name == "index":
        from .index import index
        return index
    elif name == "model":
        from .model import model
        return model
    elif name == "panel":
        from .misc import panel
        return panel
    elif name == "serial":
        from .misc import serial
        return serial
    elif name == "chat":
        from .misc import chat
        return chat
    elif name == "rules":
        from .misc import rules
        return rules
    elif name == "init":
        from .misc import init
        return init
    elif name == "import_scan":
        from .misc import import_scan
        return import_scan
    elif name == "verify":
        from .verify import verify
        return verify
    elif name == "replay":
        from .misc import replay
        return replay
    elif name == "plugin":
        from .plugin import plugin
        return plugin
    elif name == "interactive":
        from .interactive import interactive
        return interactive
    elif name == "live_scan":
        from .live_scan import live_scan
        return live_scan
    elif name == "report":
        from .report import report
        return report
    elif name == "validator":
        from .validator import validator
        return validator
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

__all__ = [
    "scan",
    "config",
    "nvd",
    "data_preload",
    "index",
    "model",
    "panel",
    "serial",
    "chat",
    "rules",
    "init",
    "import_scan",
    "verify",
    "replay",
    "plugin",
    "interactive",
    "live_scan",
    "report",
    "validator",
]
