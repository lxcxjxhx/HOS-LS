import subprocess
import sys

files = [
    r"src\core\scanner.py",
    r"src\cli\serial_port\panel.py",
    r"src\analyzers\verification\ast_transpiler_engine.py",
    r"src\ai\pure_ai\rag\embedding_optimizer.py",
    r"src\chat\main.py",
    r"src\core\chat\main.py",
    r"src\core\chunk_processor.py",
    r"src\i18n\__init__.py",
    r"src\analyzers\verification\method_storage.py",
    r"src\utils\json_parser.py",
    r"src\nvd\etl\nvd_etl.py",
    r"src\ai\pure_ai\rag\reranker.py",
    r"src\scanner\vulnerability_data_manager.py",
]

for f in files:
    result = subprocess.run(
        [sys.executable, "-m", "mypy", f, "--show-error-codes"], capture_output=True, text=True
    )
    # Count errors in the target file only
    lines = result.stdout.split("\n")
    errors = [l for l in lines if l.startswith(f) and ": error:" in l]
    print(f"{f}: {len(errors)} errors")
    for e in errors:
        print(f"  {e}")
