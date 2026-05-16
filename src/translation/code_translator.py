from typing import Dict, List, Optional, Any
import re


class CodeTranslator:
    DEPENDENCY_MAPPING: Dict[str, Dict[str, str]] = {
        "java": {
            "java.lang.Runtime": "subprocess",
            "java.lang.ProcessBuilder": "subprocess",
            "java.net.HttpClient": "requests",
            "java.net.http.HttpRequest": "requests",
            "javax.xml.parsers.DocumentBuilder": "xml.etree.ElementTree",
            "org.w3c.dom.Document": "xml.etree.ElementTree",
            "java.sql.DriverManager": "sqlite3",
            "java.sql.Connection": "sqlite3",
            "java.io.FileInputStream": "builtins.open",
            "java.nio.file.Files": "pathlib",
            "java.util.HashMap": "dict",
            "java.util.ArrayList": "list",
            "java.util.HashSet": "set",
            "java.util.stream.Collectors": "list comprehension",
        },
        "go": {
            "os/exec": "subprocess",
            "net/http": "requests",
            "html/template": "string.Template",
            "encoding/json": "json",
            "database/sql": "sqlite3",
            "io/ioutil": "pathlib",
            "os.Open": "builtins.open",
        },
        "cpp": {
            "<iostream>": "print/input",
            "<fstream>": "builtins.open",
            "<vector>": "list",
            "<map>": "dict",
            "<string>": "str",
            "std::cout": "print",
            "std::cin": "input",
            "malloc/free": "memory management removed (Python GC)",
        },
        "javascript": {
            "fetch": "requests",
            "axios": "requests",
            "fs": "pathlib/builtins.open",
            "child_process": "subprocess",
            "crypto": "hashlib",
            "Buffer": "bytes",
            "JSON.parse": "json.loads",
            "JSON.stringify": "json.dumps",
        },
        "typescript": {
            "fetch": "requests",
            "axios": "requests",
            "fs": "pathlib/builtins.open",
            "child_process": "subprocess",
            "crypto": "hashlib",
            "Buffer": "bytes",
            "JSON.parse": "json.loads",
            "JSON.stringify": "json.dumps",
        },
    }

    PATTERN_TRANSFORMERS: Dict[str, List[Dict[str, str]]] = {
        "java": [
            {
                "pattern": r'Runtime\.getRuntime\(\)\.exec\("([^"]+)"\)',
                "replacement": r'subprocess.run("\1", shell=True)',
                "description": "Runtime.exec() to subprocess",
            },
            {
                "pattern": r'System\.out\.println\("([^"]+)"\)',
                "replacement": r'print("\1")',
                "description": "System.out.println to print",
            },
            {
                "pattern": r'ArrayList<(\w+)>\s+(\w+)\s*=\s*new\s+ArrayList<>\(\)',
                "replacement": r'\2: list[\1] = []',
                "description": "ArrayList declaration",
            },
            {
                "pattern": r'HashMap<(\w+),\s*(\w+)>\s*(\w+)\s*=\s*new\s+HashMap<>\(\)',
                "replacement": r'\3: dict[\1, \2] = {}',
                "description": "HashMap declaration",
            },
            {
                "pattern": r'(\w+)\.forEach\(([\w]+)\s*->\s*(.+)\)',
                "replacement": r'for \2 in \1: \3',
                "description": "forEach lambda to for loop",
            },
            {
                "pattern": r'if\s*\(([^)]+)\s*instanceof\s+(\w+)\)',
                "replacement": r'if isinstance(\1, \2)',
                "description": "instanceof to isinstance",
            },
            {
                "pattern": r'string\.format\("([^"]+)",\s*([^)]+)\)',
                "replacement": r'f"\1".format(\2)',
                "description": "String.format to f-string",
            },
        ],
        "go": [
            {
                "pattern": r'exec\.Command\("([^"]+)"\)\s*\.Run\(\)',
                "replacement": r'subprocess.run("\1", shell=True)',
                "description": "exec.Command to subprocess",
            },
            {
                "pattern": r'fmt\.Println\("([^"]+)"\)',
                "replacement": r'print("\1")',
                "description": "fmt.Println to print",
            },
            {
                "pattern": r'if\s+err\s*!=\s*nil\s*\{[^}]*\}',
                "replacement": r'try: ... except Exception as e:',
                "description": "error handling pattern",
            },
            {
                "pattern": r'make\(\[\](\w+),\s*(\d+)\)',
                "replacement": r'[None] * \2  # or list comprehension',
                "description": "make slice to list",
            },
            {
                "pattern": r'map\[(\w+)\]\s*(\w+)\s*\{\}',
                "replacement": r'dict[\1, \2] = {}',
                "description": "map declaration",
            },
        ],
        "cpp": [
            {
                "pattern": r'std::cout\s*<<\s*"([^"]+)"\s*<<\s*std::endl',
                "replacement": r'print("\1")',
                "description": "cout to print",
            },
            {
                "pattern": r'std::cin\s*>>\s*(\w+)',
                "replacement": r'\1 = input()',
                "description": "cin to input",
            },
            {
                "pattern": r'std::vector<(\w+)>',
                "replacement": r'list[\1]',
                "description": "vector to list",
            },
            {
                "pattern": r'std::map<(\w+),\s*(\w+)>',
                "replacement": r'dict[\1, \2]',
                "description": "map to dict",
            },
            {
                "pattern": r'for\s*\(int\s+(\w+)\s*=\s*0;\s*\1\s*<\s*(\d+);\s*\1\+\+\)',
                "replacement": r'for \1 in range(\2)',
                "description": "for loop to range",
            },
        ],
        "javascript": [
            {
                "pattern": r'console\.log\("([^"]+)"\)',
                "replacement": r'print("\1")',
                "description": "console.log to print",
            },
            {
                "pattern": r'fetch\("([^"]+)"\)',
                "replacement": r'requests.get("\1")',
                "description": "fetch to requests",
            },
            {
                "pattern": r'require\("([^"]+)"\)',
                "replacement": r'import \1',
                "description": "require to import",
            },
            {
                "pattern": r'=>\s*\{([^}]+)\}',
                "replacement": r'def \1:',
                "description": "arrow function to def",
            },
            {
                "pattern": r'\.then\(([\w]+)\s*=>\s*(.+)\)',
                "replacement": r'# async: await \1 \2',
                "description": "promise then to await",
            },
            {
                "pattern": r'async\s+function\s+(\w+)\(([^)]*)\)\s*\{',
                "replacement": r'async def \1(\2):',
                "description": "async function to async def",
            },
        ],
        "typescript": [
            {
                "pattern": r'console\.log\("([^"]+)"\)',
                "replacement": r'print("\1")',
                "description": "console.log to print",
            },
            {
                "pattern": r'fetch\("([^"]+)"\)',
                "replacement": r'requests.get("\1")',
                "description": "fetch to requests",
            },
            {
                "pattern": r'const\s+(\w+):\s*(\w+)\s*=\s*(.+)',
                "replacement": r'\1: \2 = \3',
                "description": "const declaration",
            },
            {
                "pattern": r'interface\s+(\w+)\s*\{([^}]+)\}',
                "replacement": r'@dataclass\nclass \1:\n    \2',
                "description": "interface to dataclass",
            },
            {
                "pattern": r'type\s+(\w+)\s*=\s*"([^"]+)"',
                "replacement": r'\1 = "\2"  # type alias',
                "description": "type alias",
            },
        ],
    }

    def __init__(self):
        self.supported_languages = ["java", "go", "cpp", "javascript", "typescript"]

    def translate_code(self, code: str, source_lang: str) -> str:
        if source_lang.lower() not in self.supported_languages:
            return f"Error: Unsupported language '{source_lang}'. Supported: {self.supported_languages}"

        translated = code
        translated = self._apply_pattern_transformers(translated, source_lang.lower())
        translated = self._apply_import_translations(translated, source_lang.lower())

        return translated

    def identify_dependencies(self, code: str, source_lang: str) -> List[Dict[str, Any]]:
        dependencies: List[Dict[str, Any]] = []
        lang_lower = source_lang.lower()

        if lang_lower == "java":
            deps = re.findall(r'(?:import|import\s+static)\s+([\w.]+);', code)
            for dep in deps:
                mapping = self.map_to_python_alternative(dep)
                dependencies.append({
                    "original": dep,
                    "python_alternative": mapping,
                    "requires_ai": mapping is None,
                })
            exec_matches = re.findall(r'Runtime\.getRuntime\(\)\.exec\("([^"]+)"\)', code)
            for match in exec_matches:
                dependencies.append({
                    "original": f"Runtime.exec('{match}')",
                    "python_alternative": "subprocess",
                    "requires_ai": False,
                })
            http_clients = re.findall(r'HttpClient\.(?:newHttpClient|get\(\))', code)
            for _ in http_clients:
                dependencies.append({
                    "original": "HttpClient",
                    "python_alternative": "requests",
                    "requires_ai": False,
                })

        elif lang_lower == "go":
            deps = re.findall(r'(?:import|")([\w/]+)(?:"|)', code)
            go_imports = re.findall(r'import\s*\(\s*([\s\S]*?)\s*\)', code)
            if go_imports:
                for import_block in go_imports:
                    deps.extend(re.findall(r'"([^"]+)"', import_block))
            for dep in set(deps):
                mapping = self.map_to_python_alternative(dep)
                if mapping:
                    dependencies.append({
                        "original": dep,
                        "python_alternative": mapping,
                        "requires_ai": False,
                    })

        elif lang_lower == "cpp":
            includes = re.findall(r'#include\s*<([^>]+)>', code)
            for inc in includes:
                mapping = self.map_to_python_alternative(f"<{inc}>")
                dependencies.append({
                    "original": f"<{inc}>",
                    "python_alternative": mapping,
                    "requires_ai": mapping is None,
                })

        elif lang_lower in ["javascript", "typescript"]:
            requires = re.findall(r'require\s*\(\s*"([^"]+)"\s*\)', code)
            imports = re.findall(r'import\s+(?:{\s*)?([\w]+)(?:\s*,?\s*{[^}]*})?\s*from\s+"([^"]+)"', code)
            for req in requires:
                mapping = self.map_to_python_alternative(req)
                dependencies.append({
                    "original": f"require('{req}')",
                    "python_alternative": mapping,
                    "requires_ai": mapping is None,
                })
            for imp, mod in imports:
                mapping = self.map_to_python_alternative(mod)
                dependencies.append({
                    "original": f"import {imp} from '{mod}'",
                    "python_alternative": mapping,
                    "requires_ai": mapping is None,
                })

        return dependencies

    def map_to_python_alternative(self, dependency: str) -> Optional[str]:
        for lang, mappings in self.DEPENDENCY_MAPPING.items():
            for key, value in mappings.items():
                if key in dependency or dependency in key:
                    return value
        return None

    def transform_pattern(self, code: str, pattern: str, replacement: str) -> str:
        try:
            return re.sub(pattern, replacement, code)
        except re.error:
            return code

    def analyze_code_logic(self, code: str, source_lang: str) -> Dict[str, Any]:
        lang_lower = source_lang.lower()
        analysis = {
            "language": source_lang,
            "requires_ai_assistance": False,
            "complexity": "unknown",
            "detected_patterns": [],
            "warnings": [],
            "suggestions": [],
        }

        if lang_lower == "java":
            if "Runtime.getRuntime().exec" in code:
                analysis["detected_patterns"].append("command-execution")
                analysis["suggestions"].append("Use subprocess with shell=False for safer execution")
            if "HttpClient" in code or "HttpURLConnection" in code:
                analysis["detected_patterns"].append("http-client")
                analysis["suggestions"].append("Convert to requests library")
            if "DocumentBuilder" in code or "SAXParser" in code:
                analysis["detected_patterns"].append("xml-parsing")
                analysis["suggestions"].append("Use xml.etree.ElementTree or lxml")
            if "ObjectInputStream" in code:
                analysis["detected_patterns"].append("deserialization")
                analysis["warnings"].append("Deserialization detected - security risk")
                analysis["requires_ai_assistance"] = True

        elif lang_lower == "go":
            if "exec.Command" in code:
                analysis["detected_patterns"].append("command-execution")
                analysis["suggestions"].append("Use subprocess module with proper argument handling")
            if "html/template" in code:
                analysis["detected_patterns"].append("template-rendering")
            if "database/sql" in code:
                analysis["detected_patterns"].append("database-operation")

        elif lang_lower == "cpp":
            if "system(" in code:
                analysis["detected_patterns"].append("system-call")
                analysis["warnings"].append("system() calls are dangerous - consider subprocess")
            if "malloc" in code or "free" in code:
                analysis["detected_patterns"].append("manual-memory-management")
                analysis["suggestions"].append("Python handles memory automatically")

        elif lang_lower in ["javascript", "typescript"]:
            if "child_process" in code or "spawn" in code or "exec" in code:
                analysis["detected_patterns"].append("process-spawning")
            if "eval(" in code:
                analysis["detected_patterns"].append("dynamic-code-execution")
                analysis["warnings"].append("eval() is a security risk")
                analysis["requires_ai_assistance"] = True
            if "fetch(" in code or "axios" in code:
                analysis["detected_patterns"].append("http-client")

        if not analysis["detected_patterns"]:
            analysis["complexity"] = "simple"
        elif len(analysis["detected_patterns"]) <= 2:
            analysis["complexity"] = "moderate"
        else:
            analysis["complexity"] = "complex"
            analysis["requires_ai_assistance"] = True

        if analysis["requires_ai_assistance"]:
            analysis["suggestions"].append("This code requires AI-assisted translation for accurate conversion")

        return analysis

    def _apply_pattern_transformers(self, code: str, lang: str) -> str:
        if lang not in self.PATTERN_TRANSFORMERS:
            return code

        transformed = code
        for transformer in self.PATTERN_TRANSFORMERS[lang]:
            pattern = transformer["pattern"]
            replacement = transformer["replacement"]
            try:
                transformed = re.sub(pattern, replacement, transformed)
            except re.error:
                continue

        return transformed

    def _apply_import_translations(self, code: str, lang: str) -> str:
        return code
