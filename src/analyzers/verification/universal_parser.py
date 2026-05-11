from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional
import ast


class SupportedLanguage(Enum):
    PYTHON = "python"
    JAVA = "java"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    C = "c"
    CPP = "cpp"
    GO = "go"
    RUST = "rust"
    CSHARP = "csharp"
    KOTLIN = "kotlin"
    RUBY = "ruby"


@dataclass
class ParserResult:
    ast_tree: Any = None
    language: Optional[SupportedLanguage] = None
    source_code: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    success: bool = False
    error: str = ""


class UniversalParser:
    def __init__(self):
        self._parsers: Dict[SupportedLanguage, Any] = {}
        self._initialize_parsers()

    def _initialize_parsers(self):
        for lang in SupportedLanguage:
            parser = self._get_parser_for_language(lang)
            if parser is not None:
                self._parsers[lang] = parser

    def _get_parser_for_language(self, language: SupportedLanguage) -> Optional[Any]:
        if language == SupportedLanguage.PYTHON:
            return PythonParser()
        elif language == SupportedLanguage.JAVA:
            return JavaParser()
        elif language == SupportedLanguage.JAVASCRIPT or language == SupportedLanguage.TYPESCRIPT:
            return JavaScriptParser()
        elif language == SupportedLanguage.C or language == SupportedLanguage.CPP:
            return CppParser()
        elif language == SupportedLanguage.GO:
            return GoParser()
        elif language == SupportedLanguage.RUST:
            return RustParser()
        elif language == SupportedLanguage.CSHARP:
            return CSharpParser()
        elif language == SupportedLanguage.KOTLIN:
            return KotlinParser()
        elif language == SupportedLanguage.RUBY:
            return RubyParser()
        return None

    def parse(self, source_code: str, language: Optional[SupportedLanguage] = None) -> ParserResult:
        if language is None:
            language = self.detect_language(source_code)

        parser = self.get_parser_for_language(language)
        if parser is None:
            return ParserResult(
                success=False,
                error=f"No parser available for language: {language}",
                source_code=source_code,
                language=language
            )

        try:
            result = parser.parse(source_code)
            result.language = language
            result.source_code = source_code
            result.metadata["line_count"] = len(source_code.splitlines())
            return result
        except Exception as e:
            return ParserResult(
                success=False,
                error=str(e),
                source_code=source_code,
                language=language
            )

    def detect_language(self, source_code: str) -> SupportedLanguage:
        lines = source_code.strip().split("\n")
        if not lines:
            return SupportedLanguage.PYTHON

        first_lines = "\n".join(lines[:20])

        if "import java." in source_code or "import javax." in source_code or "public class" in first_lines:
            return SupportedLanguage.JAVA

        if "#include <iostream>" in source_code or "#include <cstdlib>" in source_code or "std::" in source_code:
            return SupportedLanguage.CPP

        if "#include <stdio.h>" in source_code or "#include <stdlib.h>" in source_code:
            return SupportedLanguage.C

        if "package main" in first_lines or "func main()" in source_code:
            return SupportedLanguage.GO

        if "fn main()" in source_code or "use std::" in source_code or "println!" in source_code:
            return SupportedLanguage.RUST

        if "namespace " in first_lines and ("using System;" in source_code or "public class" in first_lines):
            return SupportedLanguage.CSHARP

        if "fun main(" in source_code or "val " in source_code or "var " in source_code:
            return SupportedLanguage.KOTLIN

        if "def " in source_code or "import " in source_code:
            indent_check = [line for line in lines if line.strip() and not line.startswith(" ") and not line.startswith("\t")]
            if indent_check and ":" in source_code and "{" not in source_code:
                return SupportedLanguage.PYTHON

        if "function " in source_code or "const " in source_code or "let " in source_code or "var " in source_code:
            if ": " in source_code and ("interface " in source_code or "type " in source_code):
                return SupportedLanguage.TYPESCRIPT
            return SupportedLanguage.JAVASCRIPT

        if "require " in source_code or "def " in source_code:
            return SupportedLanguage.RUBY

        return SupportedLanguage.PYTHON

    def get_parser_for_language(self, language: SupportedLanguage) -> Optional[Any]:
        return self._parsers.get(language)


class PythonParser:
    def parse(self, source_code: str) -> ParserResult:
        try:
            tree = ast.parse(source_code)
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "python_ast"}
            )
        except SyntaxError as e:
            return ParserResult(
                success=False,
                error=f"Python syntax error: {e}"
            )
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"Python parsing error: {e}"
            )


class JavaParser:
    def __init__(self):
        self._parser = None
        self._init_parser()

    def _init_parser(self):
        try:
            import javalang
            self._parser = "javalang"
        except ImportError:
            try:
                import javaast
                self._parser = "javaast"
            except ImportError:
                self._parser = None

    def parse(self, source_code: str) -> ParserResult:
        if self._parser is None:
            return ParserResult(
                success=False,
                error="No Java parser available. Install javalang or javaast."
            )

        try:
            if self._parser == "javalang":
                import javalang
                tree = javalang.parse.parse(source_code)
                return ParserResult(
                    ast_tree=tree,
                    success=True,
                    metadata={"parser": "javalang"}
                )
            else:
                import javaast
                tree = javaast.parse(source_code)
                return ParserResult(
                    ast_tree=tree,
                    success=True,
                    metadata={"parser": "javaast"}
                )
        except ImportError:
            return ParserResult(
                success=False,
                error="Java parser library not available"
            )
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"Java parsing error: {e}"
            )


class JavaScriptParser:
    def parse(self, source_code: str) -> ParserResult:
        try:
            import esprima
            tree = esprima.parseScript(source_code)
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "esprima"}
            )
        except ImportError:
            try:
                import ast
                tree = ast.parse(source_code)
                return ParserResult(
                    ast_tree=tree,
                    success=True,
                    metadata={"parser": "python_ast_fallback"}
                )
            except Exception:
                pass
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"JavaScript parsing error: {e}"
            )

        return ParserResult(
            success=False,
            error="No JavaScript parser available. Install esprima."
        )


class CppParser:
    def parse(self, source_code: str) -> ParserResult:
        try:
            import asts
            tree = asts.cpp.parse(source_code)
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "asts"}
            )
        except ImportError:
            pass

        try:
            import tree_sitter
            from tree_sitter_languages import get_language, get_parser
            language = get_language('cpp')
            parser = get_parser()
            tree = parser.parse(bytes(source_code, "utf8"))
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "tree_sitter"}
            )
        except ImportError:
            pass
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"C++ parsing error with tree-sitter: {e}"
            )

        return ParserResult(
            success=False,
            error="No C++ parser available. Install asts or tree-sitter."
        )


class GoParser:
    def parse(self, source_code: str) -> ParserResult:
        try:
            import ast
            tree = ast.ParseFile(source_code, "")
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "go_ast"}
            )
        except ImportError:
            pass

        try:
            import tree_sitter
            from tree_sitter_languages import get_language, get_parser
            language = get_language('go')
            parser = get_parser()
            tree = parser.parse(bytes(source_code, "utf8"))
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "tree_sitter"}
            )
        except ImportError:
            pass
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"Go parsing error with tree-sitter: {e}"
            )

        return ParserResult(
            success=False,
            error="No Go parser available."
        )


class RustParser:
    def parse(self, source_code: str) -> ParserResult:
        try:
            import tree_sitter
            from tree_sitter_languages import get_language, get_parser
            language = get_language('rust')
            parser = get_parser()
            tree = parser.parse(bytes(source_code, "utf8"))
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "tree_sitter"}
            )
        except ImportError:
            pass
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"Rust parsing error: {e}"
            )

        return ParserResult(
            success=False,
            error="No Rust parser available. Install tree-sitter."
        )


class CSharpParser:
    def parse(self, source_code: str) -> ParserResult:
        try:
            import tree_sitter
            from tree_sitter_languages import get_language, get_parser
            language = get_language('csharp')
            parser = get_parser()
            tree = parser.parse(bytes(source_code, "utf8"))
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "tree_sitter"}
            )
        except ImportError:
            pass
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"C# parsing error: {e}"
            )

        return ParserResult(
            success=False,
            error="No C# parser available. Install tree-sitter."
        )


class KotlinParser:
    def parse(self, source_code: str) -> ParserResult:
        try:
            import tree_sitter
            from tree_sitter_languages import get_language, get_parser
            language = get_language('kotlin')
            parser = get_parser()
            tree = parser.parse(bytes(source_code, "utf8"))
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "tree_sitter"}
            )
        except ImportError:
            pass
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"Kotlin parsing error: {e}"
            )

        return ParserResult(
            success=False,
            error="No Kotlin parser available. Install tree-sitter."
        )


class RubyParser:
    def parse(self, source_code: str) -> ParserResult:
        try:
            import tree_sitter
            from tree_sitter_languages import get_language, get_parser
            language = get_language('ruby')
            parser = get_parser()
            tree = parser.parse(bytes(source_code, "utf8"))
            return ParserResult(
                ast_tree=tree,
                success=True,
                metadata={"parser": "tree_sitter"}
            )
        except ImportError:
            pass
        except Exception as e:
            return ParserResult(
                success=False,
                error=f"Ruby parsing error: {e}"
            )

        return ParserResult(
            success=False,
            error="No Ruby parser available. Install tree-sitter."
        )
