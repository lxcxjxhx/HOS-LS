from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

try:
    import asts
    HAS_ASTS = True
except ImportError:
    HAS_ASTS = False


LANGUAGE_MAP: Dict[str, str] = {
    'python': 'Python',
    'javascript': 'JavaScript',
    'typescript': 'TypeScript',
    'c': 'C',
    'cpp': 'CPP',
    'c++': 'CPP',
    'go': 'Go',
    'golang': 'Go',
    'rust': 'Rust',
    'java': 'Java',
    'ruby': 'Ruby',
    'php': 'PHP',
    'csharp': 'CSharp',
    'c#': 'CSharp',
}


@dataclass
class NormalizedNode:
    """标准化AST节点"""
    node_type: str
    value: Optional[str] = None
    children: List['NormalizedNode'] = field(default_factory=list)
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """转换为字典格式"""
        return {
            'node_type': self.node_type,
            'value': self.value,
            'children': [child.to_dict() for child in self.children],
            'attributes': self.attributes,
        }


class TreeSitterAdapter:
    """
    Tree-sitter AST适配器

    封装asts库，提供跨语言的AST解析功能
    """

    def __init__(self):
        self._parser = None
        self._language_enum = None
        if HAS_ASTS:
            self._init_asts()

    def _init_asts(self):
        """初始化asts库"""
        try:
            self._parser = asts.ASTParser()
            self._language_enum = asts.ASTLanguage
        except Exception as e:
            raise ImportError(
                f"Failed to initialize asts library: {e}\n"
                "Please install tree-sitter bindings: pip install tree-sitter asts"
            )

    def _get_language_enum(self, language: str):
        """获取语言枚举值"""
        if not HAS_ASTS:
            raise ImportError(
                "asts library is not installed.\n"
                "Please install tree-sitter and asts:\n"
                "  pip install tree-sitter asts\n"
                "Also ensure you have tree-sitter language bindings for your target languages."
            )

        lang_name = LANGUAGE_MAP.get(language.lower())
        if not lang_name:
            raise ValueError(f"Unsupported language: {language}")

        lang_enum = getattr(self._language_enum, lang_name, None)
        if lang_enum is None:
            raise ValueError(f"Language {language} is not supported in asts library")

        return lang_enum

    def is_language_supported(self, language: str) -> bool:
        """
        检查语言是否被支持

        Args:
            language: 语言名称

        Returns:
            是否支持
        """
        if not HAS_ASTS:
            return False

        normalized = language.lower()
        if normalized not in LANGUAGE_MAP:
            return False

        lang_name = LANGUAGE_MAP[normalized]
        return hasattr(self._language_enum, lang_name)

    def parse(self, source_code: str, language: str) -> Any:
        """
        解析源代码为AST

        Args:
            source_code: 源代码
            language: 语言名称

        Returns:
            AST树对象
        """
        if not HAS_ASTS:
            raise ImportError(
                "asts library is not installed.\n"
                "Please install tree-sitter and asts:\n"
                "  pip install tree-sitter asts\n"
                "Also ensure you have tree-sitter language bindings for your target languages."
            )

        lang_enum = self._get_language_enum(language)

        try:
            tree = self._parser.parse(source_code, lang_enum)
            return tree
        except Exception as e:
            return self._parse_with_tree_sitter_fallback(source_code, language, e)

    def _parse_with_tree_sitter_fallback(self, source_code: str, language: str, original_error: Exception) -> Any:
        """使用原生tree-sitter作为回退方案"""
        try:
            import tree_sitter
            from tree_sitter import Language, Parser

            lang_enum = self._get_language_enum(language)
            lang_name = LANGUAGE_MAP.get(language.lower())

            parser = Parser()
            lang_instance = Language(tree_sitter.Language.library(), lang_enum.value)

            parser.set_language(lang_instance)
            tree = parser.parse(source_code.encode())

            return tree

        except ImportError:
            raise ImportError(
                f"Failed to parse {language} code. Both asts and tree-sitter are unavailable.\n"
                f"Original error: {original_error}\n"
                "Please install tree-sitter: pip install tree-sitter"
            )
        except Exception as e:
            raise RuntimeError(
                f"Failed to parse {language} code with both asts and tree-sitter.\n"
                f"Original asts error: {original_error}\n"
                f"Tree-sitter fallback error: {e}"
            )

    def _convert_node(self, node: Any) -> NormalizedNode:
        """将原生节点转换为标准化格式"""
        node_type = getattr(node, 'type', str(type(node)))
        node_value = getattr(node, 'text', None)
        if node_value and isinstance(node_value, bytes):
            node_value = node_value.decode('utf-8', errors='replace')

        children = []
        attributes = {}

        if hasattr(node, 'children'):
            for child in node.children:
                children.append(self._convert_node(child))

        if hasattr(node, 'named_children'):
            attributes['named_children'] = len(node.named_children)

        if hasattr(node, 'start_point') and hasattr(node, 'end_point'):
            attributes['start_point'] = node.start_point
            attributes['end_point'] = node.end_point

        if hasattr(node, 'is_named'):
            attributes['is_named'] = node.is_named

        return NormalizedNode(
            node_type=node_type,
            value=node_value,
            children=children,
            attributes=attributes
        )

    def parse_to_normalized(self, source_code: str, language: str) -> List[NormalizedNode]:
        """
        解析并转换为标准化格式

        Args:
            source_code: 源代码
            language: 语言名称

        Returns:
            标准化节点列表
        """
        tree = self.parse(source_code, language)

        if hasattr(tree, 'root_node'):
            root = tree.root_node
        else:
            root = tree

        return [self._convert_node(root)]

    def get_functions(self, ast: Any) -> List[NormalizedNode]:
        """
        提取函数定义

        Args:
            ast: AST树对象

        Returns:
            函数节点列表
        """
        functions = []
        function_keywords = {
            'function_definition', 'function_declaration',
            'method_definition', 'function'
        }

        def traverse(node: Any):
            node_type = getattr(node, 'type', '')

            if node_type in function_keywords:
                func_node = self._convert_node(node)
                if hasattr(node, 'children'):
                    for child in node.children:
                        child_type = getattr(child, 'type', '')
                        if 'identifier' in child_type:
                            func_node.attributes['name'] = getattr(child, 'text', b'').decode('utf-8', errors='replace') if isinstance(getattr(child, 'text', b''), bytes) else getattr(child, 'text', '')
                            break
                functions.append(func_node)

            if hasattr(node, 'children'):
                for child in node.children:
                    traverse(child)

        if hasattr(ast, 'root_node'):
            traverse(ast.root_node)
        else:
            traverse(ast)

        return functions

    def get_classes(self, ast: Any) -> List[NormalizedNode]:
        """
        提取类定义

        Args:
            ast: AST树对象

        Returns:
            类节点列表
        """
        classes = []
        class_keywords = {
            'class_definition', 'class_declaration', 'class'
        }

        def traverse(node: Any):
            node_type = getattr(node, 'type', '')

            if node_type in class_keywords:
                class_node = self._convert_node(node)
                if hasattr(node, 'children'):
                    for child in node.children:
                        child_type = getattr(child, 'type', '')
                        if 'identifier' in child_type or child_type == 'name':
                            class_node.attributes['name'] = getattr(child, 'text', b'').decode('utf-8', errors='replace') if isinstance(getattr(child, 'text', b''), bytes) else getattr(child, 'text', '')
                            break
                classes.append(class_node)

            if hasattr(node, 'children'):
                for child in node.children:
                    traverse(child)

        if hasattr(ast, 'root_node'):
            traverse(ast.root_node)
        else:
            traverse(ast)

        return classes

    def get_imports(self, ast: Any) -> List[str]:
        """
        提取导入语句

        Args:
            ast: AST树对象

        Returns:
            导入语句列表
        """
        imports = []
        import_keywords = {
            'import_statement', 'import', 'import_from', 'require_statement',
            'include_statement', 'use_statement'
        }

        def traverse(node: Any):
            node_type = getattr(node, 'type', '')

            if node_type in import_keywords:
                text = getattr(node, 'text', b'')
                if isinstance(text, bytes):
                    text = text.decode('utf-8', errors='replace')
                imports.append(text)

            if hasattr(node, 'children'):
                for child in node.children:
                    traverse(child)

        if hasattr(ast, 'root_node'):
            traverse(ast.root_node)
        else:
            traverse(ast)

        return imports
