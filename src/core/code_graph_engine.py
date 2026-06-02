"""CodeGraphEngine - 代码图引擎

基于 tree-sitter 和 SQLite 的代码符号图谱引擎，支持多语言代码解析、
符号提取、关系构建和全文搜索。
"""

import hashlib
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

try:
    import aiosqlite
    HAS_AIOSQLITE = True
except ImportError:
    HAS_AIOSQLITE = False

try:
    from tree_sitter import Language, Node, Parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

logger = logging.getLogger(__name__)

SYMBOL_TYPES = {
    "function_definition": "function",
    "function_declaration": "function",
    "method_definition": "method",
    "class_definition": "class",
    "class_declaration": "class",
    "import_statement": "import",
    "import_from_statement": "import",
    "arrow_function": "function",
    "method_declaration": "method",
    "interface_declaration": "interface",
    "type_alias_declaration": "type_alias",
    "struct_item": "struct",
    "enum_item": "enum",
    "trait_item": "trait",
    "impl_item": "impl",
}

EDGE_TYPES = {"calls", "imports", "extends", "implements", "defines", "references"}


class CodeGraphEngine:
    """代码图引擎"""

    def __init__(self):
        self._db: Optional["aiosqlite.Connection"] = None
        self._db_path: Optional[str] = None
        self._parsers: Dict[str, Parser] = {}
        self._languages: Dict[str, Language] = {}
        self._initialized = False
        if HAS_TREE_SITTER:
            self._load_languages()

    def _load_languages(self) -> None:
        try:
            from tree_sitter_python import language as python_language
            self._languages["python"] = Language(python_language())
            self._parsers["python"] = Parser(self._languages["python"])
        except ImportError:
            pass
        try:
            from tree_sitter_javascript import language as js_language
            self._languages["javascript"] = Language(js_language())
            self._languages["typescript"] = Language(js_language())
            self._parsers["javascript"] = Parser(self._languages["javascript"])
            self._parsers["typescript"] = Parser(self._languages["typescript"])
        except ImportError:
            pass
        try:
            from tree_sitter_java import language as java_language
            self._languages["java"] = Language(java_language())
            self._parsers["java"] = Parser(self._languages["java"])
        except ImportError:
            pass
        try:
            from tree_sitter_cpp import language as cpp_language
            self._languages["cpp"] = Language(cpp_language())
            self._languages["c"] = Language(cpp_language())
            self._parsers["cpp"] = Parser(self._languages["cpp"])
            self._parsers["c"] = Parser(self._languages["c"])
        except ImportError:
            pass
        try:
            from tree_sitter_go import language as go_language
            self._languages["go"] = Language(go_language())
            self._parsers["go"] = Parser(self._languages["go"])
        except ImportError:
            pass
        try:
            from tree_sitter_rust import language as rust_language
            self._languages["rust"] = Language(rust_language())
            self._parsers["rust"] = Parser(self._languages["rust"])
        except ImportError:
            pass
        try:
            from tree_sitter_php import language as php_language
            self._languages["php"] = Language(php_language())
            self._parsers["php"] = Parser(self._languages["php"])
        except ImportError:
            pass
        if self._parsers:
            logger.info(f"CodeGraphEngine: 加载 {len(self._parsers)} 个语言解析器")

    async def init(self, project_path: str) -> None:
        if not HAS_AIOSQLITE:
            raise ImportError("aiosqlite 未安装: pip install aiosqlite")
        project_path_str = str(project_path)
        db_dir = Path(project_path_str) / ".codegraph"
        db_dir.mkdir(parents=True, exist_ok=True)
        self._db_path = str(db_dir / "codegraph.db")
        self._db = await aiosqlite.connect(self._db_path)
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.execute("PRAGMA synchronous=NORMAL")
        await self._db.execute("PRAGMA foreign_keys=ON")
        await self._create_schema()
        self._initialized = True
        logger.info(f"CodeGraphEngine: 数据库初始化完成 {self._db_path}")

    async def _create_schema(self) -> None:
        if self._db is None:
            return
        await self._db.executescript("""
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                path TEXT UNIQUE NOT NULL,
                hash TEXT NOT NULL,
                language TEXT,
                modified_at REAL,
                indexed_at REAL
            );
            CREATE TABLE IF NOT EXISTS nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                file_id INTEGER NOT NULL,
                symbol_name TEXT,
                symbol_type TEXT NOT NULL,
                start_line INTEGER,
                end_line INTEGER,
                start_col INTEGER,
                end_col INTEGER,
                source_code TEXT,
                metadata TEXT,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_node_id INTEGER NOT NULL,
                target_node_id INTEGER NOT NULL,
                edge_type TEXT NOT NULL CHECK(edge_type IN ('calls','imports','extends','implements','defines','references')),
                FOREIGN KEY (source_node_id) REFERENCES nodes(id) ON DELETE CASCADE,
                FOREIGN KEY (target_node_id) REFERENCES nodes(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS unresolved_refs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source_node_id INTEGER NOT NULL,
                ref_name TEXT NOT NULL,
                ref_type TEXT,
                file_id INTEGER,
                FOREIGN KEY (source_node_id) REFERENCES nodes(id) ON DELETE CASCADE,
                FOREIGN KEY (file_id) REFERENCES files(id) ON DELETE CASCADE
            );
            CREATE VIRTUAL TABLE IF NOT EXISTS nodes_fts USING fts5(
                symbol_name, source_code,
                content='nodes', content_rowid='id'
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(symbol_name);
            CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(symbol_type);
            CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source_node_id);
            CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target_node_id);
            CREATE INDEX IF NOT EXISTS idx_files_path ON files(path);
        """)
        await self._db.commit()
        await self._sync_fts()

    async def _sync_fts(self) -> None:
        if self._db is None:
            return
        await self._db.execute("""
            INSERT OR IGNORE INTO nodes_fts(rowid, symbol_name, source_code)
            SELECT id, symbol_name, source_code FROM nodes
            WHERE id NOT IN (SELECT rowid FROM nodes_fts)
        """)
        await self._db.commit()

    async def close(self) -> None:
        if self._db:
            await self._db.close()
            self._db = None
            self._initialized = False
            logger.info("CodeGraphEngine: 数据库连接已关闭")

    async def clear(self) -> None:
        if self._db is None:
            return
        await self._db.execute("DELETE FROM nodes_fts")
        await self._db.execute("DELETE FROM unresolved_refs")
        await self._db.execute("DELETE FROM edges")
        await self._db.execute("DELETE FROM nodes")
        await self._db.execute("DELETE FROM files")
        await self._db.commit()
        logger.info("CodeGraphEngine: 数据库已清空")

    async def delete_file(self, file_path: str) -> None:
        if self._db is None:
            return
        file_path_str = str(file_path)
        cursor = await self._db.execute("SELECT id FROM files WHERE path = ?", (file_path_str,))
        row = await cursor.fetchone()
        if row is None:
            return
        file_id = row[0]
        await self._db.execute("DELETE FROM nodes_fts WHERE rowid IN (SELECT id FROM nodes WHERE file_id = ?)", (file_id,))
        await self._db.execute("DELETE FROM unresolved_refs WHERE file_id = ?", (file_id,))
        await self._db.execute("DELETE FROM edges WHERE source_node_id IN (SELECT id FROM nodes WHERE file_id = ?) OR target_node_id IN (SELECT id FROM nodes WHERE file_id = ?)", (file_id, file_id))
        await self._db.execute("DELETE FROM nodes WHERE file_id = ?", (file_id,))
        await self._db.execute("DELETE FROM files WHERE id = ?", (file_id,))
        await self._db.commit()

    async def index_file(self, file_path: str, source_code: str, language: str) -> Dict[str, Any]:
        if self._db is None:
            raise RuntimeError("数据库未初始化，请先调用 init()")
        file_path_str = str(file_path)
        if language not in self._parsers:
            return {"status": "skipped", "reason": f"不支持的语言: {language}"}
        content_hash = hashlib.sha256(source_code.encode()).hexdigest()
        cursor = await self._db.execute("SELECT id, hash FROM files WHERE path = ?", (file_path_str,))
        existing = await cursor.fetchone()
        if existing and existing[1] == content_hash:
            return {"status": "up_to_date", "file_id": existing[0]}
        if existing:
            await self.delete_file(file_path_str)
        stat = os.stat(file_path_str)
        modified_at = stat.st_mtime
        cursor = await self._db.execute(
            "INSERT INTO files (path, hash, language, modified_at, indexed_at) VALUES (?, ?, ?, ?, ?)",
            (file_path_str, content_hash, language, modified_at, datetime.now().timestamp())
        )
        file_id = cursor.lastrowid
        nodes, edges, unresolved = self._extract_symbols(source_code, language)
        node_id_map: Dict[int, int] = {}
        for node_data in nodes:
            cursor = await self._db.execute(
                "INSERT INTO nodes (file_id, symbol_name, symbol_type, start_line, end_line, start_col, end_col, source_code, metadata) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (file_id, node_data["name"], node_data["type"], node_data["start_line"], node_data["end_line"], node_data["start_col"], node_data["end_col"], node_data["source"], node_data.get("metadata"))
            )
            node_id_map[node_data["internal_id"]] = cursor.lastrowid
        for edge_data in edges:
            src_id = node_id_map.get(edge_data["source"])
            tgt_id = node_id_map.get(edge_data["target"])
            if src_id and tgt_id:
                await self._db.execute(
                    "INSERT OR IGNORE INTO edges (source_node_id, target_node_id, edge_type) VALUES (?, ?, ?)",
                    (src_id, tgt_id, edge_data["type"])
                )
        for ref in unresolved:
            src_id = node_id_map.get(ref["source"])
            if src_id:
                await self._db.execute(
                    "INSERT INTO unresolved_refs (source_node_id, ref_name, ref_type, file_id) VALUES (?, ?, ?, ?)",
                    (src_id, ref["name"], ref["type"], file_id)
                )
        await self._db.execute(
            "UPDATE files SET indexed_at = ? WHERE id = ?",
            (datetime.now().timestamp(), file_id)
        )
        await self._db.commit()
        await self._sync_fts()
        return {"status": "indexed", "file_id": file_id, "nodes": len(nodes), "edges": len(edges)}

    def _extract_symbols(self, source_code: str, language: str) -> Tuple[List[Dict], List[Dict], List[Dict]]:
        parser = self._parsers.get(language)
        if parser is None:
            return [], [], []
        tree = parser.parse(source_code.encode("utf-8"))
        root = tree.root_node
        all_symbols: List[Dict[str, Any]] = []
        all_edges: List[Dict[str, str]] = []
        all_unresolved: List[Dict[str, str]] = []
        global_defs: List[Dict] = []
        self._traverse_node(root, source_code, all_symbols, all_edges, all_unresolved, global_defs, set())
        return all_symbols, all_edges, all_unresolved

    def _traverse_node(self, node, source_code: str, symbols: List[Dict], edges: List[Dict], unresolved: List[Dict], defs: List[Dict], seen_symbols: Set[str]) -> Optional[str]:
        node_type = node.type
        symbol_type = SYMBOL_TYPES.get(node_type)
        symbol_name = None
        if symbol_type:
            symbol_name = self._get_symbol_name(node)
            if symbol_name:
                key = f"{symbol_type}:{symbol_name}"
                if key not in seen_symbols:
                    seen_symbols.add(key)
                    loc = self._get_location(node)
                    try:
                        src = source_code[node.start_byte:node.end_byte]
                    except Exception:
                        src = ""
                    meta: Dict[str, Any] = {}
                    if symbol_type in ("class", "interface"):
                        bases = self._get_base_classes(node)
                        if bases:
                            meta["bases"] = bases
                    symbols.append({
                        "internal_id": node.id,
                        "name": symbol_name,
                        "type": symbol_type,
                        "start_line": loc["start_line"],
                        "end_line": loc["end_line"],
                        "start_col": loc["start_col"],
                        "end_col": loc["end_col"],
                        "source": src,
                        "metadata": str(meta) if meta else None,
                    })
                    defs.append({"id": node.id, "name": symbol_name, "type": symbol_type})
        self._extract_calls(node, source_code, edges, unresolved, node.id, symbol_name)
        self._extract_imports(node, edges, node.id)
        self._extract_extends(node, edges, node.id)
        for child in node.children:
            self._traverse_node(child, source_code, symbols, edges, unresolved, defs, seen_symbols)

    def _get_symbol_name(self, node) -> Optional[str]:
        type_map = {
            "identifier", "name", "property_identifier",
            "type_identifier", "field_identifier",
        }
        for child in node.children:
            if child.type in type_map:
                try:
                    name = child.text.decode("utf-8", errors="replace")
                    if name:
                        return name
                except Exception:
                    pass
        return None

    def _get_location(self, node) -> Dict[str, int]:
        return {
            "start_line": node.start_point[0] + 1,
            "end_line": node.end_point[0] + 1,
            "start_col": node.start_point[1],
            "end_col": node.end_point[1],
        }

    def _get_base_classes(self, node) -> List[str]:
        bases: List[str] = []
        for child in node.children:
            if child.type in ("argument_list", "superclasses", "base_type_clause"):
                for sub in child.children:
                    if sub.type in ("identifier", "type_identifier"):
                        try:
                            name = sub.text.decode("utf-8", errors="replace")
                            if name:
                                bases.append(name)
                        except Exception:
                            pass
        return bases

    def _extract_calls(self, node, source_code: str, edges: List[Dict], unresolved: List[Dict], parent_id: int, current_symbol: Optional[str]) -> None:
        if node.type == "call":
            func_name = None
            name_node = node.child_by_field_name("function") or node.child_by_field_name("name")
            if name_node is None and node.children:
                name_node = node.children[0]
            if name_node is not None:
                if name_node.type in ("identifier", "member_expression", "field_access"):
                    try:
                        text = name_node.text.decode("utf-8", errors="replace")
                        func_name = text.split(".")[-1] if "." in text else text
                    except Exception:
                        pass
                elif name_node.type == "identifier":
                    try:
                        func_name = name_node.text.decode("utf-8", errors="replace")
                    except Exception:
                        pass
            if func_name:
                if current_symbol:
                    edges.append({"source": parent_id, "target_name": func_name, "type": "calls"})
                else:
                    unresolved.append({"source": parent_id, "name": func_name, "type": "calls"})

    def _extract_imports(self, node, edges: List[Dict], parent_id: int) -> None:
        if node.type in ("import_statement", "import_from_statement", "import_declaration"):
            for child in node.children:
                if child.type in ("dotted_name", "module", "import_specifier", "scoped_identifier"):
                    try:
                        module_name = child.text.decode("utf-8", errors="replace")
                        if module_name:
                            alias_node = child.child_by_field_name("alias")
                            if alias_node:
                                try:
                                    module_name = alias_node.text.decode("utf-8", errors="replace")
                                except Exception:
                                    pass
                            edges.append({"source": parent_id, "target_name": module_name, "type": "imports"})
                    except Exception:
                        pass

    def _extract_extends(self, node, edges: List[Dict], parent_id: int) -> None:
        if node.type in ("class_definition", "class_declaration"):
            for child in node.children:
                if child.type in ("argument_list", "superclasses", "base_type_clause"):
                    for sub in child.children:
                        if sub.type in ("identifier", "type_identifier"):
                            try:
                                base = sub.text.decode("utf-8", errors="replace")
                                if base:
                                    edges.append({"source": parent_id, "target_name": base, "type": "extends"})
                            except Exception:
                                pass
                elif child.type == "implements":
                    for sub in child.children:
                        if sub.type in ("type_list", "type_identifier", "identifier"):
                            try:
                                iface = sub.text.decode("utf-8", errors="replace")
                                if iface:
                                    edges.append({"source": parent_id, "target_name": iface, "type": "implements"})
                            except Exception:
                                pass

    async def search(self, query: str, limit: int = 20) -> List[Dict[str, Any]]:
        if self._db is None:
            return []
        safe_query = query.replace("'", "''").replace('"', '""')
        cursor = await self._db.execute(f"""
            SELECT n.id, n.symbol_name, n.symbol_type, n.start_line, n.end_line, n.source_code, f.path
            FROM nodes_fts fts
            JOIN nodes n ON n.id = fts.rowid
            JOIN files f ON f.id = n.file_id
            WHERE nodes_fts MATCH ?
            LIMIT ?
        """, (f'"{safe_query}"*', limit))
        rows = await cursor.fetchall()
        return [
            {
                "id": r[0], "name": r[1], "type": r[2],
                "start_line": r[3], "end_line": r[4],
                "source_code": r[5], "file_path": r[6],
            }
            for r in rows
        ]

    async def get_node(self, symbol_name: str) -> Optional[Dict[str, Any]]:
        if self._db is None:
            return None
        cursor = await self._db.execute("""
            SELECT n.id, n.symbol_name, n.symbol_type, n.start_line, n.end_line,
                   n.start_col, n.end_col, n.source_code, n.metadata, f.path
            FROM nodes n
            JOIN files f ON f.id = n.file_id
            WHERE n.symbol_name = ?
            LIMIT 1
        """, (symbol_name,))
        row = await cursor.fetchone()
        if row is None:
            return None
        return {
            "id": row[0], "name": row[1], "type": row[2],
            "start_line": row[3], "end_line": row[4],
            "start_col": row[5], "end_col": row[6],
            "source_code": row[7], "metadata": row[8],
            "file_path": row[9],
        }

    async def get_nodes_by_file(self, file_path: str) -> List[Dict[str, Any]]:
        if self._db is None:
            return []
        file_path_str = str(file_path)
        cursor = await self._db.execute("""
            SELECT n.id, n.symbol_name, n.symbol_type, n.start_line, n.end_line,
                   n.start_col, n.end_col, n.source_code, n.metadata
            FROM nodes n
            JOIN files f ON f.id = n.file_id
            WHERE f.path = ?
            ORDER BY n.start_line
        """, (file_path_str,))
        rows = await cursor.fetchall()
        return [
            {
                "id": r[0], "name": r[1], "type": r[2],
                "start_line": r[3], "end_line": r[4],
                "start_col": r[5], "end_col": r[6],
                "source_code": r[7], "metadata": r[8],
            }
            for r in rows
        ]

    async def get_edges(self, node_id: int, edge_type: Optional[str] = None) -> List[Dict[str, Any]]:
        if self._db is None:
            return []
        if edge_type and edge_type not in EDGE_TYPES:
            return []
        if edge_type:
            cursor = await self._db.execute("""
                SELECT e.id, e.source_node_id, e.target_node_id, e.edge_type,
                       sn.symbol_name, tn.symbol_name
                FROM edges e
                JOIN nodes sn ON sn.id = e.source_node_id
                JOIN nodes tn ON tn.id = e.target_node_id
                WHERE e.source_node_id = ? AND e.edge_type = ?
            """, (node_id, edge_type))
        else:
            cursor = await self._db.execute("""
                SELECT e.id, e.source_node_id, e.target_node_id, e.edge_type,
                       sn.symbol_name, tn.symbol_name
                FROM edges e
                JOIN nodes sn ON sn.id = e.source_node_id
                JOIN nodes tn ON tn.id = e.target_node_id
                WHERE e.source_node_id = ?
            """, (node_id,))
        rows = await cursor.fetchall()
        return [
            {
                "id": r[0], "source_node_id": r[1], "target_node_id": r[2],
                "edge_type": r[3], "source_name": r[4], "target_name": r[5],
            }
            for r in rows
        ]

    async def get_stats(self) -> Dict[str, Any]:
        if self._db is None:
            return {}
        files_cursor = await self._db.execute("SELECT COUNT(*) FROM files")
        nodes_cursor = await self._db.execute("SELECT COUNT(*) FROM nodes")
        edges_cursor = await self._db.execute("SELECT COUNT(*) FROM edges")
        unresolved_cursor = await self._db.execute("SELECT COUNT(*) FROM unresolved_refs")
        return {
            "files": (await files_cursor.fetchone())[0],
            "nodes": (await nodes_cursor.fetchone())[0],
            "edges": (await edges_cursor.fetchone())[0],
            "unresolved_refs": (await unresolved_cursor.fetchone())[0],
        }
