import re
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass

SAFE_PATTERNS = {
    r'Wrappers\.query\(': 'MyBatis-Plus预编译语句，安全',
    r'Wrappers\.lambdaQuery\(': 'MyBatis-Plus预编译语句，安全',
    r'#\{': 'MyBatis参数绑定，安全'
}

UNSAFE_PATTERNS = {
    r'\$\{': 'MyBatis字符串拼接，不安全'
}


def match_framework_patterns(code_content: str) -> Dict[str, List[Tuple[str, str]]]:
    result = {
        'safe': [],
        'unsafe': []
    }

    for pattern, description in SAFE_PATTERNS.items():
        matches = re.finditer(pattern, code_content)
        for match in matches:
            result['safe'].append((pattern, description))

    for pattern, description in UNSAFE_PATTERNS.items():
        matches = re.finditer(pattern, code_content)
        for match in matches:
            result['unsafe'].append((pattern, description))

    return result


def check_safe_pattern(code_content: str) -> bool:
    result = match_framework_patterns(code_content)
    return len(result['safe']) > 0


def check_unsafe_pattern(code_content: str) -> bool:
    result = match_framework_patterns(code_content)
    return len(result['unsafe']) > 0


@dataclass
class RouteInfo:
    url_pattern: str
    handler_name: str
    handler_file: str
    handler_line: int
    http_methods: List[str]
    framework: str


class FrameworkRouteRecognizer:

    def recognize(self, file_path: str, source_code: str, language: str) -> List[RouteInfo]:
        routes = []
        file_path_str = str(file_path)

        if language == 'python':
            routes.extend(self._recognize_django(file_path_str, source_code))
            routes.extend(self._recognize_flask(file_path_str, source_code))
            routes.extend(self._recognize_fastapi(file_path_str, source_code))
        elif language == 'javascript' or language == 'typescript':
            routes.extend(self._recognize_express(file_path_str, source_code))
        elif language == 'java':
            routes.extend(self._recognize_spring(file_path_str, source_code))

        return routes

    def _recognize_django(self, file_path: str, source_code: str) -> List[RouteInfo]:
        routes = []
        patterns = [
            r"path\(['\"]([^'\"]+)['\"],\s*(\w+(?:\.\w+)*)",
            r"re_path\([r]?['\"]([^'\"]+)['\"],\s*(\w+(?:\.\w+)*)",
            r"url\(['\"]([^'\"]+)['\"],\s*(\w+(?:\.\w+)*)",
        ]
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern in patterns:
                match = re.search(pattern, line)
                if match:
                    routes.append(RouteInfo(
                        url_pattern=match.group(1),
                        handler_name=match.group(2),
                        handler_file=str(file_path),
                        handler_line=i,
                        http_methods=['GET', 'POST'],
                        framework='django'
                    ))
        return routes

    def _recognize_flask(self, file_path: str, source_code: str) -> List[RouteInfo]:
        routes = []
        pattern = r"@app\.route\(['\"]([^'\"]+)['\"](?:,\s*methods=\[([^\]]+)\])?\)"
        lines = source_code.splitlines()
        for i, line in enumerate(lines, 1):
            match = re.search(pattern, line)
            if match:
                methods_str = match.group(2) or 'GET'
                methods = [m.strip().strip("'\"").upper() for m in methods_str.split(',')]
                handler_name = self._extract_next_def(lines, i)
                routes.append(RouteInfo(
                    url_pattern=match.group(1),
                    handler_name=handler_name,
                    handler_file=str(file_path),
                    handler_line=i,
                    http_methods=methods,
                    framework='flask'
                ))
        return routes

    def _recognize_fastapi(self, file_path: str, source_code: str) -> List[RouteInfo]:
        routes = []
        pattern = r"@(\w+)\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"]\)"
        lines = source_code.splitlines()
        for i, line in enumerate(lines, 1):
            match = re.search(pattern, line)
            if match:
                handler_name = self._extract_next_def(lines, i)
                routes.append(RouteInfo(
                    url_pattern=match.group(3),
                    handler_name=handler_name,
                    handler_file=str(file_path),
                    handler_line=i,
                    http_methods=[match.group(2).upper()],
                    framework='fastapi'
                ))
        return routes

    def _recognize_express(self, file_path: str, source_code: str) -> List[RouteInfo]:
        routes = []
        pattern = r"(?:app|router)\.(get|post|put|delete|patch)\(['\"]([^'\"]+)['\"](?:,\s*(\w+))?"
        for i, line in enumerate(source_code.splitlines(), 1):
            match = re.search(pattern, line)
            if match:
                routes.append(RouteInfo(
                    url_pattern=match.group(2),
                    handler_name=match.group(3) or '',
                    handler_file=str(file_path),
                    handler_line=i,
                    http_methods=[match.group(1).upper()],
                    framework='express'
                ))
        return routes

    def _recognize_spring(self, file_path: str, source_code: str) -> List[RouteInfo]:
        routes = []
        patterns = [
            (r"@GetMapping\(['\"]([^'\"]+)['\"]\)", ['GET']),
            (r"@PostMapping\(['\"]([^'\"]+)['\"]\)", ['POST']),
            (r"@PutMapping\(['\"]([^'\"]+)['\"]\)", ['PUT']),
            (r"@DeleteMapping\(['\"]([^'\"]+)['\"]\)", ['DELETE']),
            (r"@PatchMapping\(['\"]([^'\"]+)['\"]\)", ['PATCH']),
            (r"@RequestMapping\(.*?value\s*=\s*['\"]([^'\"]+)['\"]", ['GET']),
        ]
        for i, line in enumerate(source_code.splitlines(), 1):
            for pattern, methods in patterns:
                match = re.search(pattern, line)
                if match:
                    routes.append(RouteInfo(
                        url_pattern=match.group(1),
                        handler_name='',
                        handler_file=str(file_path),
                        handler_line=i,
                        http_methods=methods,
                        framework='spring'
                    ))
        return routes

    def _extract_next_def(self, lines: List[str], current_line: int, max_lookahead: int = 5) -> str:
        for j in range(current_line, min(current_line + max_lookahead, len(lines))):
            m = re.search(r'def\s+(\w+)', lines[j])
            if m:
                return m.group(1)
        return ''


def integrate_routes_to_graph(code_graph_engine, file_path: str, source_code: str, language: str):
    recognizer = FrameworkRouteRecognizer()
    routes = recognizer.recognize(file_path, source_code, language)

    if not routes:
        return []

    import asyncio
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        return routes

    async def _integrate():
        results = []
        for route in routes:
            try:
                if code_graph_engine._db is None:
                    continue

                file_path_str = str(file_path)
                cursor = await code_graph_engine._db.execute(
                    "SELECT id FROM files WHERE path = ?", (file_path_str,)
                )
                file_row = await cursor.fetchone()
                if file_row is None:
                    continue
                file_id = file_row[0]

                route_symbol = f"route:{route.url_pattern}"

                await code_graph_engine._db.execute(
                    "INSERT OR IGNORE INTO nodes (file_id, symbol_name, symbol_type, start_line, end_line, source_code) VALUES (?, ?, ?, ?, ?, ?)",
                    (file_id, route_symbol, "route", route.handler_line, route.handler_line, f"{route.framework} {route.http_methods}")
                )
                await code_graph_engine._db.commit()

                if route.handler_name:
                    handler_cursor = await code_graph_engine._db.execute(
                        "SELECT id FROM nodes WHERE file_id = ? AND symbol_name = ? AND symbol_type IN ('function', 'method')",
                        (file_id, route.handler_name)
                    )
                    handler_row = await handler_cursor.fetchone()
                    if handler_row:
                        handler_id = handler_row[0]
                        route_cursor = await code_graph_engine._db.execute(
                            "SELECT id FROM nodes WHERE file_id = ? AND symbol_name = ?",
                            (file_id, route_symbol)
                        )
                        route_row = await route_cursor.fetchone()
                        if route_row:
                            route_id = route_row[0]
                            await code_graph_engine._db.execute(
                                "INSERT OR IGNORE INTO edges (source_node_id, target_node_id, edge_type) VALUES (?, ?, ?)",
                                (route_id, handler_id, "defines")
                            )
                            await code_graph_engine._db.commit()

                results.append(route)
            except Exception:
                pass
        return results

    try:
        if loop.is_running():
            asyncio.ensure_future(_integrate())
        else:
            loop.run_until_complete(_integrate())
    except Exception:
        pass

    return routes
