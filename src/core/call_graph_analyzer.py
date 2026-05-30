from typing import List, Dict, Optional, Set
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class CallGraphNode:
    symbol_name: str
    file_path: str
    start_line: int
    end_line: int
    symbol_type: str

    def __hash__(self):
        return hash((self.symbol_name, self.file_path, self.start_line))

    def __eq__(self, other):
        if not isinstance(other, CallGraphNode):
            return False
        return (self.symbol_name == other.symbol_name and
                self.file_path == other.file_path and
                self.start_line == other.start_line)


@dataclass
class CallPath:
    path: List[CallGraphNode]
    depth: int


class CallGraphAnalyzer:

    def __init__(self, code_graph_engine):
        self.engine = code_graph_engine

    def get_callers(self, symbol_name: str, max_depth: int = 3) -> List[CallPath]:
        callers = []
        target_node = self._find_node(symbol_name)
        if target_node is None:
            return callers

        visited: Set[int] = set()
        queue: List[tuple] = [(target_node["id"], [self._to_node(target_node)], 0)]

        while queue:
            current_id, current_path, current_depth = queue.pop(0)
            if current_depth >= max_depth:
                continue

            incoming = self._get_incoming_edges(current_id)
            for edge in incoming:
                source_id = edge["source_node_id"]
                if source_id in visited:
                    continue
                visited.add(source_id)

                source_node_info = self._get_node_by_id(source_id)
                if source_node_info is None:
                    continue

                source_node = self._to_node(source_node_info)
                new_path = [source_node] + current_path
                callers.append(CallPath(path=new_path, depth=current_depth + 1))

                if current_depth + 1 < max_depth:
                    queue.append((source_id, new_path, current_depth + 1))

        return callers

    def get_callees(self, symbol_name: str, max_depth: int = 3) -> List[CallPath]:
        callees = []
        start_node = self._find_node(symbol_name)
        if start_node is None:
            return callees

        visited: Set[int] = set()
        queue: List[tuple] = [(start_node["id"], [self._to_node(start_node)], 0)]

        while queue:
            current_id, current_path, current_depth = queue.pop(0)
            if current_depth >= max_depth:
                continue

            edges = self.engine.get_edges(current_id, edge_type="calls")
            for edge in edges:
                target_id = edge["target_node_id"]
                if target_id in visited:
                    continue
                visited.add(target_id)

                target_node_info = self._get_node_by_id(target_id)
                if target_node_info is None:
                    continue

                target_node = self._to_node(target_node_info)
                new_path = current_path + [target_node]
                callees.append(CallPath(path=new_path, depth=current_depth + 1))

                if current_depth + 1 < max_depth:
                    queue.append((target_id, new_path, current_depth + 1))

        return callees

    def get_call_chain(self, from_symbol: str, to_symbol: str, max_depth: int = 5) -> Optional[CallPath]:
        start_node = self._find_node(from_symbol)
        target_node = self._find_node(to_symbol)
        if start_node is None or target_node is None:
            return None

        target_id = target_node["id"]
        visited: Set[int] = set()
        queue: List[tuple] = [(start_node["id"], [self._to_node(start_node)], 0)]

        while queue:
            current_id, current_path, current_depth = queue.pop(0)
            if current_depth > max_depth:
                continue

            if current_id == target_id:
                return CallPath(path=current_path, depth=len(current_path) - 1)

            if current_id in visited:
                continue
            visited.add(current_id)

            edges = self.engine.get_edges(current_id, edge_type="calls")
            for edge in edges:
                next_id = edge["target_node_id"]
                if next_id not in visited:
                    next_node_info = self._get_node_by_id(next_id)
                    if next_node_info:
                        queue.append((next_id, current_path + [self._to_node(next_node_info)], current_depth + 1))

        return None

    def get_call_chain_from_entry(self, symbol_name: str, max_depth: int = 3) -> List[CallPath]:
        entry_points = self._find_entry_points()
        results = []
        for entry in entry_points:
            chain = self.get_call_chain(entry["name"], symbol_name, max_depth)
            if chain:
                results.append(chain)
        return results

    def _find_node(self, symbol_name: str) -> Optional[Dict]:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                future = asyncio.ensure_future(self.engine.get_node(symbol_name))
                result = asyncio.get_event_loop().run_until_complete(future)
                return result
            else:
                return loop.run_until_complete(self.engine.get_node(symbol_name))
        except RuntimeError:
            return None

    def _get_node_by_id(self, node_id: int) -> Optional[Dict]:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            async def _fetch():
                if self.engine._db is None:
                    return None
                cursor = await self.engine._db.execute("""
                    SELECT n.id, n.symbol_name, n.symbol_type, n.start_line, n.end_line,
                           n.start_col, n.end_col, n.source_code, n.metadata, f.path
                    FROM nodes n
                    JOIN files f ON f.id = n.file_id
                    WHERE n.id = ?
                    LIMIT 1
                """, (node_id,))
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
            if loop.is_running():
                return asyncio.get_event_loop().run_until_complete(_fetch())
            else:
                return loop.run_until_complete(_fetch())
        except RuntimeError:
            return None

    def _get_incoming_edges(self, node_id: int) -> List[Dict]:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            async def _fetch():
                if self.engine._db is None:
                    return []
                cursor = await self.engine._db.execute("""
                    SELECT e.id, e.source_node_id, e.target_node_id, e.edge_type,
                           sn.symbol_name, tn.symbol_name
                    FROM edges e
                    JOIN nodes sn ON sn.id = e.source_node_id
                    JOIN nodes tn ON tn.id = e.target_node_id
                    WHERE e.target_node_id = ? AND e.edge_type = 'calls'
                """, (node_id,))
                rows = await cursor.fetchall()
                return [
                    {
                        "id": r[0], "source_node_id": r[1], "target_node_id": r[2],
                        "edge_type": r[3], "source_name": r[4], "target_name": r[5],
                    }
                    for r in rows
                ]
            if loop.is_running():
                return asyncio.get_event_loop().run_until_complete(_fetch())
            else:
                return loop.run_until_complete(_fetch())
        except RuntimeError:
            return []

    def _find_entry_points(self) -> List[Dict]:
        import asyncio
        entry_names = ["main", "run", "start", "handler", "index"]
        results = []
        for name in entry_names:
            node = self._find_node(name)
            if node:
                results.append(node)
        return results

    def _to_node(self, data: Dict) -> CallGraphNode:
        return CallGraphNode(
            symbol_name=data.get("name", ""),
            file_path=str(data.get("file_path", "")),
            start_line=data.get("start_line", 0),
            end_line=data.get("end_line", 0),
            symbol_type=data.get("type", ""),
        )
