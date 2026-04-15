import re
import time
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from collections import OrderedDict
from datetime import datetime


@dataclass
class Entity:
    type: str
    name: str
    value: str
    first_mentioned: float
    last_mentioned: float
    mention_count: int


@dataclass
class ConversationTurn:
    timestamp: float
    user_input: str
    entities_extracted: List[str]
    intent: Optional[str]
    response_summary: str


class ContextMemoryManager:
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.max_entities = self.config.get("max_entities", 100)
        self.max_history = self.config.get("max_history", 50)
        self._entities: OrderedDict[str, Entity] = OrderedDict()
        self._conversation_history: List[ConversationTurn] = []
        self._current_intent: Optional[str] = None
        self._pronoun_map: Dict[str, str] = {
            "it": "entity",
            "this": "entity",
            "that": "entity",
            "these": "entity",
            "them": "entity",
            "the file": "file",
            "the function": "function",
            "this function": "function",
            "that function": "function",
            "the class": "class",
            "this class": "class",
            "that class": "class",
            "these files": "file",
            "those files": "file",
            "them": "entity"
        }
        self._type_keywords: Dict[str, List[str]] = {
            "file": ["file", "path", ".py", ".js", ".ts", ".java", ".cpp", ".c", ".h", ".txt", "module", "script"],
            "function": ["function", "func", "method", "def", "()", "procedure"],
            "class": ["class", "object", "struct", "interface", "type"],
            "variable": ["variable", "var", "const", "let", "value", "parameter", "arg"]
        }
        self._intent_patterns: Dict[str, List[str]] = {
            "scan": ["scan", "check", "review", "inspect", "examine"],
            "analyze": ["analyze", "parse", "examine", "investigate", "study"],
            "modify": ["modify", "change", "update", "edit", "alter", "fix"],
            "create": ["create", "add", "new", "generate", "make"],
            "delete": ["delete", "remove", "clear", "drop"],
            "search": ["search", "find", "look", "query", "grep"],
            "execute": ["run", "execute", "start", "launch", "call"],
            "explain": ["explain", "describe", "show", "tell", "what", "how"],
            "compare": ["compare", "diff", "versus", "vs"],
            "refactor": ["refactor", "restructure", "reorganize", "optimize"]
        }

    def extract_entities(self, text: str) -> List[Entity]:
        print(f"[DEBUG] 开始提取实体: {text[:50]}...")
        entities: List[Entity] = []
        current_time = time.time()

        file_patterns = [
            r'\b[\w/\\]+\.py\b',
            r'\b[\w/\\]+\.js\b',
            r'\b[\w/\\]+\.ts\b',
            r'\b[\w/\\]+\.java\b',
            r'\b[\w/\\]+\.cpp\b',
            r'\b[\w/\\]+\.c\b',
            r'\b[\w/\\]+\.h\b',
            r'\b[\w/\\]+\.txt\b',
            r'\b[\w/\\]+\.md\b',
            r'\b[\w/\\]+\.json\b',
            r'\b[\w/\\]+\.yaml\b',
            r'\b[\w/\\]+\.yml\b',
            r'\b[\w/\\]+\.xml\b',
            r'\b[\w/\\]+\.html\b',
            r'\b[\w/\\]+\.css\b',
            r'\b[\w./\\_-]+\b(?:file|path|module|script|source)\b',
            r'(?:src|lib|bin|obj|build|dist|test|tests|config|doc|docs)/[\w/\\.-]+',
        ]

        for pattern in file_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                file_path = match.group()
                if self._is_likely_file_path(file_path):
                    entity_key = f"file:{file_path}"
                    if entity_key in self._entities:
                        entity = self._entities[entity_key]
                        entity.last_mentioned = current_time
                        entity.mention_count += 1
                        self._entities.move_to_end(entity_key)
                    else:
                        entity = Entity(
                            type="file",
                            name=file_path,
                            value=file_path,
                            first_mentioned=current_time,
                            last_mentioned=current_time,
                            mention_count=1
                        )
                        self._entities[entity_key] = entity
                        self._enforce_entity_limit()
                    if entity not in entities:
                        entities.append(entity)

        function_patterns = [
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(',
            r'(?:def|function|func|method)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'(?:call|invoke|execute)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
            r'([a-zA-Z_][a-zA-Z0-9_]*)\s*(?:\(\))',
        ]

        for pattern in function_patterns:
            for match in re.finditer(pattern, text, re.IGNORECASE):
                func_name = match.group(1)
                if not self._is_common_keyword(func_name) and len(func_name) > 1:
                    entity_key = f"function:{func_name}"
                    if entity_key in self._entities:
                        entity = self._entities[entity_key]
                        entity.last_mentioned = current_time
                        entity.mention_count += 1
                        self._entities.move_to_end(entity_key)
                    else:
                        entity = Entity(
                            type="function",
                            name=func_name,
                            value=func_name,
                            first_mentioned=current_time,
                            last_mentioned=current_time,
                            mention_count=1
                        )
                        self._entities[entity_key] = entity
                        self._enforce_entity_limit()
                    if entity not in entities:
                        entities.append(entity)

        class_patterns = [
            r'\bclass\s+([A-Z][a-zA-Z0-9_]*)',
            r'(?:type|struct|interface)\s+([A-Z][a-zA-Z0-9_]*)',
            r'([A-Z][a-zA-Z0-9_]*)\s+(?:class|object|instance)',
        ]

        for pattern in class_patterns:
            for match in re.finditer(pattern, text):
                class_name = match.group(1)
                entity_key = f"class:{class_name}"
                if entity_key in self._entities:
                    entity = self._entities[entity_key]
                    entity.last_mentioned = current_time
                    entity.mention_count += 1
                    self._entities.move_to_end(entity_key)
                else:
                    entity = Entity(
                        type="class",
                        name=class_name,
                        value=class_name,
                        first_mentioned=current_time,
                        last_mentioned=current_time,
                        mention_count=1
                    )
                    self._entities[entity_key] = entity
                    self._enforce_entity_limit()
                if entity not in entities:
                    entities.append(entity)

        variable_patterns = [
            r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*',
            r'(?:const|let|var|parameter|arg)\s+([a-zA-Z_][a-zA-Z0-9_]*)',
        ]

        for pattern in variable_patterns:
            for match in re.finditer(pattern, text):
                var_name = match.group(1)
                if not self._is_common_keyword(var_name) and len(var_name) > 1:
                    entity_key = f"variable:{var_name}"
                    if entity_key in self._entities:
                        entity = self._entities[entity_key]
                        entity.last_mentioned = current_time
                        entity.mention_count += 1
                        self._entities.move_to_end(entity_key)
                    else:
                        entity = Entity(
                            type="variable",
                            name=var_name,
                            value=var_name,
                            first_mentioned=current_time,
                            last_mentioned=current_time,
                            mention_count=1
                        )
                        self._entities[entity_key] = entity
                        self._enforce_entity_limit()
                    if entity not in entities:
                        entities.append(entity)

        print(f"[DEBUG] 提取到 {len(entities)} 个实体")
        return entities

    def _is_likely_file_path(self, text: str) -> bool:
        if not text:
            return False
        if text.startswith('http://') or text.startswith('https://'):
            return False
        if text.startswith('www.'):
            return False
        if len(text) < 3:
            return False
        if re.search(r'^\d+$', text):
            return False
        return True

    def _is_common_keyword(self, word: str) -> bool:
        keywords = {
            'if', 'else', 'elif', 'for', 'while', 'do', 'switch', 'case',
            'break', 'continue', 'return', 'yield', 'throw', 'try', 'catch',
            'finally', 'with', 'as', 'import', 'from', 'export', 'def', 'class',
            'function', 'var', 'let', 'const', 'true', 'false', 'null', 'none',
            'self', 'this', 'that', 'it', 'in', 'is', 'and', 'or', 'not', 'async',
            'await', 'pass', 'lambda', 'map', 'filter', 'reduce', 'print', 'len',
            'str', 'int', 'float', 'list', 'dict', 'set', 'tuple', 'type', 'void',
            'new', 'delete', 'typeof', 'instanceof', 'static', 'public', 'private',
            'protected', 'readonly', 'abstract', 'extends', 'implements', 'super',
            'get', 'set', 'init', 'setup', 'teardown', 'main', 'run', 'execute'
        }
        return word.lower() in keywords

    def _enforce_entity_limit(self) -> None:
        while len(self._entities) > self.max_entities:
            oldest_key = next(iter(self._entities))
            del self._entities[oldest_key]
            print(f"[DEBUG] 实体数量超限，删除最旧的实体: {oldest_key}")

    def resolve_pronouns(self, text: str) -> str:
        print(f"[DEBUG] 开始解析代词: {text[:50]}...")
        resolved_text = text
        pronoun_replacements: Dict[str, str] = {}

        recent_entities = self.get_recent_entities(limit=5)

        lower_text = text.lower()

        for pronoun, entity_type in self._pronoun_map.items():
            if pronoun.lower() in lower_text:
                target_entity: Optional[Entity] = None

                for entity in recent_entities:
                    if entity.type == entity_type or (entity_type == "entity" and entity.type in ["file", "function", "class"]):
                        target_entity = entity
                        break

                if target_entity is None:
                    for entity in recent_entities:
                        if entity_type == "entity":
                            target_entity = entity
                            break

                if target_entity:
                    pronoun_replacements[pronoun] = f"[{target_entity.type}:{target_entity.name}]"

        for pronoun, replacement in sorted(pronoun_replacements.items(), key=lambda x: len(x[0]), reverse=True):
            pattern = r'\b' + re.escape(pronoun) + r'\b'
            resolved_text = re.sub(pattern, replacement, resolved_text, flags=re.IGNORECASE)

        print(f"[DEBUG] 代词解析完成: {resolved_text[:80]}...")
        return resolved_text

    def track_intent(self, user_input: str, entities: List[Entity]) -> Optional[str]:
        print(f"[DEBUG] 开始跟踪意图: {user_input[:50]}...")
        lower_input = user_input.lower()

        best_intent: Optional[str] = None
        best_score = 0

        for intent, keywords in self._intent_patterns.items():
            score = 0
            for keyword in keywords:
                if keyword in lower_input:
                    score += 1
                    if keyword == intent:
                        score += 2

            if entities:
                for entity in entities:
                    if entity.type in ["file", "function", "class"]:
                        score += 0.5

            if score > best_score:
                best_score = score
                best_intent = intent

        self._current_intent = best_intent
        print(f"[DEBUG] 识别到意图: {best_intent}, 分数: {best_score}")
        return best_intent

    def add_to_history(self, user_input: str, entities: List[Entity],
                      intent: Optional[str], response_summary: str) -> None:
        print(f"[DEBUG] 添加到历史记录...")
        turn = ConversationTurn(
            timestamp=time.time(),
            user_input=user_input,
            entities_extracted=[entity.name for entity in entities],
            intent=intent,
            response_summary=response_summary
        )

        self._conversation_history.append(turn)

        while len(self._conversation_history) > self.max_history:
            self._conversation_history.pop(0)
            print(f"[DEBUG] 历史记录超限，删除最旧的记录")

        print(f"[DEBUG] 当前历史记录数量: {len(self._conversation_history)}")

    def get_recent_entities(self, limit: int = 10) -> List[Entity]:
        entities_list = list(self._entities.values())
        entities_list.sort(key=lambda e: e.last_mentioned, reverse=True)
        return entities_list[:limit]

    def get_entity(self, name: str) -> Optional[Entity]:
        print(f"[DEBUG] 查找实体: {name}")

        direct_key = f"file:{name}"
        if direct_key in self._entities:
            return self._entities[direct_key]

        direct_key = f"function:{name}"
        if direct_key in self._entities:
            return self._entities[direct_key]

        direct_key = f"class:{name}"
        if direct_key in self._entities:
            return self._entities[direct_key]

        direct_key = f"variable:{name}"
        if direct_key in self._entities:
            return self._entities[direct_key]

        for entity in self._entities.values():
            if entity.name == name:
                return entity

        name_lower = name.lower()
        for entity in self._entities.values():
            if entity.name.lower() == name_lower:
                return entity

        return None

    def resolve_reference(self, reference: str) -> Optional[str]:
        print(f"[DEBUG] 解析引用: {reference}")
        reference_lower = reference.lower().strip()

        if reference_lower in self._pronoun_map:
            entity_type = self._pronoun_map[reference_lower]
            recent_entities = self.get_recent_entities(limit=5)

            for entity in recent_entities:
                if entity_type == "entity" or entity.type == entity_type:
                    print(f"[DEBUG] 引用解析结果: {entity.name}")
                    return entity.name

        entity = self.get_entity(reference)
        if entity:
            print(f"[DEBUG] 引用解析结果: {entity.name}")
            return entity.name

        for entity_key, entity in self._entities.items():
            if reference_lower in entity.name.lower():
                print(f"[DEBUG] 引用解析结果(模糊匹配): {entity.name}")
                return entity.name

        return None

    def get_conversation_history(self, limit: Optional[int] = None) -> List[ConversationTurn]:
        if limit is None:
            return list(self._conversation_history)
        return self._conversation_history[-limit:]

    def get_entities_by_type(self, entity_type: str) -> List[Entity]:
        print(f"[DEBUG] 获取类型为 {entity_type} 的实体")
        return [e for e in self._entities.values() if e.type == entity_type]

    def get_current_intent(self) -> Optional[str]:
        return self._current_intent

    def clear_old_entities(self, max_age_seconds: float = 3600) -> int:
        print(f"[DEBUG] 清理超过 {max_age_seconds} 秒的实体")
        current_time = time.time()
        keys_to_delete = []

        for key, entity in self._entities.items():
            if current_time - entity.last_mentioned > max_age_seconds:
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del self._entities[key]

        print(f"[DEBUG] 删除了 {len(keys_to_delete)} 个过期实体")
        return len(keys_to_delete)

    def get_entity_stats(self) -> Dict[str, Any]:
        stats = {
            "total_entities": len(self._entities),
            "total_history": len(self._conversation_history),
            "by_type": {},
            "most_mentioned": [],
            "recent_intent": self._current_intent
        }

        for entity in self._entities.values():
            if entity.type not in stats["by_type"]:
                stats["by_type"][entity.type] = 0
            stats["by_type"][entity.type] += 1

        sorted_entities = sorted(self._entities.values(), key=lambda e: e.mention_count, reverse=True)
        stats["most_mentioned"] = [
            {"name": e.name, "type": e.type, "count": e.mention_count}
            for e in sorted_entities[:5]
        ]

        return stats
