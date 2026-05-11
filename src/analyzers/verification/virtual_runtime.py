import sys
import re
import os
from typing import Any, Callable, Dict, List, Optional, Set, Union
from abc import ABC, abstractmethod
from datetime import datetime

from .multi_lang_mocks import MockRegistry, setup_python_module_mocks


class MockJavaClass(ABC):
    _java_class_name: str = ""

    def _get_java_class_name(self) -> str:
        return self._java_class_name

    def _to_python(self, obj: Any) -> Any:
        if isinstance(obj, MockJavaClass):
            return obj
        if isinstance(obj, str):
            return obj
        if isinstance(obj, bool):
            return obj
        if isinstance(obj, (int, float)):
            return obj
        if isinstance(obj, list):
            return [self._to_python(item) for item in obj]
        if isinstance(obj, dict):
            return {k: self._to_python(v) for k, v in obj.items()}
        return obj

    def _to_java(self, obj: Any) -> Any:
        if isinstance(obj, MockJavaClass):
            return obj
        if isinstance(obj, str):
            return MockString(obj)
        if isinstance(obj, bool):
            return obj
        if isinstance(obj, (int, float)):
            return obj
        if isinstance(obj, list):
            return ArrayList([self._to_java(item) for item in obj])
        if isinstance(obj, dict):
            result = HashMap()
            for k, v in obj.items():
                result.put(k, self._to_java(v))
            return result
        return obj


class MockString(MockJavaClass):
    _java_class_name = "java.lang.String"

    def __init__(self, value: str = ""):
        self._value = str(value)

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f'MockString("{self._value}")'

    def __add__(self, other: Any) -> "MockString":
        if isinstance(other, MockString):
            return MockString(self._value + other._value)
        return MockString(self._value + str(other))

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, MockString):
            return self._value == other._value
        if isinstance(other, str):
            return self._value == other
        return False

    def __hash__(self) -> int:
        return hash(self._value)

    def __getitem__(self, index: int) -> str:
        return self._value[index]

    def __len__(self) -> int:
        return len(self._value)

    def length(self) -> int:
        return len(self._value)

    def charAt(self, index: int) -> str:
        return self._value[index]

    def substring(self, begin: int, end: Optional[int] = None) -> "MockString":
        if end is None:
            return MockString(self._value[begin:])
        return MockString(self._value[begin:end])

    def replace(self, old: str, new: str) -> "MockString":
        return MockString(self._value.replace(old, new))

    def replaceFirst(self, regex: str, replacement: str) -> "MockString":
        return MockString(re.sub(regex, replacement, self._value, count=1))

    def replaceAll(self, regex: str, replacement: str) -> "MockString":
        return MockString(re.sub(regex, replacement, self._value))

    def split(self, regex: str, limit: Optional[int] = None) -> List["MockString"]:
        parts = self._value.split(regex, limit if limit else 0)
        return [MockString(p) for p in parts]

    def trim(self) -> "MockString":
        return MockString(self._value.strip())

    def toLowerCase(self) -> "MockString":
        return MockString(self._value.lower())

    def toUpperCase(self) -> "MockString":
        return MockString(self._value.upper())

    def startsWith(self, prefix: str) -> bool:
        return self._value.startswith(prefix)

    def endsWith(self, suffix: str) -> bool:
        return self._value.endswith(suffix)

    def contains(self, s: str) -> bool:
        return s in self._value

    def indexOf(self, s: str) -> int:
        return self._value.find(s)

    def lastIndexOf(self, s: str) -> int:
        return self._value.rfind(s)

    def isEmpty(self) -> bool:
        return len(self._value) == 0

    def concat(self, s: str) -> "MockString":
        return MockString(self._value + s)

    def matches(self, regex: str) -> bool:
        return bool(re.search(regex, self._value))

    def equalsIgnoreCase(self, other: str) -> bool:
        return self._value.lower() == other.lower()

    def subSequence(self, start: int, end: int) -> "MockString":
        return self.substring(start, end)

    def toCharArray(self) -> List[str]:
        return list(self._value)

    def getBytes(self) -> List[int]:
        return [ord(c) for c in self._value]

    @staticmethod
    def valueOf(obj: Any) -> "MockString":
        return MockString(str(obj))

    @staticmethod
    def format(fmt: str, *args: Any) -> "MockString":
        try:
            return MockString(fmt % args)
        except (ValueError, TypeError):
            return MockString(fmt.format(*args))


class MockIterator(MockJavaClass):
    _java_class_name = "java.util.Iterator"

    def __init__(self, items: List[Any]):
        self._items = items
        self._index = 0

    def hasNext(self) -> bool:
        return self._index < len(self._items)

    def next(self) -> Any:
        if self._index >= len(self._items):
            raise StopIteration()
        item = self._items[self._index]
        self._index += 1
        return item

    def remove(self) -> None:
        if self._index > 0:
            del self._items[self._index - 1]
            self._index -= 1


class ArrayList(MockJavaClass):
    _java_class_name = "java.util.ArrayList"

    def __init__(self, initial: Optional[List[Any]] = None):
        self._items: List[Any] = list(initial) if initial else []

    def __len__(self) -> int:
        return len(self._items)

    def __getitem__(self, index: int) -> Any:
        return self._items[index]

    def __setitem__(self, index: int, value: Any) -> None:
        self._items[index] = value

    def __iter__(self):
        return iter(self._items)

    def add(self, item: Any) -> bool:
        self._items.append(item)
        return True

    def add_at(self, index: int, item: Any) -> None:
        self._items.insert(index, item)

    def remove(self, index: Union[int, Any]) -> Any:
        if isinstance(index, int):
            return self._items.pop(index)
        self._items.remove(index)
        return True

    def get(self, index: int) -> Any:
        return self._items[index]

    def set(self, index: int, value: Any) -> Any:
        old = self._items[index]
        self._items[index] = value
        return old

    def size(self) -> int:
        return len(self._items)

    def isEmpty(self) -> bool:
        return len(self._items) == 0

    def contains(self, item: Any) -> bool:
        return item in self._items

    def indexOf(self, item: Any) -> int:
        try:
            return self._items.index(item)
        except ValueError:
            return -1

    def clear(self) -> None:
        self._items.clear()

    def iterator(self) -> MockIterator:
        return MockIterator(self._items)

    def toArray(self) -> List[Any]:
        return list(self._items)

    def containsAll(self, collection: "ArrayList") -> bool:
        for item in collection:
            if item not in self._items:
                return False
        return True

    def addAll(self, collection: "ArrayList") -> bool:
        self._items.extend(collection._items)
        return True


class LinkedList(ArrayList):
    _java_class_name = "java.util.LinkedList"


class HashMap(MockJavaClass):
    _java_class_name = "java.util.HashMap"

    def __init__(self, initial: Optional[Dict[Any, Any]] = None):
        self._map: Dict[Any, Any] = dict(initial) if initial else {}

    def __len__(self) -> int:
        return len(self._map)

    def __getitem__(self, key: Any) -> Any:
        return self._map[key]

    def __setitem__(self, key: Any, value: Any) -> None:
        self._map[key] = value

    def __contains__(self, key: Any) -> bool:
        return key in self._map

    def __iter__(self):
        return iter(self._map)

    def put(self, key: Any, value: Any) -> Optional[Any]:
        old = self._map.get(key)
        self._map[key] = value
        return old

    def get(self, key: Any, default: Any = None) -> Any:
        return self._map.get(key, default)

    def remove(self, key: Any) -> Optional[Any]:
        return self._map.pop(key, None)

    def size(self) -> int:
        return len(self._map)

    def isEmpty(self) -> bool:
        return len(self._map) == 0

    def containsKey(self, key: Any) -> bool:
        return key in self._map

    def containsValue(self, value: Any) -> bool:
        return value in self._map.values()

    def keySet(self) -> "MockSet":
        return MockSet(set(self._map.keys()))

    def values(self) -> ArrayList:
        return ArrayList(list(self._map.values()))

    def entrySet(self) -> "MockSet":
        entries = [MapEntry(k, v) for k, v in self._map.items()]
        return MockSet(set(entries))

    def clear(self) -> None:
        self._map.clear()

    def putAll(self, other: "HashMap") -> None:
        self._map.update(other._map)

    def getOrDefault(self, key: Any, default: Any) -> Any:
        return self._map.get(key, default)


class TreeMap(HashMap):
    _java_class_name = "java.util.TreeMap"


class MapEntry(MockJavaClass):
    _java_class_name = "java.util.Map.Entry"

    def __init__(self, key: Any, value: Any):
        self._key = key
        self._value = value

    def getKey(self) -> Any:
        return self._key

    def getValue(self) -> Any:
        return self._value


class MockSet(MockJavaClass):
    _java_class_name = "java.util.Set"

    def __init__(self, initial: Optional[Set[Any]] = None):
        self._set: Set[Any] = set(initial) if initial else set()

    def __len__(self) -> int:
        return len(self._set)

    def __iter__(self):
        return iter(self._set)

    def __contains__(self, item: Any) -> bool:
        return item in self._set

    def add(self, item: Any) -> bool:
        if item in self._set:
            return False
        self._set.add(item)
        return True

    def remove(self, item: Any) -> bool:
        if item not in self._set:
            return False
        self._set.remove(item)
        return True

    def contains(self, item: Any) -> bool:
        return item in self._set

    def size(self) -> int:
        return len(self._set)

    def isEmpty(self) -> bool:
        return len(self._set) == 0

    def iterator(self) -> MockIterator:
        return MockIterator(list(self._set))

    def clear(self) -> None:
        self._set.clear()

    def addAll(self, collection: "MockSet") -> bool:
        original_size = len(self._set)
        self._set.update(collection._set)
        return len(self._set) > original_size


class MockInputStream(MockJavaClass):
    _java_class_name = "java.io.InputStream"

    def __init__(self, data: Optional[bytes] = None):
        self._data = data or b""
        self._position = 0

    def read(self) -> int:
        if self._position >= len(self._data):
            return -1
        byte = self._data[self._position]
        self._position += 1
        return byte

    def read_all(self) -> bytes:
        return self._data[self._position:]

    def skip(self, n: int) -> int:
        skipped = min(n, len(self._data) - self._position)
        self._position += skipped
        return skipped

    def available(self) -> int:
        return len(self._data) - self._position

    def close(self) -> None:
        self._position = len(self._data)

    def reset(self) -> None:
        self._position = 0


class MockOutputStream(MockJavaClass):
    _java_class_name = "java.io.OutputStream"

    def __init__(self):
        self._buffer: List[int] = []

    def write(self, data: Union[int, bytes]) -> None:
        if isinstance(data, int):
            self._buffer.append(data)
        else:
            self._buffer.extend(data)

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass

    def toBytes(self) -> bytes:
        return bytes(self._buffer)


class MockBufferedReader(MockJavaClass):
    _java_class_name = "java.io.BufferedReader"

    def __init__(self, reader: Optional["MockInputStream"] = None):
        self._reader = reader

    def readLine(self) -> Optional[str]:
        if not self._reader:
            return None
        data = self._reader.read_all()
        try:
            return data.decode('utf-8').split('\n')[0]
        except:
            return None


class MockHttpServletRequest(MockJavaClass):
    _java_class_name = "javax.servlet.http.HttpServletRequest"

    def __init__(self):
        self._method = "GET"
        self._request_uri = "/"
        self._headers: HashMap = HashMap()
        self._parameters: HashMap = HashMap()
        self._session: MockHttpSession = MockHttpSession()
        self._body: Optional[bytes] = None

    def getMethod(self) -> str:
        return self._method

    def getRequestURI(self) -> str:
        return self._request_uri

    def getHeader(self, name: str) -> Optional[str]:
        return self._headers.get(name)

    def getHeaders(self, name: str) -> ArrayList:
        value = self._headers.get(name)
        if value:
            return ArrayList([value])
        return ArrayList()

    def getParameter(self, name: str) -> Optional[str]:
        return self._parameters.get(name)

    def getParameterMap(self) -> HashMap:
        return self._parameters

    def getSession(self, create: bool = True) -> "MockHttpSession":
        return self._session

    def setAttribute(self, name: str, value: Any) -> None:
        self._session.setAttribute(name, value)

    def getAttribute(self, name: str) -> Any:
        return self._session.getAttribute(name)

    def setMethod(self, method: str) -> None:
        self._method = method

    def setRequestURI(self, uri: str) -> None:
        self._request_uri = uri

    def setHeader(self, name: str, value: str) -> None:
        self._headers.put(name, value)

    def setParameter(self, name: str, value: str) -> None:
        self._parameters.put(name, value)

    def setBody(self, body: bytes) -> None:
        self._body = body


class MockHttpServletResponse(MockJavaClass):
    _java_class_name = "javax.servlet.http.HttpServletResponse"

    def __init__(self):
        self._status = 200
        self._headers: HashMap = HashMap()
        self._output_stream: MockOutputStream = MockOutputStream()
        self._content_type: Optional[str] = None
        self._committed = False

    def setStatus(self, status: int) -> None:
        self._status = status

    def getStatus(self) -> int:
        return self._status

    def setHeader(self, name: str, value: str) -> None:
        self._headers.put(name, value)

    def getHeader(self, name: str) -> str:
        return self._headers.get(name)

    def setContentType(self, content_type: str) -> None:
        self._content_type = content_type

    def getContentType(self) -> Optional[str]:
        return self._content_type

    def getOutputStream(self) -> MockOutputStream:
        return self._output_stream

    def setAttribute(self, name: str, value: Any) -> None:
        pass

    def addHeader(self, name: str, value: str) -> None:
        self._headers.put(name, value)

    def isCommitted(self) -> bool:
        return self._committed

    def sendRedirect(self, location: str) -> None:
        self._committed = True


class MockHttpSession(MockJavaClass):
    _java_class_name = "javax.servlet.http.HttpSession"

    def __init__(self):
        self._attributes: Dict[str, Any] = {}
        self._creation_time = datetime.now().timestamp()
        self._last_accessed_time = datetime.now().timestamp()
        self._max_inactive_interval = 1800
        self._id = "mock-session-id"

    def setAttribute(self, name: str, value: Any) -> None:
        self._attributes[name] = value

    def getAttribute(self, name: str) -> Any:
        return self._attributes.get(name)

    def removeAttribute(self, name: str) -> None:
        self._attributes.pop(name, None)

    def getId(self) -> str:
        return self._id

    def getCreationTime(self) -> int:
        return int(self._creation_time * 1000)

    def getLastAccessedTime(self) -> int:
        return int(self._last_accessed_time * 1000)

    def setMaxInactiveInterval(self, interval: int) -> None:
        self._max_inactive_interval = interval

    def getMaxInactiveInterval(self) -> int:
        return self._max_inactive_interval

    def invalidate(self) -> None:
        self._attributes.clear()


class MockComponent:
    _registered_components: Dict[str, Any] = {}

    def __init__(self, cls: type):
        self._cls = cls
        self._instance: Optional[Any] = None

    def __call__(self, *args, **kwargs) -> Any:
        instance = self._cls(*args, **kwargs)
        class_name = self._cls.__name__
        MockComponent._registered_components[class_name] = instance
        MockApplicationContext._instance.register_bean(class_name, instance)
        return instance

    @classmethod
    def get_registered_components(cls) -> Dict[str, Any]:
        return cls._registered_components


class MockRequestMapping:
    _routes: Dict[str, List[Dict[str, Any]]] = {}

    def __init__(self, path: str, method: str = "GET"):
        self._path = path
        self._method = method

    def __call__(self, func: Callable) -> Callable:
        route_key = f"{self._method}:{self._path}"
        if route_key not in MockRequestMapping._routes:
            MockRequestMapping._routes[route_key] = []
        MockRequestMapping._routes[route_key].append({
            "path": self._path,
            "method": self._method,
            "handler": func
        })
        return func

    @classmethod
    def get_routes(cls) -> Dict[str, List[Dict[str, Any]]]:
        return cls._routes

    @classmethod
    def clear_routes(cls) -> None:
        cls._routes.clear()


class MockApplicationContext(MockJavaClass):
    _java_class_name = "org.springframework.context.ApplicationContext"
    _instance: Optional["MockApplicationContext"] = None

    def __init__(self):
        self._beans: Dict[str, Any] = {}
        self._bean_factory: "MockBeanFactory" = MockBeanFactory()

    @classmethod
    def get_instance(cls) -> "MockApplicationContext":
        if cls._instance is None:
            cls._instance = MockApplicationContext()
        return cls._instance

    def register_bean(self, name: str, bean: Any) -> None:
        self._beans[name] = bean

    def getBean(self, name_or_class: Union[str, type]) -> Any:
        if isinstance(name_or_class, str):
            return self._beans.get(name_or_class)
        for bean in self._beans.values():
            if isinstance(bean, name_or_class):
                return bean
        return None

    def getBeansOfType(self, cls: type) -> Dict[str, Any]:
        result = {}
        for name, bean in self._beans.items():
            if isinstance(bean, cls):
                result[name] = bean
        return result

    def containsBean(self, name: str) -> bool:
        return name in self._beans

    def clear(self) -> None:
        self._beans.clear()


class MockBeanFactory(MockJavaClass):
    _java_class_name = "org.springframework.beans.factory.BeanFactory"

    def __init__(self):
        self._singleton_cache: Dict[str, Any] = {}
        self._bean_definitions: Dict[str, Dict[str, Any]] = {}

    def register_singleton(self, name: str, instance: Any) -> None:
        self._singleton_cache[name] = instance

    def getSingleton(self, name: str) -> Any:
        return self._singleton_cache.get(name)

    def createBean(self, cls: type, *args, **kwargs) -> Any:
        return cls(*args, **kwargs)


class MyBatisParameterHandler(MockJavaClass):
    _java_class_name = "org.apache.ibatis.binding.MapperMethod$ParamMap"

    def __init__(self, params: Optional[Dict[str, Any]] = None):
        self._params: Dict[str, Any] = params or {}

    def get_parameter(self, key: str) -> Any:
        return self._params.get(key)

    def set_parameter(self, key: str, value: Any) -> None:
        self._params[key] = value

    @staticmethod
    def handle_dollar_brace(sql: str, params: Dict[str, Any]) -> str:
        pattern = r'\$\{([^}]+)\}'
        matches = re.findall(pattern, sql)
        result = sql
        for match in matches:
            key = match.strip()
            value = params.get(key, "")
            result = result.replace(f'${{{match}}}', str(value))
        return result

    @staticmethod
    def handle_hash_brace(sql: str, params: Dict[str, Any]) -> str:
        pattern = r'#\{([^}]+)\}'
        result = sql
        param_index = 0
        for match in re.findall(pattern, sql):
            key = match.strip()
            value = params.get(key, f'?')
            if value == '?':
                param_index += 1
                result = result.replace(f'#{{{match}}}', '?', 1)
            else:
                if isinstance(value, str):
                    value = f"'{value}'"
                else:
                    value = str(value)
                result = result.replace(f'#{{{match}}}', value, 1)
        return result


class MockSqlSession(MockJavaClass):
    _java_class_name = "org.apache.ibatis.session.SqlSession"

    def __init__(self, configuration: Optional["MockConfiguration"] = None):
        self._configuration = configuration or MockConfiguration()
        self._mapper_results: Dict[str, Any] = {}
        self._is_committed = False
        self._is_rollback = False

    def selectOne(self, sql: str, params: Optional[Dict[str, Any]] = None) -> Any:
        params = params or {}
        safe_sql = MyBatisParameterHandler.handle_hash_brace(sql, params)
        return self._mapper_results.get(sql)

    def selectList(self, sql: str, params: Optional[Dict[str, Any]] = None) -> ArrayList:
        params = params or {}
        return ArrayList()

    def insert(self, sql: str, params: Optional[Dict[str, Any]] = None) -> int:
        params = params or {}
        return 1

    def update(self, sql: str, params: Optional[Dict[str, Any]] = None) -> int:
        params = params or {}
        return 1

    def delete(self, sql: str, params: Optional[Dict[str, Any]] = None) -> int:
        params = params or {}
        return 1

    def commit(self) -> None:
        self._is_committed = True

    def rollback(self) -> None:
        self._is_rollback = True

    def close(self) -> None:
        pass

    def setMapperResult(self, sql: str, result: Any) -> None:
        self._mapper_results[sql] = result

    def getConfiguration(self) -> "MockConfiguration":
        return self._configuration


class MockSqlSessionFactory(MockJavaClass):
    _java_class_name = "org.apache.ibatis.session.SqlSessionFactory"

    def __init__(self, configuration: Optional["MockConfiguration"] = None):
        self._configuration = configuration or MockConfiguration()

    def openSession(self, auto_commit: bool = False) -> MockSqlSession:
        session = MockSqlSession(self._configuration)
        if auto_commit:
            session.commit()
        return session

    def getConfiguration(self) -> "MockConfiguration":
        return self._configuration


class MockConfiguration(MockJavaClass):
    _java_class_name = "org.apache.ibatis.session.Configuration"

    def __init__(self):
        self._mapper_registry: Dict[str, Any] = {}
        self._type_aliases: Dict[str, type] = {}

    def addMappedStatement(self, statement_id: str, statement: Any) -> None:
        self._mapper_registry[statement_id] = statement

    def getMappedStatement(self, statement_id: str) -> Any:
        return self._mapper_registry.get(statement_id)

    def registerTypeAlias(self, alias: str, cls: type) -> None:
        self._type_aliases[alias] = cls

    def getTypeAlias(self, alias: str) -> type:
        return self._type_aliases.get(alias)


class MockResultSet(MockJavaClass):
    _java_class_name = "java.sql.ResultSet"

    def __init__(self, rows: Optional[List[Dict[str, Any]]] = None):
        self._rows = rows or []
        self._current_row: int = -1
        self._metadata: Optional["MockResultSetMetaData"] = None

    def next(self) -> bool:
        self._current_row += 1
        return self._current_row < len(self._rows)

    def getString(self, column: Union[str, int]) -> Optional[str]:
        if self._current_row < 0 or self._current_row >= len(self._rows):
            return None
        row = self._rows[self._current_row]
        if isinstance(column, int):
            keys = list(row.keys())
            if column < len(keys):
                return str(row[keys[column]])
        return str(row.get(column, ""))

    def getInt(self, column: Union[str, int]) -> int:
        value = self.getString(column)
        try:
            return int(value) if value else 0
        except (ValueError, TypeError):
            return 0

    def getLong(self, column: Union[str, int]) -> int:
        return self.getInt(column)

    def getBoolean(self, column: Union[str, int]) -> bool:
        value = self.getString(column)
        return value.lower() in ("true", "1", "yes") if value else False

    def close(self) -> None:
        self._rows.clear()


class MockResultSetMetaData(MockJavaClass):
    _java_class_name = "java.sql.ResultSetMetaData"

    def __init__(self, columns: Optional[List[str]] = None):
        self._columns = columns or []

    def getColumnCount(self) -> int:
        return len(self._columns)

    def getColumnLabel(self, column: int) -> str:
        if 0 <= column < len(self._columns):
            return self._columns[column]
        return ""

    def getColumnName(self, column: int) -> str:
        return self.getColumnLabel(column)


class MockConnection(MockJavaClass):
    _java_class_name = "java.sql.Connection"

    def __init__(self):
        self._is_closed = False
        self._auto_commit = True

    def createStatement(self) -> "MockStatement":
        return MockStatement()

    def prepareStatement(self, sql: str) -> "MockPreparedStatement":
        return MockPreparedStatement(sql)

    def setAutoCommit(self, auto_commit: bool) -> None:
        self._auto_commit = auto_commit

    def getAutoCommit(self) -> bool:
        return self._auto_commit

    def commit(self) -> None:
        pass

    def rollback(self) -> None:
        pass

    def close(self) -> None:
        self._is_closed = True

    def isClosed(self) -> bool:
        return self._is_closed


class MockStatement(MockJavaClass):
    _java_class_name = "java.sql.Statement"

    def __init__(self):
        self._results: List[Any] = []

    def executeQuery(self, sql: str) -> MockResultSet:
        return MockResultSet()

    def executeUpdate(self, sql: str) -> int:
        return 0

    def execute(self, sql: str) -> bool:
        return True

    def close(self) -> None:
        pass


class MockPreparedStatement(MockJavaClass):
    _java_class_name = "java.sql.PreparedStatement"

    def __init__(self, sql: str):
        self._sql = sql
        self._params: List[Any] = []

    def setString(self, index: int, value: str) -> None:
        while len(self._params) <= index:
            self._params.append(None)
        self._params[index] = value

    def setInt(self, index: int, value: int) -> None:
        while len(self._params) <= index:
            self._params.append(None)
        self._params[index] = value

    def setLong(self, index: int, value: int) -> None:
        self.setInt(index, value)

    def setBoolean(self, index: int, value: bool) -> None:
        while len(self._params) <= index:
            self._params.append(None)
        self._params[index] = value

    def setNull(self, index: int, sql_type: int) -> None:
        while len(self._params) <= index:
            self._params.append(None)
        self._params[index] = None

    def executeQuery(self) -> MockResultSet:
        sql = self._sql
        for i, param in enumerate(self._params):
            if param is not None:
                sql = sql.replace(f'?', f"'{param}'" if isinstance(param, str) else str(param), 1)
        return MockResultSet()

    def executeUpdate(self) -> int:
        return 1

    def execute(self) -> bool:
        return True

    def close(self) -> None:
        self._params.clear()


class VirtualRuntimeEnvironment:
    def __init__(self):
        self._mock_classes: Dict[str, MockJavaClass] = {}
        self._original_modules: Dict[str, Any] = {}
        self._installed = False
        self._mock_registry = MockRegistry()
        self._current_language: Optional[str] = None
        self._setup_mocks()

    def _setup_mocks(self) -> None:
        self._mock_classes = {
            "java.lang.String": MockString,
            "java.util.List": ArrayList,
            "java.util.ArrayList": ArrayList,
            "java.util.LinkedList": LinkedList,
            "java.util.Map": HashMap,
            "java.util.HashMap": HashMap,
            "java.util.TreeMap": TreeMap,
            "java.util.Set": MockSet,
            "java.util.Iterator": MockIterator,
            "java.io.InputStream": MockInputStream,
            "java.io.OutputStream": MockOutputStream,
            "java.io.BufferedReader": MockBufferedReader,
            "javax.servlet.http.HttpServletRequest": MockHttpServletRequest,
            "javax.servlet.http.HttpServletResponse": MockHttpServletResponse,
            "javax.servlet.http.HttpSession": MockHttpSession,
            "org.springframework.context.ApplicationContext": MockApplicationContext,
            "org.springframework.beans.factory.BeanFactory": MockBeanFactory,
            "org.apache.ibatis.session.SqlSession": MockSqlSession,
            "org.apache.ibatis.session.SqlSessionFactory": MockSqlSessionFactory,
            "org.apache.ibatis.session.Configuration": MockConfiguration,
            "org.apache.ibatis.binding.MapperMethod$ParamMap": MyBatisParameterHandler,
            "java.sql.ResultSet": MockResultSet,
            "java.sql.ResultSetMetaData": MockResultSetMetaData,
            "java.sql.Connection": MockConnection,
            "java.sql.Statement": MockStatement,
            "java.sql.PreparedStatement": MockPreparedStatement,
        }

    def set_language(self, language: str) -> None:
        self._current_language = language

    def get_mock_registry(self) -> MockRegistry:
        return self._mock_registry

    def setup_for_language(self, language: str) -> None:
        self._current_language = language
        self.setup_environment()

    def _setup_cpp_mocks(self) -> None:
        pass

    def _setup_go_mocks(self) -> None:
        pass

    def _setup_rust_mocks(self) -> None:
        pass

    def _setup_csharp_mocks(self) -> None:
        pass

    def register_mock_class(self, java_class_name: str, mock_class: type) -> None:
        self._mock_classes[java_class_name] = mock_class
        self._mock_registry.register(java_class_name, mock_class)

    def get_mock_class(self, java_class_name: str) -> Optional[type]:
        return self._mock_classes.get(java_class_name)

    def setup_environment(self) -> None:
        if self._installed:
            return

        for module_name in list(sys.modules.keys()):
            if any(module_name.startswith(prefix) for prefix in [
                "java.", "javax.", "org.springframework.", "org.apache."
            ]):
                self._original_modules[module_name] = sys.modules[module_name]
                del sys.modules[module_name]

        for java_class_name, mock_class in self._mock_classes.items():
            module_parts = java_class_name.rsplit(".", 1)
            if len(module_parts) == 2:
                module_name, class_name = module_parts
            else:
                module_name = ""
                class_name = java_class_name

            if module_name:
                if module_name not in sys.modules:
                    mock_module = type(sys)('_mock_' + module_name)
                    mock_module.__path__ = []
                    sys.modules[module_name] = mock_module

                actual_module = sys.modules[module_name]
                setattr(actual_module, class_name, mock_class)
            else:
                sys.modules[class_name] = mock_class

        if self._current_language:
            if self._current_language == "cpp":
                self._setup_cpp_mocks()
            elif self._current_language == "go":
                self._setup_go_mocks()
            elif self._current_language == "rust":
                self._setup_rust_mocks()
            elif self._current_language == "csharp":
                self._setup_csharp_mocks()

        setup_python_module_mocks(self._mock_registry)
        self._install_string_concatenation()
        self._installed = True

    def _install_string_concatenation(self) -> None:
        original_str_add = str.__add__

        def custom_str_add(self, other):
            if isinstance(other, MockString):
                return original_str_add(self, str(other._value))
            return original_str_add(self, other)

        str.__add__ = custom_str_add

    def teardown_environment(self) -> None:
        if not self._installed:
            return

        for module_name in list(sys.modules.keys()):
            if module_name.startswith("_mock_"):
                del sys.modules[module_name]

        for java_class_name in list(sys.modules.keys()):
            module_parts = java_class_name.rsplit(".", 1)
            if len(module_parts) == 2:
                module_name, class_name = module_parts
                if any(module_name.startswith(prefix) for prefix in [
                    "java", "javax", "org.springframework", "org.apache"
                ]):
                    if module_name in sys.modules:
                        module = sys.modules[module_name]
                        if hasattr(module, class_name):
                            delattr(module, class_name)

        for module_name, module in self._original_modules.items():
            sys.modules[module_name] = module

        self._original_modules.clear()
        self._mock_registry.clear()
        self._current_language = None
        self._installed = False

    def is_installed(self) -> bool:
        return self._installed


def java_to_python(obj: Any) -> Any:
    if isinstance(obj, MockString):
        return obj._value
    if isinstance(obj, MockJavaClass):
        if isinstance(obj, ArrayList):
            return [java_to_python(item) for item in obj._items]
        if isinstance(obj, HashMap):
            return {java_to_python(k): java_to_python(v) for k, v in obj._map.items()}
        if isinstance(obj, MockSet):
            return {java_to_python(item) for item in obj._set}
        return obj
    if isinstance(obj, str):
        return obj
    if isinstance(obj, (list, tuple)):
        return [java_to_python(item) for item in obj]
    if isinstance(obj, dict):
        return {java_to_python(k): java_to_python(v) for k, v in obj.items()}
    return obj


def python_to_java(obj: Any) -> Any:
    if obj is None:
        return None
    if isinstance(obj, MockJavaClass):
        return obj
    if isinstance(obj, MockString):
        return obj
    if isinstance(obj, str):
        return MockString(obj)
    if isinstance(obj, bool):
        return obj
    if isinstance(obj, (int, float)):
        return obj
    if isinstance(obj, list):
        return ArrayList([python_to_java(item) for item in obj])
    if isinstance(obj, tuple):
        result = LinkedList()
        for item in obj:
            result.add(python_to_java(item))
        return result
    if isinstance(obj, set):
        return MockSet({python_to_java(item) for item in obj})
    if isinstance(obj, dict):
        result = HashMap()
        for k, v in obj.items():
            result.put(python_to_java(k), python_to_java(v))
        return result
    return obj


_runtime_environment: Optional[VirtualRuntimeEnvironment] = None


def get_runtime_environment() -> VirtualRuntimeEnvironment:
    global _runtime_environment
    if _runtime_environment is None:
        _runtime_environment = VirtualRuntimeEnvironment()
    return _runtime_environment


def setup_java_runtime() -> VirtualRuntimeEnvironment:
    env = get_runtime_environment()
    env.setup_environment()
    return env


def teardown_java_runtime() -> None:
    global _runtime_environment
    if _runtime_environment is not None:
        _runtime_environment.teardown_environment()
        _runtime_environment = None
