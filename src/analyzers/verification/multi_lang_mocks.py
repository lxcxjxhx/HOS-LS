from typing import TypeVar, Generic, Optional, Any, Dict, List, Union, Callable
from abc import ABC, abstractmethod

K = TypeVar('K')
V = TypeVar('V')
T = TypeVar('T')
E = TypeVar('E')


class BaseMock(ABC):
    _original_name: str = ""

    def _get_original_name(self) -> str:
        return self._original_name

    def _to_python(self) -> Any:
        return self

    @classmethod
    def _from_python(cls, value: Any) -> 'BaseMock':
        return cls()


class MockRegistry:
    _mocks: Dict[str, Dict[str, type]] = {}
    _language_setup: Dict[str, bool] = {}

    @classmethod
    def register(cls, language: str, mock_class: type) -> None:
        if language not in cls._mocks:
            cls._mocks[language] = {}
        cls._mocks[language][mock_class.__name__] = mock_class

    @classmethod
    def get(cls, language: str, class_name: str) -> Optional[type]:
        return cls._mocks.get(language, {}).get(class_name)

    @classmethod
    def setup_for_language(cls, language: str) -> Dict[str, type]:
        if language in cls._language_setup and cls._language_setup[language]:
            return cls._mocks.get(language, {})

        language_lower = language.lower()
        if language_lower == "cpp" or language_lower == "c++":
            cls._setup_cpp_mocks()
        elif language_lower == "go" or language_lower == "golang":
            cls._setup_go_mocks()
        elif language_lower == "rust":
            cls._setup_rust_mocks()
        elif language_lower == "csharp" or language_lower == "c#":
            cls._setup_csharp_mocks()

        cls._language_setup[language] = True
        return cls._mocks.get(language, {})

    @classmethod
    def _setup_cpp_mocks(cls) -> None:
        language = "cpp"
        cls._mocks[language] = {
            "MockStdString": MockStdString,
            "MockStdVector": MockStdVector,
            "MockStdMap": MockStdMap,
            "MockStdcout": MockStdcout,
            "MockStdcerr": MockStdcerr,
        }

    @classmethod
    def _setup_go_mocks(cls) -> None:
        language = "go"
        cls._mocks[language] = {
            "MockFmt": MockFmt,
            "MockStrconv": MockStrconv,
            "MockStrings": MockStrings,
            "MockIo": MockIo,
            "MockOs": MockOs,
        }

    @classmethod
    def _setup_rust_mocks(cls) -> None:
        language = "rust"
        cls._mocks[language] = {
            "MockVec": MockVec,
            "MockHashMap": MockHashMap,
            "MockOption": MockOption,
            "MockResult": MockResult,
            "MockPrint": MockPrint,
        }

    @classmethod
    def _setup_csharp_mocks(cls) -> None:
        language = "csharp"
        cls._mocks[language] = {
            "MockConsole": MockConsole,
            "MockString": MockString,
            "MockList": MockList,
            "MockDictionary": MockDictionary,
        }


class MockStdString(BaseMock):
    _original_name = "std::string"

    def __init__(self, value: str = ""):
        self._value = value
        self._original_name = "std::string"

    def append(self, other: str) -> 'MockStdString':
        self._value += other
        return self

    def replace(self, pos: int, len_: int, other: str) -> 'MockStdString':
        self._value = self._value[:pos] + other + self._value[pos + len_:]
        return self

    def substr(self, pos: int = 0, len_: int = -1) -> 'MockStdString':
        if len_ == -1:
            return MockStdString(self._value[pos:])
        return MockStdString(self._value[pos:pos + len_])

    def c_str(self) -> str:
        return self._value + '\0'

    def length(self) -> int:
        return len(self._value)

    def empty(self) -> bool:
        return len(self._value) == 0

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"MockStdString('{self._value}')"

    def _to_python(self) -> str:
        return self._value

    @classmethod
    def _from_python(cls, value: Any) -> 'MockStdString':
        return cls(str(value))


class MockStdVector(BaseMock, Generic[T]):
    _original_name = "std::vector"

    def __init__(self, data: Optional[List[T]] = None):
        self._data = data if data is not None else []
        self._original_name = "std::vector"

    def push_back(self, value: T) -> None:
        self._data.append(value)

    def pop_back(self) -> T:
        return self._data.pop()

    def at(self, index: int) -> T:
        return self._data[index]

    def front(self) -> T:
        return self._data[0]

    def back(self) -> T:
        return self._data[-1]

    def empty(self) -> bool:
        return len(self._data) == 0

    def size(self) -> int:
        return len(self._data)

    def clear(self) -> None:
        self._data.clear()

    def begin(self) -> int:
        return 0

    def end(self) -> int:
        return len(self._data)

    def __getitem__(self, index: int) -> T:
        return self._data[index]

    def __setitem__(self, index: int, value: T) -> None:
        self._data[index] = value

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def _to_python(self) -> List[T]:
        return self._data

    @classmethod
    def _from_python(cls, value: Any) -> 'MockStdVector':
        return cls(list(value))


class MockStdMap(BaseMock, Generic[K, V]):
    _original_name = "std::map"

    def __init__(self, data: Optional[Dict[K, V]] = None):
        self._data = data if data is not None else {}
        self._original_name = "std::map"

    def insert(self, key: K, value: V) -> None:
        self._data[key] = value

    def erase(self, key: K) -> None:
        if key in self._data:
            del self._data[key]

    def find(self, key: K) -> Optional[V]:
        return self._data.get(key)

    def at(self, key: K) -> V:
        return self._data[key]

    def count(self, key: K) -> int:
        return 1 if key in self._data else 0

    def empty(self) -> bool:
        return len(self._data) == 0

    def size(self) -> int:
        return len(self._data)

    def clear(self) -> None:
        self._data.clear()

    def __getitem__(self, key: K) -> V:
        return self._data[key]

    def __setitem__(self, key: K, value: V) -> None:
        self._data[key] = value

    def __contains__(self, key: K) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def _to_python(self) -> Dict[K, V]:
        return self._data

    @classmethod
    def _from_python(cls, value: Any) -> 'MockStdMap':
        return cls(dict(value))


class MockStdcout(BaseMock):
    _original_name = "std::cout"

    _buffer: List[str] = []

    @classmethod
    def print(cls, *args: Any) -> None:
        output = ' '.join(str(arg) for arg in args)
        cls._buffer.append(output)

    @classmethod
    def println(cls, *args: Any) -> None:
        output = ' '.join(str(arg) for arg in args)
        cls._buffer.append(output + '\n')

    @classmethod
    def flush(cls) -> None:
        pass

    @classmethod
    def get_buffer(cls) -> List[str]:
        return cls._buffer.copy()

    @classmethod
    def clear_buffer(cls) -> None:
        cls._buffer.clear()


class MockStdcerr(BaseMock):
    _original_name = "std::cerr"

    _buffer: List[str] = []

    @classmethod
    def print(cls, *args: Any) -> None:
        output = ' '.join(str(arg) for arg in args)
        cls._buffer.append(output)

    @classmethod
    def println(cls, *args: Any) -> None:
        output = ' '.join(str(arg) for arg in args)
        cls._buffer.append(output + '\n')

    @classmethod
    def flush(cls) -> None:
        pass

    @classmethod
    def get_buffer(cls) -> List[str]:
        return cls._buffer.copy()

    @classmethod
    def clear_buffer(cls) -> None:
        cls._buffer.clear()


class MockFmt(BaseMock):
    _original_name = "fmt"

    @staticmethod
    def Print(*args: Any) -> str:
        return ' '.join(str(arg) for arg in args)

    @staticmethod
    def Println(*args: Any) -> str:
        return ' '.join(str(arg) for arg in args) + '\n'

    @staticmethod
    def Sprintf(format_str: str, *args: Any) -> str:
        result = format_str
        for arg in args:
            result = result.replace('{}', str(arg), 1)
        return result

    @staticmethod
    def Printf(format_str: str, *args: Any) -> str:
        return MockFmt.Sprintf(format_str, *args)


class MockStrconv(BaseMock):
    _original_name = "strconv"

    @staticmethod
    def Atoi(s: str) -> int:
        return int(s)

    @staticmethod
    def Itoa(i: int) -> str:
        return str(i)

    @staticmethod
    def FormatInt(i: int, base: int = 10) -> str:
        if base == 10:
            return str(i)
        return format(i, 'b' if base == 2 else 'x' if base == 16 else 'd')

    @staticmethod
    def ParseInt(s: str, base: int = 10) -> int:
        return int(s, base if base != 10 else 10)

    @staticmethod
    def FormatFloat(f: float, precision: int = 6) -> str:
        return format(f, f'.{precision}f')

    @staticmethod
    def ParseFloat(s: str) -> float:
        return float(s)


class MockStrings(BaseMock):
    _original_name = "strings"

    @staticmethod
    def Contains(s: str, substr: str) -> bool:
        return substr in s

    @staticmethod
    def ContainsAny(s: str, chars: str) -> bool:
        return any(c in s for c in chars)

    @staticmethod
    def Count(s: str, substr: str) -> int:
        return s.count(substr)

    @staticmethod
    def Fields(s: str) -> List[str]:
        return s.split()

    @staticmethod
    def HasPrefix(s: str, prefix: str) -> bool:
        return s.startswith(prefix)

    @staticmethod
    def HasSuffix(s: str, suffix: str) -> bool:
        return s.endswith(suffix)

    @staticmethod
    def Index(s: str, substr: str) -> int:
        return s.find(substr)

    @staticmethod
    def Join(elems: List[str], sep: str) -> str:
        return sep.join(elems)

    @staticmethod
    def Lower(s: str) -> str:
        return s.lower()

    @staticmethod
    def Upper(s: str) -> str:
        return s.upper()

    @staticmethod
    def Replace(s: str, old: str, new: str, n: int = -1) -> str:
        return s.replace(old, new, n)

    @staticmethod
    def Split(s: str, sep: str) -> List[str]:
        return s.split(sep)

    @staticmethod
    def SplitN(s: str, sep: str, n: int) -> List[str]:
        return s.split(sep, n)

    @staticmethod
    def Trim(s: str, cutset: str) -> str:
        return s.strip(cutset)

    @staticmethod
    def TrimSpace(s: str) -> str:
        return s.strip()


class MockIo(BaseMock):
    _original_name = "io"

    class Reader(BaseMock):
        def __init__(self, data: bytes = b''):
            self._data = data
            self._position = 0

        def Read(self, p: bytearray) -> int:
            if self._position >= len(self._data):
                return 0
            chunk = self._data[self._position:self._position + len(p)]
            for i, b in enumerate(chunk):
                p[i] = b
            self._position += len(chunk)
            return len(chunk)

        def ReadAll(self) -> bytes:
            return self._data[self._position:]

    class Writer(BaseMock):
        def __init__(self):
            self._buffer = bytearray()

        def Write(self, p: Union[bytes, bytearray]) -> int:
            self._buffer.extend(p)
            return len(p)

        def GetData(self) -> bytes:
            return bytes(self._buffer)

        def Clear(self) -> None:
            self._buffer.clear()


class MockOs(BaseMock):
    _original_name = "os"

    _files: Dict[str, bytes] = {}

    @classmethod
    def Open(cls, path: str, mode: str = 'r') -> 'MockOs.File':
        return cls.File(path, mode)

    @classmethod
    def Create(cls, path: str) -> 'MockOs.File':
        return cls.File(path, 'w')

    @classmethod
    def Read(cls, path: str) -> bytes:
        return cls._files.get(path, b'')

    @classmethod
    def Write(cls, path: str, data: bytes) -> None:
        cls._files[path] = data

    @classmethod
    def SetFiles(cls, files: Dict[str, bytes]) -> None:
        cls._files = files.copy()

    @classmethod
    def ClearFiles(cls) -> None:
        cls._files.clear()

    class File(BaseMock):
        def __init__(self, path: str, mode: str = 'r'):
            self._path = path
            self._mode = mode
            self._position = 0
            self._data = MockOs._files.get(path, b'')

        def Read(self, n: int = -1) -> bytes:
            if n == -1:
                result = self._data[self._position:]
                self._position = len(self._data)
            else:
                result = self._data[self._position:self._position + n]
                self._position += n
            return result

        def Write(self, data: bytes) -> int:
            if 'w' in self._mode or 'a' in self._mode:
                if self._position >= len(self._data):
                    self._data += data
                else:
                    self._data = self._data[:self._position] + data
                MockOs._files[self._path] = self._data
                self._position += len(data)
                return len(data)
            return 0

        def Seek(self, offset: int, whence: int = 0) -> int:
            if whence == 0:
                self._position = offset
            elif whence == 1:
                self._position += offset
            elif whence == 2:
                self._position = len(self._data) + offset
            return self._position

        def Close(self) -> None:
            pass


class MockVec(BaseMock, Generic[T]):
    _original_name = "Vec"

    def __init__(self, data: Optional[List[T]] = None):
        self._data = data if data is not None else []
        self._original_name = "Vec"

    def push(self, value: T) -> None:
        self._data.append(value)

    def pop(self) -> Optional[T]:
        if self._data:
            return self._data.pop()
        return None

    def get(self, index: int) -> Optional[T]:
        if 0 <= index < len(self._data):
            return self._data[index]
        return None

    def len(self) -> int:
        return len(self._data)

    def is_empty(self) -> bool:
        return len(self._data) == 0

    def clear(self) -> None:
        self._data.clear()

    def __getitem__(self, index: int) -> T:
        return self._data[index]

    def __setitem__(self, index: int, value: T) -> None:
        self._data[index] = value

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def _to_python(self) -> List[T]:
        return self._data

    @classmethod
    def _from_python(cls, value: Any) -> 'MockVec':
        return cls(list(value))


class MockHashMap(BaseMock, Generic[K, V]):
    _original_name = "HashMap"

    def __init__(self, data: Optional[Dict[K, V]] = None):
        self._data = data if data is not None else {}
        self._original_name = "HashMap"

    def insert(self, key: K, value: V) -> None:
        self._data[key] = value

    def remove(self, key: K) -> None:
        if key in self._data:
            del self._data[key]

    def get(self, key: K) -> Optional[V]:
        return self._data.get(key)

    def contains_key(self, key: K) -> bool:
        return key in self._data

    def len(self) -> int:
        return len(self._data)

    def is_empty(self) -> bool:
        return len(self._data) == 0

    def clear(self) -> None:
        self._data.clear()

    def __getitem__(self, key: K) -> V:
        return self._data[key]

    def __setitem__(self, key: K, value: V) -> None:
        self._data[key] = value

    def __contains__(self, key: K) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def _to_python(self) -> Dict[K, V]:
        return self._data

    @classmethod
    def _from_python(cls, value: Any) -> 'MockHashMap':
        return cls(dict(value))


class MockOption(Generic[T]):
    _original_name = "Option"

    def __init__(self, value: Optional[T] = None, is_some: bool = False):
        self._value = value
        self._is_some = is_some
        self._is_none = not is_some

    @classmethod
    def Some(cls, value: T) -> 'MockOption[T]':
        return cls(value, True)

    @classmethod
    def None(cls) -> 'MockOption':
        return cls(None, False)

    def is_some(&self) -> bool:
        return self._is_some

    def is_none(&self) -> bool:
        return self._is_none

    def unwrap(self) -> T:
        if self._is_some:
            return self._value
        raise ValueError("called unwrap on None")

    def unwrap_or(self, default: T) -> T:
        if self._is_some:
            return self._value
        return default

    def map(self, func: Callable[[T], Any]) -> 'MockOption':
        if self._is_some:
            return MockOption.Some(func(self._value))
        return MockOption.None()

    def _to_python(self) -> Optional[T]:
        return self._value


class MockResult(BaseMock, Generic[T, E]):
    _original_name = "Result"

    def __init__(self, value: Optional[T] = None, error: Optional[E] = None, is_ok: bool = True):
        self._value = value
        self._error = error
        self._is_ok = is_ok
        self._is_err = not is_ok

    @classmethod
    def Ok(cls, value: T) -> 'MockResult[T, E]':
        return cls(value, None, True)

    @classmethod
    def Err(cls, error: E) -> 'MockResult[T, E]':
        return cls(None, error, False)

    def is_ok(&self) -> bool:
        return self._is_ok

    def is_err(&self) -> bool:
        return self._is_err

    def unwrap(self) -> T:
        if self._is_ok:
            return self._value
        raise ValueError(f"called unwrap on Err: {self._error}")

    def unwrap_err(self) -> E:
        if self._is_err:
            return self._error
        raise ValueError(f"called unwrap_err on Ok: {self._value}")

    def unwrap_or(self, default: T) -> T:
        if self._is_ok:
            return self._value
        return default

    def map(self, func: Callable[[T], Any]) -> 'MockResult':
        if self._is_ok:
            return MockResult.Ok(func(self._value))
        return self

    def _to_python(self) -> Union[T, E]:
        return self._value if self._is_ok else self._error


class MockPrint(BaseMock):
    _original_name = "println!"

    _buffer: List[str] = []

    @classmethod
    def println(cls, *args: Any) -> None:
        output = ' '.join(str(arg) for arg in args)
        cls._buffer.append(output)

    @classmethod
    def print(cls, *args: Any) -> None:
        output = ' '.join(str(arg) for arg in args)
        cls._buffer.append(output)

    @classmethod
    def eprintln(cls, *args: Any) -> None:
        output = ' '.join(str(arg) for arg in args)
        cls._buffer.append(output)

    @classmethod
    def get_buffer(cls) -> List[str]:
        return cls._buffer.copy()

    @classmethod
    def clear_buffer(cls) -> None:
        cls._buffer.clear()


class MockConsole(BaseMock):
    _original_name = "System.Console"

    _buffer: List[str] = []

    @classmethod
    def Write(cls, *args: Any) -> None:
        output = ''.join(str(arg) for arg in args)
        cls._buffer.append(output)

    @classmethod
    def WriteLine(cls, *args: Any) -> None:
        output = ''.join(str(arg) for arg in args)
        cls._buffer.append(output + '\n')

    @classmethod
    def ReadLine(cls) -> str:
        if cls._buffer:
            return cls._buffer.pop(0)
        return ''

    @classmethod
    def get_buffer(cls) -> List[str]:
        return cls._buffer.copy()

    @classmethod
    def clear_buffer(cls) -> None:
        cls._buffer.clear()


class MockString(BaseMock):
    _original_name = "System.String"

    def __init__(self, value: str = ""):
        self._value = value
        self._original_name = "System.String"

    @staticmethod
    def Concat(*args: str) -> str:
        return ''.join(str(arg) for arg in args)

    @staticmethod
    def Format(format_str: str, *args: Any) -> str:
        result = format_str
        for i, arg in enumerate(args):
            result = result.replace('{' + str(i) + '}', str(arg))
        return result

    def Contains(self, substr: str) -> bool:
        return substr in self._value

    def StartsWith(self, prefix: str) -> bool:
        return self._value.startswith(prefix)

    def EndsWith(self, suffix: str) -> bool:
        return self._value.endswith(suffix)

    def IndexOf(self, substr: str) -> int:
        return self._value.find(substr)

    def LastIndexOf(self, substr: str) -> int:
        return self._value.rfind(substr)

    def ToLower(self) -> str:
        return self._value.lower()

    def ToUpper(self) -> str:
        return self._value.upper()

    def Trim(self) -> str:
        return self._value.strip()

    def Split(self, separator: str) -> List[str]:
        return self._value.split(separator)

    def Substring(self, start: int, length: int = -1) -> str:
        if length == -1:
            return self._value[start:]
        return self._value[start:start + length]

    def Replace(self, old: str, new: str) -> str:
        return self._value.replace(old, new)

    def __str__(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return f"MockString('{self._value}')"

    def _to_python(self) -> str:
        return self._value

    @classmethod
    def _from_python(cls, value: Any) -> 'MockString':
        return cls(str(value))


class MockList(BaseMock, Generic[T]):
    _original_name = "System.Collections.Generic.List"

    def __init__(self, data: Optional[List[T]] = None):
        self._data = data if data is not None else []
        self._original_name = "System.Collections.Generic.List"

    def Add(self, item: T) -> None:
        self._data.append(item)

    def AddRange(self, items: List[T]) -> None:
        self._data.extend(items)

    def Remove(self, item: T) -> bool:
        if item in self._data:
            self._data.remove(item)
            return True
        return False

    def RemoveAt(self, index: int) -> None:
        if 0 <= index < len(self._data):
            self._data.pop(index)

    def Insert(self, index: int, item: T) -> None:
        self._data.insert(index, item)

    def Clear(self) -> None:
        self._data.clear()

    def Contains(self, item: T) -> bool:
        return item in self._data

    def IndexOf(self, item: T) -> int:
        return self._data.index(item) if item in self._data else -1

    def Count(self) -> int:
        return len(self._data)

    def Capacity(self) -> int:
        return len(self._data)

    def GetRange(self, index: int, count: int) -> 'MockList[T]':
        return MockList(self._data[index:index + count])

    def __getitem__(self, index: int) -> T:
        return self._data[index]

    def __setitem__(self, index: int, value: T) -> None:
        self._data[index] = value

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def _to_python(self) -> List[T]:
        return self._data

    @classmethod
    def _from_python(cls, value: Any) -> 'MockList':
        return cls(list(value))


class MockDictionary(BaseMock, Generic[K, V]):
    _original_name = "System.Collections.Generic.Dictionary"

    def __init__(self, data: Optional[Dict[K, V]] = None):
        self._data = data if data is not None else {}
        self._original_name = "System.Collections.Generic.Dictionary"

    def Add(self, key: K, value: V) -> None:
        self._data[key] = value

    def Remove(self, key: K) -> bool:
        if key in self._data:
            del self._data[key]
            return True
        return False

    def ContainsKey(self, key: K) -> bool:
        return key in self._data

    def ContainsValue(self, value: V) -> bool:
        return value in self._data.values()

    def TryGetValue(self, key: K) -> Optional[V]:
        return self._data.get(key)

    def Clear(self) -> None:
        self._data.clear()

    def Count(self) -> int:
        return len(self._data)

    def Keys(self) -> List[K]:
        return list(self._data.keys())

    def Values(self) -> List[V]:
        return list(self._data.values())

    def __getitem__(self, key: K) -> V:
        return self._data[key]

    def __setitem__(self, key: K, value: V) -> None:
        self._data[key] = value

    def __contains__(self, key: K) -> bool:
        return key in self._data

    def __len__(self) -> int:
        return len(self._data)

    def __iter__(self):
        return iter(self._data)

    def _to_python(self) -> Dict[K, V]:
        return self._data

    @classmethod
    def _from_python(cls, value: Any) -> 'MockDictionary':
        return cls(dict(value))


def setup_python_module_mocks(language: str) -> Dict[str, Any]:
    if language.lower() in ["cpp", "c++"]:
        return {
            "std::string": MockStdString,
            "std::vector": MockStdVector,
            "std::map": MockStdMap,
            "std::cout": MockStdcout,
            "std::cerr": MockStdcerr,
        }
    elif language.lower() in ["go", "golang"]:
        return {
            "fmt": MockFmt,
            "fmt.Println": MockFmt.println,
            "fmt.Print": MockFmt.Print,
            "fmt.Sprintf": MockFmt.Sprintf,
            "strconv": MockStrconv,
            "strings": MockStrings,
            "io": MockIo,
            "io.Reader": MockIo.Reader,
            "io.Writer": MockIo.Writer,
            "os": MockOs,
            "os.Open": MockOs.Open,
            "os.Create": MockOs.Create,
            "os.File": MockOs.File,
        }
    elif language.lower() == "rust":
        return {
            "Vec": MockVec,
            "HashMap": MockHashMap,
            "Option": MockOption,
            "Option::Some": MockOption.Some,
            "Option::None": MockOption.None,
            "Result": MockResult,
            "Result::Ok": MockResult.Ok,
            "Result::Err": MockResult.Err,
            "println": MockPrint.println,
            "print": MockPrint.print,
        }
    elif language.lower() in ["csharp", "c#", "dotnet", ".net"]:
        return {
            "System.Console": MockConsole,
            "System.Console.Write": MockConsole.Write,
            "System.Console.WriteLine": MockConsole.WriteLine,
            "System.String": MockString,
            "System.Collections.Generic.List": MockList,
            "System.Collections.Generic.Dictionary": MockDictionary,
        }
    return {}


MockRegistry.register("cpp", MockStdString)
MockRegistry.register("cpp", MockStdVector)
MockRegistry.register("cpp", MockStdMap)
MockRegistry.register("cpp", MockStdcout)
MockRegistry.register("cpp", MockStdcerr)

MockRegistry.register("go", MockFmt)
MockRegistry.register("go", MockStrconv)
MockRegistry.register("go", MockStrings)
MockRegistry.register("go", MockIo)
MockRegistry.register("go", MockOs)

MockRegistry.register("rust", MockVec)
MockRegistry.register("rust", MockHashMap)
MockRegistry.register("rust", MockOption)
MockRegistry.register("rust", MockResult)
MockRegistry.register("rust", MockPrint)

MockRegistry.register("csharp", MockConsole)
MockRegistry.register("csharp", MockString)
MockRegistry.register("csharp", MockList)
MockRegistry.register("csharp", MockDictionary)
