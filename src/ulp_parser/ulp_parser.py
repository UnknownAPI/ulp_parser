import ctypes
from abc import ABC, abstractmethod
from ctypes import POINTER, Structure, c_char_p, c_int
from dataclasses import dataclass


class ULPResult(Structure):
    _fields_ = [
        ("url", c_char_p),
        ("login", c_char_p),
        ("password", c_char_p),
        ("success", c_int),
    ]


class ULPResultArray(Structure):
    _fields_ = [("results", POINTER(ULPResult)), ("count", c_int), ("capacity", c_int)]


@dataclass(slots=True)
class Credentials:
    login: str | None
    password: str | None


class Parser(ABC):
    @abstractmethod
    def parse(self, input_string: str) -> Credentials:
        pass

    def parse_file(self, filename: str) -> list[Credentials]:
        with open(filename) as f:
            return [self.parse(line) for line in f]


@dataclass(slots=True)
class ParsedULP(Credentials):
    url: str | None
    success: bool = False


class ULPParser(Parser):
    def __init__(self, format_string: str):
        self.lib = ctypes.CDLL("./parser.dll")
        self.format_string = format_string
        self._setup_functions()

    def _setup_functions(self):
        # Single parse
        self.lib.parse_ulp_alloc.argtypes = [c_char_p, c_char_p]
        self.lib.parse_ulp_alloc.restype = POINTER(ULPResult)
        self.lib.free_ulp_result_ptr.argtypes = [POINTER(ULPResult)]
        self.lib.free_ulp_result_ptr.restype = None

        # File parse
        self.lib.parse_ulp_from_file.argtypes = [c_char_p, c_char_p]
        self.lib.parse_ulp_from_file.restype = POINTER(ULPResultArray)
        self.lib.free_ulp_result_array_ptr.argtypes = [POINTER(ULPResultArray)]
        self.lib.free_ulp_result_array_ptr.restype = None
        self.lib.get_array_count.argtypes = [POINTER(ULPResultArray)]
        self.lib.get_array_count.restype = c_int
        self.lib.get_array_element.argtypes = [POINTER(ULPResultArray), c_int]
        self.lib.get_array_element.restype = POINTER(ULPResult)

    def parse(self, input_string: str) -> ParsedULP:
        input_bytes = input_string.encode("utf-8")
        format_bytes = self.format_string.encode("utf-8")
        result_ptr = self.lib.parse_ulp_alloc(input_bytes, format_bytes)

        if not result_ptr:
            return ParsedULP(url=None, login=None, password=None, success=False)

        try:
            result = result_ptr.contents
            return ParsedULP(
                result.url.decode("utf-8", errors="ignore") if result.url else None,
                result.login.decode("utf-8", errors="ignore") if result.login else None,
                result.password.decode("utf-8", errors="ignore") if result.password else None,
                bool(result.success),
            )
        finally:
            self.lib.free_ulp_result_ptr(result_ptr)

    def parse_file(self, filename: str) -> list[Credentials]:
        filename_bytes = filename.encode("utf-8")
        format_bytes = self.format_string.encode("utf-8")
        array_ptr = self.lib.parse_ulp_from_file(filename_bytes, format_bytes)

        if not array_ptr:
            return []

        try:
            results = []
            count = self.lib.get_array_count(array_ptr)

            for i in range(count):
                element_ptr = self.lib.get_array_element(array_ptr, i)
                if element_ptr:
                    result = element_ptr.contents
                    results.append(
                        ParsedULP(
                            url=result.url.decode("utf-8", errors="ignore") if result.url else None,
                            login=result.login.decode("utf-8", errors="ignore") if result.login else None,
                            password=result.password.decode("utf-8", errors="ignore") if result.password else None,
                            success=bool(result.success),
                        )
                    )
            return results
        finally:
            self.lib.free_ulp_result_array_ptr(array_ptr)


class ComboParser(Parser):
    def parse(self, input_string: str) -> Credentials:
        split = input_string.strip().split(":")
        if len(split) != 2:
            return Credentials(login=None, password=None)
        return Credentials(login=split[0], password=split[1])
