import ctypes
from ctypes import POINTER, Structure, c_char_p, c_int
from typing import NamedTuple


class ULPResult(Structure):
    _fields_ = [
        ("url", c_char_p),
        ("login", c_char_p),
        ("password", c_char_p),
        ("success", c_int),
    ]


class ULPResultArray(Structure):
    """C structure representation for ULPResultArray"""

    _fields_ = [("results", POINTER(ULPResult)), ("count", c_int), ("capacity", c_int)]


class ULPStats(Structure):
    """C structure representation for ULPStats"""

    _fields_ = [("total_lines", c_int), ("successful_parses", c_int), ("failed_parses", c_int), ("empty_lines", c_int)]


class ParsedULP(NamedTuple):
    """Python-friendly result container"""

    url: str | None
    login: str | None
    password: str | None
    success: bool


class ParsedULPStats(NamedTuple):
    """Python-friendly stats container"""

    total_lines: int
    successful_parses: int
    failed_parses: int
    empty_lines: int


class ULPParser:
    """Python wrapper for the ULP parser C library"""

    def __init__(self):
        """
        Initialize the parser with the path to the compiled C library.

        Args:
            lib_path: Path to the compiled shared library

        """
        self.lib = ctypes.CDLL("./log_parser_batch.dll")
        self._setup_functions()

    def _setup_functions(self):
        """Set up function signatures for ctypes"""
        # Single parse functions
        self.lib.parse_ulp_alloc.argtypes = [c_char_p, c_char_p]
        self.lib.parse_ulp_alloc.restype = POINTER(ULPResult)

        self.lib.free_ulp_result_ptr.argtypes = [POINTER(ULPResult)]
        self.lib.free_ulp_result_ptr.restype = None

        # Batch parse functions
        self.lib.parse_ulp_file.argtypes = [c_char_p, c_char_p]
        self.lib.parse_ulp_file.restype = POINTER(ULPResultArray)

        self.lib.parse_ulp_from_file.argtypes = [c_char_p, c_char_p]
        self.lib.parse_ulp_from_file.restype = POINTER(ULPResultArray)

        self.lib.free_ulp_result_array_ptr.argtypes = [POINTER(ULPResultArray)]
        self.lib.free_ulp_result_array_ptr.restype = None

        self.lib.get_array_count.argtypes = [POINTER(ULPResultArray)]
        self.lib.get_array_count.restype = c_int

        self.lib.get_array_element.argtypes = [POINTER(ULPResultArray), c_int]
        self.lib.get_array_element.restype = POINTER(ULPResult)

        self.lib.get_ulp_stats.argtypes = [POINTER(ULPResultArray), c_char_p]
        self.lib.get_ulp_stats.restype = ULPStats

    def parse(self, input_string: str, format_string: str) -> ParsedULP:
        """
        Parse a ULP log entry.

        Args:
            input_string: The log entry to parse (e.g., "https://site.com:user:pass")
            format_string: Format specification (e.g., "u:l:p", "l,p,u")
                          - u = URL, l = login, p = password
                          - Characters between letters specify the separator

        Returns:
            ParsedULP object with url, login, password fields and success flag

        """
        # Convert strings to bytes for C
        input_bytes = input_string.encode("utf-8")
        format_bytes = format_string.encode("utf-8")

        # Call C function
        result_ptr = self.lib.parse_ulp_alloc(input_bytes, format_bytes)

        if not result_ptr:
            return ParsedULP(None, None, None, False)

        try:
            result = result_ptr.contents

            url = result.url.decode("utf-8", errors="ignore") if result.url else None
            login = result.login.decode("utf-8", errors="ignore") if result.login else None
            password = result.password.decode("utf-8", errors="ignore") if result.password else None
            success = bool(result.success)

            return ParsedULP(url, login, password, success)

        finally:
            # Always free the allocated memory
            self.lib.free_ulp_result_ptr(result_ptr)

    def parse_file_content(self, content: str, format_string: str) -> list[ParsedULP]:
        """
        Parse ULP entries from file content string.

        Args:
            content: File content as string (with newlines)
            format_string: Format specification (e.g., "u:l:p", "l,p,u")

        Returns:
            List of ParsedULP objects

        """
        content_bytes = content.encode("utf-8")
        format_bytes = format_string.encode("utf-8")

        array_ptr = self.lib.parse_ulp_file(content_bytes, format_bytes)

        if not array_ptr:
            return []

        try:
            results = []
            count = self.lib.get_array_count(array_ptr)

            for i in range(count):
                element_ptr = self.lib.get_array_element(array_ptr, i)
                if element_ptr:
                    result = element_ptr.contents

                    url = result.url.decode("utf-8", errors="ignore") if result.url else None
                    login = result.login.decode("utf-8", errors="ignore") if result.login else None
                    password = result.password.decode("utf-8", errors="ignore") if result.password else None
                    success = bool(result.success)

                    results.append(ParsedULP(url, login, password, success))

            return results

        finally:
            self.lib.free_ulp_result_array_ptr(array_ptr)

    def parse_file(self, filename: str, format_string: str) -> list[ParsedULP]:
        """
        Parse ULP entries from a file.

        Args:
            filename: Path to the file to parse
            format_string: Format specification (e.g., "u:l:p", "l,p,u")

        Returns:
            List of ParsedULP objects

        """
        filename_bytes = filename.encode("utf-8")
        format_bytes = format_string.encode("utf-8")

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

                    url = result.url.decode("utf-8", errors="ignore") if result.url else None
                    login = result.login.decode("utf-8", errors="ignore") if result.login else None
                    password = result.password.decode("utf-8", errors="ignore") if result.password else None
                    success = bool(result.success)

                    results.append(ParsedULP(url, login, password, success))

            return results

        finally:
            self.lib.free_ulp_result_array_ptr(array_ptr)

    def get_stats(self, content: str, format_string: str) -> ParsedULPStats:
        """
        Get parsing statistics for content.

        Args:
            content: File content as string
            format_string: Format specification

        Returns:
            ParsedULPStats with parsing statistics

        """
        content_bytes = content.encode("utf-8")
        format_bytes = format_string.encode("utf-8")

        array_ptr = self.lib.parse_ulp_file(content_bytes, format_bytes)

        if not array_ptr:
            return ParsedULPStats(0, 0, 0, 0)

        try:
            stats = self.lib.get_ulp_stats(array_ptr, content_bytes)
            return ParsedULPStats(
                total_lines=stats.total_lines,
                successful_parses=stats.successful_parses,
                failed_parses=stats.failed_parses,
                empty_lines=stats.empty_lines,
            )
        finally:
            self.lib.free_ulp_result_array_ptr(array_ptr)
