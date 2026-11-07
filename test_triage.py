"""The target triage: what a file is, and what can be done with it.

None of this needs Ghidra, Kuna, x64dbg or a network: the triage reads the
bytes of a file and names them. The fixtures are written by hand - a minimal
PE header, a minimal ELF header, a binary Android manifest - so that a test
proves the parser and not the fixture generator.
"""

import gzip
import hashlib
import json
import os
import plistlib
import struct
import sys
import tempfile
import unittest
import zipfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ghydra import triage


# --------------------------------------------------------------- PE fixtures


def _pe_bytes(
    machine=0x8664,
    subsystem=3,
    is_dll=False,
    dotnet=False,
    with_imports=True,
    with_resources=True,
):
    """A minimal PE: a DOS stub, the COFF header, one section, the imports."""
    e_lfanew = 0x80
    opt_size = 0xF0
    file_size = 0x800
    data = bytearray(file_size)

    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, e_lfanew)

    characteristics = 0x0022 | (0x2000 if is_dll else 0)
    struct.pack_into(
        "<4sHHIIIHH",
        data,
        e_lfanew,
        b"PE\x00\x00",
        machine,
        1,
        1600000000,
        0,
        0,
        opt_size,
        characteristics,
    )

    directories = [(0, 0)] * 16
    if with_imports:
        directories[1] = (0x1100, 40)
    if with_resources:
        directories[2] = (0x1200, 0x100)
    if dotnet:
        directories[14] = (0x1400, 0x48)

    optional = struct.pack(
        "<HBBIIIIIQIIHHHHHHIIIIHHQQQQII",
        0x20B,
        14,
        0,
        0x200,
        0x200,
        0,
        0x1000,
        0x1000,
        0x140000000,
        0x1000,
        0x200,
        6,
        0,
        0,
        0,
        6,
        0,
        0,
        0x2000,
        0x400,
        0,
        subsystem,
        0x8160,
        0x100000,
        0x1000,
        0x100000,
        0x1000,
        0,
        16,
    )
    assert len(optional) == 112, len(optional)
    for index, (rva, size) in enumerate(directories):
        optional += struct.pack("<II", rva, size)
    assert len(optional) == opt_size, len(optional)
    data[e_lfanew + 24 : e_lfanew + 24 + opt_size] = optional

    section = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        0x1000,
        0x1000,
        0x600,
        0x200,
        0,
        0,
        0,
        0,
        0x60000020,
    )
    data[e_lfanew + 24 + opt_size : e_lfanew + 24 + opt_size + 40] = section

    if with_imports:
        # The import descriptor, its terminator, the name of the library, the
        # thunk array and the two names it points at.
        descriptor = struct.pack("<IIIII", 0x1138, 0, 0, 0x1128, 0x1138)
        data[0x300:0x314] = descriptor
        data[0x314:0x328] = b"\x00" * 20
        data[0x328:0x335] = b"kernel32.dll\x00"
        data[0x338:0x350] = struct.pack("<QQQ", 0x1150, 0x1160, 0)
        data[0x350:0x35E] = struct.pack("<H", 0) + b"CreateFileW\x00"
        data[0x360:0x36B] = struct.pack("<H", 0) + b"ReadFile\x00"

    if with_resources:
        struct.pack_into("<IIHHHH", data, 0x400, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", data, 0x410, 16, 0x80000000 | 0x20)
        struct.pack_into("<IIHHHH", data, 0x420, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", data, 0x430, 1, 0x80000000 | 0x40)
        struct.pack_into("<IIHHHH", data, 0x440, 0, 0, 0, 0, 0, 1)
        struct.pack_into("<II", data, 0x450, 0x0409, 0x60)
        struct.pack_into("<IIII", data, 0x460, 0x1300, 52, 0, 0)
        data[0x500:0x534] = b"VS_VERSION_INFO" + b"\x00" * 37

    if dotnet:
        struct.pack_into("<IHHII", data, 0x600, 0x48, 2, 5, 0x1500, 0x50)
        data[0x700:0x704] = b"BSJB"
        struct.pack_into("<HHI", data, 0x704, 1, 0, 0)
        version = b"v4.0.30319\x00\x00"
        struct.pack_into("<I", data, 0x70C, len(version))
        data[0x710 : 0x710 + len(version)] = version

    assert len(data) == file_size, "a slice grew the fixture: %d" % len(data)
    return bytes(data)


# -------------------------------------------------------------- ELF fixtures


def _elf_bytes(etype=2):
    """A minimal 64-bit little-endian ELF with an interpreter and two libraries."""
    data = bytearray(0x400)
    data[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    struct.pack_into(
        "<HHIQQQ",
        data,
        0x10,
        etype,
        0x3E,
        1,
        0x1000,
        0x40,
        0x100,
    )
    struct.pack_into("<IHHHHHH", data, 0x30, 0, 0x40, 0x38, 3, 0x40, 4, 3)

    interp = b"/lib64/ld-linux-x86-64.so.2\x00"
    struct.pack_into("<IIQQQQQQ", data, 0x40, 3, 4, 0x200, 0x200, 0x200, len(interp), len(interp), 4)
    struct.pack_into("<IIQQQQQQ", data, 0x78, 1, 5, 0x200, 0x2000, 0x2000, 0x400, 0x1000, 5)
    struct.pack_into("<IIQQQQQQ", data, 0xB0, 2, 6, 0x220, 0x2020, 0x2020, 64, 64, 6)
    data[0x200 : 0x200 + len(interp)] = interp

    dynamic = struct.pack("<qQ", 1, 1)
    dynamic += struct.pack("<qQ", 1, 11)
    dynamic += struct.pack("<qQ", 5, 0x2060)
    dynamic += struct.pack("<qQ", 10, 21)
    dynamic += struct.pack("<qQ", 0, 0)
    data[0x220 : 0x220 + len(dynamic)] = dynamic

    strtab = b"\x00libc.so.6\x00libm.so.6\x00"
    data[0x260 : 0x260 + len(strtab)] = strtab

    names = b"\x00.interp\x00.dynamic\x00.shstrtab\x00"
    data[0x300 : 0x300 + len(names)] = names
    headers = [
        (0, 0, 0, 0, 0, 0),
        (1, 1, 3, 0x200, 0x200, len(interp)),
        (9, 1, 3, 0x220, 0x220, 64),
        (18, 3, 0, 0, 0x300, len(names)),
    ]
    for index, (name, stype, flags, addr, offset, size) in enumerate(headers):
        struct.pack_into(
            "<IIQQQQIIQQ",
            data,
            0x100 + index * 64,
            name,
            stype,
            flags,
            addr,
            offset,
            size,
            0,
            0,
            1,
            0,
        )
    return bytes(data)


def _core_elf_bytes():
    """An ELF core dump with one NT_PRSTATUS note."""
    registers = [0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666]
    registers += [0x7777, 0x8888, 0x9999, 0xAAAA, 0xBBBB, 0xCCCC]
    registers += [0xDDDD, 0xEEEE, 0xFFFF, 0x1000, 0xDEAD]
    registers += [0] * (27 - len(registers))
    # The 64-bit prstatus: the signal, the cursig, the pending signals, the
    # identifiers, the four times (a timeval is two longs) and the registers.
    status = struct.pack("<iii", 11, 1, 0)
    status += struct.pack("<HH", 11, 0)
    status += struct.pack("<qq", 0, 0)
    status += struct.pack("<iii", 4242, 1, 4242)
    status += struct.pack("<i", 4242)
    for _ in range(4):
        status += struct.pack("<qq", 0, 0)
    for value in registers:
        status += struct.pack("<Q", value)
    assert len(status) == 328, len(status)

    note = struct.pack("<III", 4, len(status), 1)
    note += b"CORE" + b"\x00" * 0
    note += status

    data = bytearray(0x400)
    data[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    struct.pack_into("<HHIQQQ", data, 0x10, 4, 0x3E, 1, 0, 0x40, 0)
    struct.pack_into("<IHHHHHH", data, 0x30, 0, 0x40, 0x38, 1, 0x40, 0, 0)
    struct.pack_into("<IIQQQQQQ", data, 0x40, 4, 0, 0x200, 0x200, 0x200, len(note), len(note), 0)
    data[0x200 : 0x200 + len(note)] = note
    return bytes(data)


def _minidump_bytes():
    """A Windows minidump with two streams."""
    streams = [(6, 168), (7, 56)]
    directory_size = len(streams) * 12
    header = struct.pack("<IIIIII", 0x504D444D, 0xA793, len(streams), 32, 0, 1600000000)
    header += struct.pack("<Q", 0)
    data = bytearray(header + b"\x00" * directory_size)
    for index, (stream_type, size) in enumerate(streams):
        struct.pack_into("<III", data, 32 + index * 12, stream_type, size, 64 + index * 64)
    data += b"\x00" * 64
    return bytes(data)


# ------------------------------------------------------------ Mach-O fixture


def _macho_bytes():
    """A minimal 64-bit little-endian Mach-O with one segment."""
    data = bytearray(0x100)
    data[0:4] = b"\xcf\xfa\xed\xfe"
    struct.pack_into("<IIIIIII", data, 4, 0x01000007, 3, 2, 1, 72, 0, 0)
    struct.pack_into("<I", data, 28, 0)
    struct.pack_into("<II", data, 32, 0x19, 72)
    data[40:56] = b"__TEXT".ljust(16, b"\x00")
    struct.pack_into("<QQQQ", data, 56, 0x100000000, 0x1000, 0, 0x1000)
    struct.pack_into("<IIII", data, 88, 7, 5, 0, 0)
    return bytes(data)


# -------------------------------------------------------------- DEX fixture


def _dex_bytes():
    """A minimal DEX header."""
    data = bytearray(112)
    data[0:8] = b"dex\n035\x00"
    struct.pack_into("<I", data, 8, 0xDEADBEEF)
    struct.pack_into("<I", data, 32, 112)
    struct.pack_into("<I", data, 36, 0x70)
    struct.pack_into("<I", data, 40, 0x12345678)
    struct.pack_into("<IIII", data, 56, 10, 0, 5, 0)
    struct.pack_into("<IIII", data, 72, 3, 0, 2, 0)
    struct.pack_into("<IIII", data, 88, 7, 0, 4, 0)
    struct.pack_into("<II", data, 104, 0, 0)
    return bytes(data)


# -------------------------------------------------------------- WASM fixture


def _uleb(value):
    """An unsigned LEB128 number."""
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        if value:
            out.append(byte | 0x80)
        else:
            out.append(byte)
            return bytes(out)


def _wasm_bytes():
    """A minimal WASM module with a custom, an import, a function, a memory and an export."""
    custom = _uleb(len(b"sourceMappingURL")) + b"sourceMappingURL"
    imports = _uleb(1) + _uleb(3) + b"env" + _uleb(3) + b"foo" + b"\x00" + _uleb(0)
    functions = _uleb(2)
    memory = _uleb(1) + b"\x00" + _uleb(1)
    exports = _uleb(1) + _uleb(3) + b"run" + b"\x00" + _uleb(0)
    data = b"\x00asm" + struct.pack("<I", 1)
    for section_id, payload in (
        (0, custom),
        (2, imports),
        (3, functions),
        (5, memory),
        (7, exports),
    ):
        data += bytes([section_id]) + _uleb(len(payload)) + payload
    return data


# --------------------------------------------------------------- EVM fixture


def _evm_bytes(selector=0xA9059CBB, creation=True):
    """An EVM contract with one dispatcher entry."""
    code = b"\x60\x80\x60\x40"
    if creation:
        code += b"\x52"
    code += b"\x63" + struct.pack(">I", selector)
    code += b"\x14\x61\x00\xf3\x57\x00"
    return code


# --------------------------------------------------------- Android manifest


def _axml_bytes(elements):
    """A binary Android manifest: a string pool and the elements."""
    strings = []
    index = {}

    def add(text):
        if text not in index:
            index[text] = len(strings)
            strings.append(text)
        return index[text]

    encoded = []
    for tag, attributes in elements:
        tag_index = add(tag)
        items = []
        for name, value in attributes:
            name_index = add(name)
            if isinstance(value, int):
                items.append((name_index, 0xFFFFFFFF, 0x10, value))
            else:
                value_index = add(value)
                items.append((name_index, value_index, 0x03, value_index))
        encoded.append((tag_index, items))

    offsets = []
    body = bytearray()
    for text in strings:
        offsets.append(len(body))
        encoded_text = text.encode("utf-16-le")
        # A string of the pool: the number of characters, the number of
        # bytes, the bytes themselves and the terminator.
        body += struct.pack("<HH", len(text), len(encoded_text))
        body += encoded_text + b"\x00\x00"
    while len(body) % 4:
        body += b"\x00"
    strings_start = 28 + 4 * len(offsets)
    pool = bytearray()
    pool += struct.pack("<HH", 0x0001, 28)
    pool += struct.pack("<I", 0)  # chunk size, patched below
    pool += struct.pack("<IIIII", len(strings), 0, 0, strings_start, 0)
    for offset in offsets:
        pool += struct.pack("<I", offset)
    pool += body
    struct.pack_into("<I", pool, 4, len(pool))

    tree = bytearray()
    for tag_index, items in encoded:
        chunk = bytearray()
        chunk += struct.pack("<HHI", 0x0102, 16, 0)
        chunk += struct.pack("<II", 1, 0xFFFFFFFF)
        chunk += struct.pack("<II", 0xFFFFFFFF, tag_index)
        chunk += struct.pack("<HHH", 20, 20, len(items))
        chunk += struct.pack("<HHH", 0, 0, 0)
        for name_index, raw_index, data_type, value in items:
            chunk += struct.pack("<III", 0xFFFFFFFF, name_index, raw_index)
            chunk += struct.pack("<HBB I", 8, 0, data_type, value)
        struct.pack_into("<I", chunk, 4, len(chunk))
        tree += chunk
        end = bytearray()
        end += struct.pack("<HHI", 0x0103, 16, 24)
        end += struct.pack("<II", 1, 0xFFFFFFFF)
        end += struct.pack("<II", 0xFFFFFFFF, tag_index)
        tree += end

    header = struct.pack("<HHI", 0x0003, 8, 8 + len(pool) + len(tree))
    return bytes(header + pool + tree)


# ---------------------------------------------------------------- ZIP / APK


def _zip_bytes(entries, path):
    """A ZIP holding the given entries."""
    with zipfile.ZipFile(path, "w") as archive:
        for name, payload in entries:
            archive.writestr(name, payload)
    return path


# -------------------------------------------------------------------- asar


def _asar_bytes(files, path):
    """An asar archive: a pickle header, a JSON header and the files."""
    header = {"files": {}}
    offset = 0
    for name, payload in files:
        header["files"][name] = {"size": len(payload), "offset": str(offset)}
        offset += len(payload)
    raw = json.dumps(header).encode("utf-8")
    padding = (4 - len(raw) % 4) % 4
    json_size = len(raw) + padding
    prefix = struct.pack("<IIII", 4, 8 + json_size, 4 + json_size, json_size)
    body = raw + b"\x00" * padding
    base = 8 + (8 + json_size)
    with open(path, "wb") as handle:
        handle.write(prefix + body)
        for _name, payload in files:
            handle.write(payload)
    assert base == 16 + json_size
    return path


# ------------------------------------------------------------------- others


def _uimage_bytes(name=b"myimage", size=64):
    """A uImage firmware header."""
    header = struct.pack(
        ">IIIIIII",
        0x27051956,
        0,
        1600000000,
        size,
        0x80008000,
        0x80008000,
        0,
    )
    header += struct.pack(">BBBB", 1, 2, 2, 1)
    header += name.ljust(32, b"\x00")
    return header


def _squashfs_bytes():
    """A squashfs superblock."""
    data = bytearray(96)
    data[0:4] = b"hsqs"
    struct.pack_into("<I", data, 4, 100)
    struct.pack_into("<I", data, 8, 1600000000)
    struct.pack_into("<I", data, 12, 131072)
    struct.pack_into("<I", data, 16, 1)
    struct.pack_into("<H", data, 20, 1)  # compression: gzip
    struct.pack_into("<H", data, 22, 17)  # block log
    struct.pack_into("<I", data, 24, 0)  # flags
    struct.pack_into("<H", data, 28, 2)  # the number of ids
    struct.pack_into("<H", data, 30, 4)  # the major version
    struct.pack_into("<H", data, 32, 0)  # the minor version
    return bytes(data)


def _class_bytes(major=52):
    """A Java class file with one UTF-8 constant and one class constant."""
    data = bytearray()
    data += b"\xca\xfe\xba\xbe"
    data += struct.pack(">HHH", 0, major, 3)
    data += b"\x01" + struct.pack(">H", 5) + b"Hello"
    data += b"\x07" + struct.pack(">H", 2)
    # The access flags, the class, the super class, and the three counts.
    data += struct.pack(">HHHHHH", 0x0021, 2, 0, 0, 0, 1)
    return bytes(data)


def _sqlite_bytes():
    """A SQLite header."""
    data = bytearray(100)
    data[0:16] = b"SQLite format 3\x00"
    struct.pack_into(">H", data, 16, 4096)
    struct.pack_into(">I", data, 28, 3)
    struct.pack_into(">I", data, 56, 1)
    return bytes(data)


def _har_dict():
    """A small HTTP archive."""
    return {
        "log": {
            "version": "1.2",
            "creator": {"name": "triage-test", "version": "1.0"},
            "pages": [{"title": "Example"}],
            "entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://example.test/one",
                        "headers": [{"name": "Accept", "value": "*/*"}],
                    },
                    "response": {
                        "status": 200,
                        "bodySize": 120,
                        "content": {"size": 120, "mimeType": "text/html"},
                    },
                    "time": 12.5,
                },
                {
                    "request": {
                        "method": "POST",
                        "url": "https://example.test/two",
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                    },
                    "response": {
                        "status": 500,
                        "bodySize": 30,
                        "content": {"size": 30, "mimeType": "application/json"},
                    },
                    "time": 40,
                },
            ],
        }
    }


class TriageFixtureMixin:
    """A temporary directory and the files written into it."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def write(self, name, payload):
        """A file in the temporary directory."""
        path = os.path.join(self.tmp.name, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        mode = "wb" if isinstance(payload, (bytes, bytearray)) else "w"
        with open(path, mode) as handle:
            handle.write(payload)
        return path


class PublicApiTests(TriageFixtureMixin, unittest.TestCase):
    """The shape of the public API."""

    def test_missing_path_raises_triage_error(self):
        """A path that is not there is an error with a code."""
        with self.assertRaises(triage.TriageError) as caught:
            triage.identify(os.path.join(self.tmp.name, "nope.bin"))
        self.assertEqual(caught.exception.code, "TRIAGE_NO_FILE")

    def test_missing_path_raises_on_every_entry_point(self):
        """Every public function refuses a path that is not there."""
        missing = os.path.join(self.tmp.name, "nope.bin")
        for call in (triage.format_of, triage.identify, triage.overview):
            with self.assertRaises(triage.TriageError) as caught:
                call(missing)
            self.assertEqual(caught.exception.code, "TRIAGE_NO_FILE")

    def test_hashes_of_missing_file_raises(self):
        """Hashing a file that is not there is an error too."""
        with self.assertRaises(triage.TriageError) as caught:
            triage.hashes(os.path.join(self.tmp.name, "nope.bin"))
        self.assertEqual(caught.exception.code, "TRIAGE_NO_FILE")

    def test_identify_returns_format_size_and_facts(self):
        """The identification is the format, the size and the facts."""
        path = self.write("a.bin", b"MZ" + b"\x00" * 100)
        result = triage.identify(path)
        self.assertEqual(sorted(result), ["facts", "format", "size"])
        self.assertEqual(result["size"], 102)
        self.assertIsInstance(result["facts"], dict)

    def test_overview_returns_the_full_report(self):
        """The overview carries the hash, the details and the advice."""
        path = self.write("a.bin", b"MZ" + b"\x00" * 100)
        result = triage.overview(path)
        self.assertEqual(
            sorted(result),
            ["details", "facts", "format", "recommendations", "sha256", "size"],
        )
        self.assertEqual(result["sha256"], hashlib.sha256(open(path, "rb").read()).hexdigest())
        self.assertIsInstance(result["recommendations"], list)

    def test_format_of_agrees_with_identify(self):
        """The short call and the long one name the same format."""
        path = self.write("a.bin", b"\x7fELF" + b"\x00" * 60)
        self.assertEqual(triage.format_of(path), triage.identify(path)["format"])

    def test_truncated_file_does_not_raise(self):
        """A file that stops in the middle of its header is described, not refused."""
        path = self.write("short.exe", b"MZ\x90\x00")
        result = triage.identify(path)
        self.assertEqual(result["format"], "pe")
        self.assertEqual(result["facts"], {})

    def test_a_directory_is_a_target_too(self):
        """A path may be a directory, and it is triaged like any other."""
        root = os.path.join(self.tmp.name, "folder")
        os.makedirs(root)
        with open(os.path.join(root, "a.bin"), "wb") as handle:
            handle.write(b"\x00" * 16)
        result = triage.identify(root)
        self.assertEqual(result["size"], 16)
        self.assertIn(result["format"], triage.FORMATS)
        self.assertIn("recommendations", triage.overview(root))

    def test_an_empty_file_is_not_an_error(self):
        """An empty file has no magic, and that is all that is said about it."""
        path = self.write("empty.bin", b"")
        result = triage.identify(path)
        self.assertEqual(result["size"], 0)
        self.assertIn(result["format"], triage.FORMATS)


class EntropyTests(unittest.TestCase):
    """The entropy of a buffer."""

    def test_entropy_of_an_empty_buffer_is_zero(self):
        """Nothing in, nothing out."""
        self.assertEqual(triage.entropy(b""), 0.0)

    def test_entropy_of_an_all_zero_buffer_is_zero(self):
        """One byte repeated carries no information."""
        self.assertEqual(triage.entropy(b"\x00" * 4096), 0.0)

    def test_entropy_of_random_bytes_is_high(self):
        """Bytes that look random carry a lot of information."""
        payload = bytes((index * 97 + 13) % 256 for index in range(4096))
        self.assertGreater(triage.entropy(payload), 7.0)

    def test_entropy_of_two_symbols_is_one_bit(self):
        """Two symbols, evenly spread, are one bit per byte."""
        self.assertAlmostEqual(triage.entropy(b"ab" * 512), 1.0, places=4)

    def test_entropy_is_between_zero_and_eight(self):
        """The measure never leaves its own scale."""
        for payload in (b"", b"\x00", b"\xff" * 100, bytes(range(256))):
            value = triage.entropy(payload)
            self.assertGreaterEqual(value, 0.0)
            self.assertLessEqual(value, 8.0)


class HashTests(TriageFixtureMixin, unittest.TestCase):
    """The hashes of a file."""

    def test_hashes_of_abc_are_the_known_values(self):
        """The digests of b"abc" are the ones in every book."""
        path = self.write("abc.bin", b"abc")
        result = triage.hashes(path)
        self.assertEqual(result["md5"], "900150983cd24fb0d6963f7d28e17f72")
        self.assertEqual(result["sha1"], "a9993e364706816aba3e25717850c26c9cd0d89d")
        self.assertEqual(
            result["sha256"],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        )

    def test_hashes_of_an_empty_file_are_the_empty_digests(self):
        """An empty file has the digests of nothing."""
        path = self.write("empty.bin", b"")
        result = triage.hashes(path)
        self.assertEqual(result["sha256"], hashlib.sha256(b"").hexdigest())

    def test_hashes_are_streamed_over_a_large_file(self):
        """The digests of a big file are the digests of its bytes."""
        payload = os.urandom(200000)
        path = self.write("big.bin", payload)
        self.assertEqual(triage.hashes(path)["sha256"], hashlib.sha256(payload).hexdigest())


class PeTests(TriageFixtureMixin, unittest.TestCase):
    """A Windows PE."""

    def test_pe_is_detected(self):
        """The MZ header and the PE signature name a PE."""
        path = self.write("a.exe", _pe_bytes())
        self.assertEqual(triage.format_of(path), "pe")

    def test_pe_facts_carry_the_machine_and_the_subsystem(self):
        """The COFF header says which machine and which subsystem."""
        path = self.write("a.exe", _pe_bytes(machine=0x8664, subsystem=3))
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["machine_name"], "x86-64")
        self.assertEqual(facts["machine"], 0x8664)
        self.assertEqual(facts["subsystem_name"], "windows-cui")
        self.assertEqual(facts["subsystem"], 3)
        self.assertTrue(facts["is_64bit"])
        self.assertFalse(facts["is_dll"])

    def test_pe_timestamp_is_iso_utc(self):
        """The timestamp of the header is an ISO-8601 moment in UTC."""
        path = self.write("a.exe", _pe_bytes())
        facts = triage.identify(path)["facts"]
        self.assertTrue(facts["timestamp"].endswith("Z"))
        self.assertTrue(facts["timestamp"].startswith("2020-09-13"))

    def test_pe_addresses_are_lowercase_hex(self):
        """The entry point and the image base are hex strings."""
        path = self.write("a.exe", _pe_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["entry_point"], "0x1000")
        self.assertEqual(facts["image_base"], "0x140000000")

    def test_pe_dll_is_flagged(self):
        """The DLL characteristic is in the header."""
        path = self.write("a.dll", _pe_bytes(is_dll=True))
        self.assertTrue(triage.identify(path)["facts"]["is_dll"])

    def test_pe_sections_are_read(self):
        """The section table is read, with the flags of each section."""
        path = self.write("a.exe", _pe_bytes())
        details = triage.overview(path)["details"]
        self.assertEqual(len(details["sections"]), 1)
        section = details["sections"][0]
        self.assertEqual(section["name"], ".text")
        self.assertEqual(section["virtual_address"], "0x1000")
        self.assertTrue(section["executable"])
        self.assertTrue(section["readable"])
        self.assertFalse(section["writable"])

    def test_pe_imports_are_read(self):
        """The import directory gives the library and its functions."""
        path = self.write("a.exe", _pe_bytes())
        details = triage.overview(path)["details"]
        self.assertEqual(len(details["imports"]), 1)
        self.assertEqual(details["imports"][0]["dll"], "kernel32.dll")
        self.assertEqual(details["imports"][0]["functions"], ["CreateFileW", "ReadFile"])
        self.assertFalse(details["imports_truncated"])

    def test_pe_resources_are_parsed(self):
        """The resource directory gives the type, the language and the size."""
        path = self.write("a.exe", _pe_bytes())
        details = triage.overview(path)["details"]
        self.assertEqual(len(details["resources"]), 1)
        resource = details["resources"][0]
        self.assertEqual(resource["type"], "RT_VERSION")
        self.assertEqual(resource["language"], 0x0409)
        self.assertEqual(resource["size"], 52)

    def test_pe_dotnet_is_detected(self):
        """A COM descriptor in the data directory means a managed assembly."""
        path = self.write("a.dll", _pe_bytes(dotnet=True))
        facts = triage.identify(path)["facts"]
        self.assertTrue(facts["is_dotnet"])
        self.assertTrue(facts["data_directories"]["clr"])
        self.assertEqual(facts["dotnet"]["metadata_version"], "v4.0.30319")

    def test_pe_without_dotnet_says_so(self):
        """A native PE has no CLR version."""
        path = self.write("a.exe", _pe_bytes(dotnet=False))
        self.assertFalse(triage.identify(path)["facts"]["is_dotnet"])

    def test_pe_recommends_a_native_decompiler(self):
        """A native PE is worth a report."""
        path = self.write("a.exe", _pe_bytes())
        advice = triage.overview(path)["recommendations"]
        self.assertTrue(any("report build" in line for line in advice))

    def test_dotnet_pe_is_advised_against_a_native_reader(self):
        """A managed assembly is better read by a .NET decompiler."""
        path = self.write("a.dll", _pe_bytes(dotnet=True, is_dll=True))
        advice = triage.overview(path)["recommendations"]
        self.assertTrue(any(".NET decompiler" in line for line in advice))


class ElfTests(TriageFixtureMixin, unittest.TestCase):
    """An ELF binary and an ELF core dump."""

    def test_elf_is_detected(self):
        """The ELF magic names an ELF."""
        path = self.write("a.out", _elf_bytes())
        self.assertEqual(triage.format_of(path), "elf")

    def test_elf_facts_carry_the_class_and_the_machine(self):
        """The header says the class, the endianness and the machine."""
        path = self.write("a.out", _elf_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["class"], 64)
        self.assertEqual(facts["endianness"], "little")
        self.assertEqual(facts["machine_name"], "x86-64")
        self.assertEqual(facts["machine"], 62)
        self.assertEqual(facts["type"], "ET_EXEC")
        self.assertEqual(facts["entry_point"], "0x1000")
        self.assertEqual(facts["program_header_count"], 3)
        self.assertEqual(facts["section_header_count"], 4)

    def test_elf_program_headers_are_read(self):
        """The program headers are read, with their flags."""
        path = self.write("a.out", _elf_bytes())
        details = triage.overview(path)["details"]
        types = [segment["type"] for segment in details["program_headers"]]
        self.assertIn("PT_INTERP", types)
        self.assertIn("PT_DYNAMIC", types)

    def test_elf_section_headers_are_read(self):
        """The section headers are read, with the names resolved."""
        path = self.write("a.out", _elf_bytes())
        details = triage.overview(path)["details"]
        names = [section["name"] for section in details["section_headers"]]
        self.assertIn(".interp", names)
        self.assertIn(".dynamic", names)

    def test_elf_needed_libraries_are_read(self):
        """The dynamic section names the shared libraries."""
        path = self.write("a.out", _elf_bytes())
        details = triage.overview(path)["details"]
        self.assertEqual(details["needed"], ["libc.so.6", "libm.so.6"])

    def test_elf_interpreter_is_read(self):
        """The PT_INTERP segment holds the interpreter path."""
        path = self.write("a.out", _elf_bytes())
        details = triage.overview(path)["details"]
        self.assertEqual(details["interpreter"], "/lib64/ld-linux-x86-64.so.2")

    def test_elf_core_is_detected(self):
        """An ELF of type ET_CORE is a core dump."""
        path = self.write("core", _core_elf_bytes())
        self.assertEqual(triage.format_of(path), "core")

    def test_elf_core_carries_the_signal(self):
        """The NT_PRSTATUS note names the signal and the thread."""
        path = self.write("core", _core_elf_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["signal"], 11)
        self.assertEqual(facts["signal_name"], "SIGSEGV")
        self.assertEqual(facts["thread_id"], 4242)

    def test_elf_core_carries_the_registers(self):
        """The registers of the note are read, in hex."""
        path = self.write("core", _core_elf_bytes())
        registers = triage.identify(path)["facts"]["registers"]
        self.assertEqual(registers["rip"], "0xdead")
        self.assertEqual(registers["rax"], "0xbbbb")


class MinidumpTests(TriageFixtureMixin, unittest.TestCase):
    """A Windows minidump."""

    def test_minidump_is_detected(self):
        """The MDMP signature names a core dump."""
        path = self.write("dump.dmp", _minidump_bytes())
        self.assertEqual(triage.format_of(path), "core")

    def test_minidump_lists_the_streams(self):
        """The stream directory names the streams of the dump."""
        path = self.write("dump.dmp", _minidump_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["core_kind"], "minidump")
        self.assertIn("Exception", facts["streams"])
        self.assertIn("SystemInfo", facts["streams"])


class MachoTests(TriageFixtureMixin, unittest.TestCase):
    """A Mach-O binary."""

    def test_macho_is_detected(self):
        """The Mach-O magic names a Mach-O."""
        path = self.write("a.macho", _macho_bytes())
        self.assertEqual(triage.format_of(path), "mach-o")

    def test_macho_facts_carry_the_cpu_and_the_filetype(self):
        """The header says the CPU, the file type and the load commands."""
        path = self.write("a.macho", _macho_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["bits"], 64)
        self.assertEqual(facts["endianness"], "little")
        self.assertEqual(facts["cputype_name"], "x86-64")
        self.assertEqual(facts["cputype"], 0x01000007)
        self.assertEqual(facts["filetype_name"], "MH_EXECUTE")
        self.assertEqual(facts["filetype"], 2)
        self.assertEqual(facts["load_command_count"], 1)

    def test_macho_segments_are_read(self):
        """The load commands give the segments."""
        path = self.write("a.macho", _macho_bytes())
        segments = triage.overview(path)["details"]["segments"]
        self.assertEqual(segments[0]["name"], "__TEXT")
        self.assertEqual(segments[0]["vmaddr"], "0x100000000")


class DexTests(TriageFixtureMixin, unittest.TestCase):
    """A DEX file."""

    def test_dex_is_detected(self):
        """The dex magic names a DEX."""
        path = self.write("classes.dex", _dex_bytes())
        self.assertEqual(triage.format_of(path), "dex")

    def test_dex_facts_carry_the_counts(self):
        """The header carries the counts of the tables."""
        path = self.write("classes.dex", _dex_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["version"], "035")
        self.assertEqual(facts["header_size"], 0x70)
        self.assertEqual(facts["string_ids_size"], 10)
        self.assertEqual(facts["type_ids_size"], 5)
        self.assertEqual(facts["method_ids_size"], 7)
        self.assertEqual(facts["class_defs_size"], 4)


class ZipAndApkTests(TriageFixtureMixin, unittest.TestCase):
    """A ZIP and an Android package."""

    def test_zip_is_detected(self):
        """A ZIP without a manifest is a plain ZIP."""
        path = _zip_bytes([("a.txt", b"hello"), ("b/c.txt", b"world")], self.write("a.zip", b""))
        self.assertEqual(triage.format_of(path), "zip")

    def test_zip_entries_are_listed(self):
        """The entry list of a ZIP is right."""
        path = _zip_bytes([("a.txt", b"hello"), ("b/c.txt", b"world")], self.write("a.zip", b""))
        details = triage.overview(path)["details"]
        names = [entry["name"] for entry in details["entries"]]
        self.assertEqual(names, ["a.txt", "b/c.txt"])
        self.assertEqual(details["entries"][0]["size"], 5)
        self.assertEqual(triage.identify(path)["facts"]["entry_count"], 2)

    def test_long_lists_are_capped_and_say_so(self):
        """A list longer than the cap is cut, and the cut is said out loud."""
        entries = [("file-%03d.txt" % index, b"x") for index in range(250)]
        path = _zip_bytes(entries, self.write("many.zip", b""))
        details = triage.overview(path)["details"]
        self.assertEqual(len(details["entries"]), 200)
        self.assertTrue(details["entries_truncated"])

    def test_apk_is_detected(self):
        """A ZIP with a manifest is an APK."""
        manifest = _axml_bytes([("manifest", [("package", "com.example.app")])])
        path = _zip_bytes(
            [("AndroidManifest.xml", manifest), ("classes.dex", _dex_bytes())],
            self.write("a.apk", b""),
        )
        self.assertEqual(triage.format_of(path), "apk")

    def test_apk_reads_the_package_and_the_version(self):
        """The manifest gives the package name and the version."""
        manifest = _axml_bytes(
            [
                (
                    "manifest",
                    [
                        ("package", "com.example.app"),
                        ("versionName", "1.2.3"),
                        ("versionCode", 42),
                    ],
                ),
                (
                    "uses-sdk",
                    [("minSdkVersion", 21), ("targetSdkVersion", 33)],
                ),
            ]
        )
        path = _zip_bytes([("AndroidManifest.xml", manifest)], self.write("a.apk", b""))
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["package"], "com.example.app")
        self.assertEqual(facts["version_name"], "1.2.3")
        self.assertEqual(facts["version_code"], 42)
        self.assertEqual(facts["min_sdk"], 21)
        self.assertEqual(facts["target_sdk"], 33)

    def test_apk_permissions_are_extracted(self):
        """The permissions come out of the manifest, and say so."""
        manifest = _axml_bytes(
            [
                ("manifest", [("package", "com.example.app")]),
                ("uses-permission", [("name", "android.permission.INTERNET")]),
                ("uses-permission", [("name", "android.permission.CAMERA")]),
            ]
        )
        path = _zip_bytes([("AndroidManifest.xml", manifest)], self.write("a.apk", b""))
        facts = triage.identify(path)["facts"]
        self.assertEqual(
            facts["permissions_extracted"],
            ["android.permission.INTERNET", "android.permission.CAMERA"],
        )
        self.assertIn("not fully parsed", facts["permissions_note"])

    def test_apk_lists_the_native_libraries(self):
        """The .so files of the package carry their architecture."""
        manifest = _axml_bytes([("manifest", [("package", "com.example.app")])])
        path = _zip_bytes(
            [
                ("AndroidManifest.xml", manifest),
                ("lib/arm64-v8a/libfoo.so", b"\x7fELF"),
                ("classes.dex", _dex_bytes()),
            ],
            self.write("a.apk", b""),
        )
        facts = triage.identify(path)["facts"]
        self.assertEqual(len(facts["native_libraries"]), 1)
        self.assertEqual(facts["native_libraries"][0]["architecture"], "arm64-v8a")
        self.assertEqual(facts["dex_files"], ["classes.dex"])

    def test_apk_lists_the_signature_files(self):
        """The signature files live under META-INF."""
        manifest = _axml_bytes([("manifest", [("package", "com.example.app")])])
        path = _zip_bytes(
            [("AndroidManifest.xml", manifest), ("META-INF/CERT.RSA", b"\x30\x82")],
            self.write("a.apk", b""),
        )
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["signature_files"], ["META-INF/CERT.RSA"])


class WasmTests(TriageFixtureMixin, unittest.TestCase):
    """A WebAssembly module."""

    def test_wasm_is_detected(self):
        """The wasm magic names a WASM module."""
        path = self.write("a.wasm", _wasm_bytes())
        self.assertEqual(triage.format_of(path), "wasm")

    def test_wasm_sections_are_listed(self):
        """The section list names every section."""
        path = self.write("a.wasm", _wasm_bytes())
        facts = triage.identify(path)["facts"]
        names = [section["name"] for section in facts["sections"]]
        self.assertEqual(names, ["custom", "import", "function", "memory", "export"])
        self.assertEqual(facts["sections"][0]["id"], 0)

    def test_wasm_counts_are_read(self):
        """The module says how many imports, exports and functions it has."""
        path = self.write("a.wasm", _wasm_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["import_count"], 1)
        self.assertEqual(facts["export_count"], 1)
        self.assertEqual(facts["function_count"], 2)
        self.assertEqual(facts["memory_pages"], 1)
        self.assertEqual(facts["version"], 1)


class EvmTests(TriageFixtureMixin, unittest.TestCase):
    """An EVM contract."""

    def test_evm_is_detected(self):
        """The contract bytecode names an EVM contract."""
        path = self.write("a.bin", _evm_bytes())
        self.assertEqual(triage.format_of(path), "evm")

    def test_evm_facts_carry_the_size_and_the_kind(self):
        """The contract says how big it is and whether it is creation code."""
        path = self.write("a.bin", _evm_bytes(creation=True))
        facts = triage.identify(path)["facts"]
        self.assertTrue(facts["is_creation"])
        self.assertEqual(facts["code_size"], 16)

    def test_evm_runtime_bytecode_is_not_creation(self):
        """Runtime bytecode is not creation bytecode."""
        path = self.write("a.bin", _evm_bytes(creation=False))
        facts = triage.identify(path)["facts"]
        self.assertFalse(facts["is_creation"])

    def test_evm_selector_scan_finds_the_selector(self):
        """The dispatcher selector is found, with the offset it was found at."""
        path = self.write("a.bin", _evm_bytes(selector=0xA9059CBB))
        details = triage.overview(path)["details"]
        self.assertEqual(len(details["selectors"]), 1)
        self.assertEqual(details["selectors"][0]["selector"], "0xa9059cbb")
        self.assertEqual(details["selectors"][0]["offset"], "0x5")

    def test_evm_without_a_dispatcher_has_no_selector(self):
        """A contract with no dispatcher has no selector."""
        path = self.write("a.bin", b"\x60\x80\x60\x40\x52" + b"\x00" * 32)
        details = triage.overview(path)["details"]
        self.assertEqual(details["selectors"], [])


class PlistTests(TriageFixtureMixin, unittest.TestCase):
    """A property list."""

    def test_xml_plist_is_detected(self):
        """An XML property list is a property list."""
        path = self.write("a.plist", plistlib.dumps({"Name": "x", "Value": 1}))
        self.assertEqual(triage.format_of(path), "plist")

    def test_binary_plist_is_detected(self):
        """A binary property list is a property list too."""
        path = self.write("a.plist", plistlib.dumps({"Name": "x"}, fmt=plistlib.FMT_BINARY))
        self.assertEqual(triage.format_of(path), "plist")

    def test_plist_facts_carry_the_keys(self):
        """The top level keys and the number of entries are read."""
        path = self.write("a.plist", plistlib.dumps({"Name": "x", "Value": 1}))
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["keys"], ["Name", "Value"])
        self.assertEqual(facts["entry_count"], 2)
        self.assertEqual(facts["plist_format"], "xml")

    def test_binary_plist_says_it_is_binary(self):
        """The format of the property list is said out loud."""
        path = self.write("a.plist", plistlib.dumps({"Name": "x"}, fmt=plistlib.FMT_BINARY))
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["plist_format"], "binary")


class HarTests(TriageFixtureMixin, unittest.TestCase):
    """An HTTP archive."""

    def test_har_is_detected(self):
        """A JSON file with a log of entries is an HTTP archive."""
        path = self.write("a.har", json.dumps(_har_dict()))
        self.assertEqual(triage.format_of(path), "har")

    def test_har_facts_carry_the_counts(self):
        """The archive says how many entries it holds and who made it."""
        path = self.write("a.har", json.dumps(_har_dict()))
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["entry_count"], 2)
        self.assertEqual(facts["creator"], "triage-test")
        self.assertEqual(facts["page_title"], "Example")
        self.assertEqual(facts["total_transferred_bytes"], 150)

    def test_har_entries_are_read(self):
        """Each entry gives the method, the URL, the status and the time."""
        path = self.write("a.har", json.dumps(_har_dict()))
        entries = triage.overview(path)["details"]["entries"]
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["method"], "GET")
        self.assertEqual(entries[0]["url"], "https://example.test/one")
        self.assertEqual(entries[0]["status"], 200)
        self.assertEqual(entries[0]["mime_type"], "text/html")
        self.assertEqual(entries[0]["response_size"], 120)
        self.assertEqual(entries[0]["time_ms"], 12.5)
        self.assertEqual(entries[0]["request_headers"], ["Accept"])

    def test_plain_json_is_text(self):
        """A JSON file that is not an archive is just text."""
        path = self.write("a.json", json.dumps({"hello": "world"}))
        self.assertEqual(triage.format_of(path), "text")


class JavaScriptTests(TriageFixtureMixin, unittest.TestCase):
    """A JavaScript project, an Electron application and an asar archive."""

    def test_directory_with_a_package_json_is_javascript(self):
        """A directory with a package.json is a JavaScript project."""
        root = os.path.join(self.tmp.name, "app")
        os.makedirs(root)
        with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "name": "demo",
                    "version": "1.4.2",
                    "main": "index.js",
                    "type": "module",
                    "scripts": {"start": "node index.js"},
                },
                handle,
            )
        self.assertEqual(triage.format_of(root), "javascript")

    def test_package_json_facts_are_read(self):
        """The package.json gives the name, the version, the entry and the scripts."""
        root = os.path.join(self.tmp.name, "app")
        os.makedirs(root)
        with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "name": "demo",
                    "version": "1.4.2",
                    "main": "index.js",
                    "type": "module",
                    "scripts": {"start": "node index.js"},
                },
                handle,
            )
        facts = triage.identify(root)["facts"]
        self.assertEqual(facts["name"], "demo")
        self.assertEqual(facts["version"], "1.4.2")
        self.assertEqual(facts["main"], "index.js")
        self.assertEqual(facts["type"], "module")
        self.assertEqual(facts["scripts"], {"start": "node index.js"})

    def test_standalone_javascript_file_is_javascript(self):
        """A .js file is a script, and not a text file."""
        path = self.write("index.js", "console.log(1)\n")
        self.assertEqual(triage.format_of(path), "javascript")

    def test_webpack_bundle_is_detected(self):
        """The webpack bootstrap marker names a bundle."""
        path = self.write("bundle.js", "var webpackBootstrap = function() {}\n")
        self.assertTrue(triage.overview(path)["details"]["webpack"])

    def test_source_map_next_to_the_script_is_found(self):
        """The source map beside a script is found."""
        path = self.write("index.js", "console.log(1)\n")
        self.write("index.js.map", "{}")
        details = triage.overview(path)["details"]
        self.assertTrue(details["source_map"])

    def test_electron_markers_are_found(self):
        """Electron in the dependencies is a marker of an Electron application."""
        root = os.path.join(self.tmp.name, "app")
        os.makedirs(root)
        with open(os.path.join(root, "package.json"), "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "name": "demo",
                    "version": "1.0.0",
                    "devDependencies": {"electron": "^30.0.0"},
                },
                handle,
            )
        result = triage.overview(root)
        self.assertTrue(result["facts"]["electron"])
        self.assertTrue(result["details"]["electron"])

    def test_asar_archive_is_parsed(self):
        """An asar archive is a pickle header and a JSON header, not a ZIP."""
        root = os.path.join(self.tmp.name, "app")
        os.makedirs(root)
        _asar_bytes(
            [("index.js", b"console.log(1)"), ("assets/logo.png", b"\x89PNG")],
            os.path.join(root, "app.asar"),
        )
        result = triage.overview(root)
        self.assertEqual(result["format"], "javascript")
        names = [entry["name"] for entry in result["details"]["files"]]
        self.assertEqual(names, ["assets/logo.png", "index.js"])

    def test_asar_is_not_a_zip(self):
        """An asar archive is not read as a ZIP."""
        root = os.path.join(self.tmp.name, "app")
        os.makedirs(root)
        _asar_bytes([("index.js", b"console.log(1)")], os.path.join(root, "app.asar"))
        self.assertNotEqual(triage.format_of(os.path.join(root, "app.asar")), "zip")


class FirmwareTests(TriageFixtureMixin, unittest.TestCase):
    """A firmware image."""

    def test_uimage_is_detected(self):
        """The uImage magic names a firmware image."""
        path = self.write("uimage.bin", _uimage_bytes())
        self.assertEqual(triage.format_of(path), "firmware")

    def test_uimage_facts_carry_the_name_and_the_size(self):
        """The uImage header carries the payload size, the name and the stamp."""
        path = self.write("uimage.bin", _uimage_bytes(name=b"myimage", size=1024))
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["firmware_format"], "uimage")
        self.assertEqual(facts["payload_size"], 1024)
        self.assertEqual(facts["name"], "myimage")
        self.assertTrue(facts["timestamp"].endswith("Z"))

    def test_squashfs_is_detected(self):
        """The squashfs magic names a firmware image."""
        path = self.write("sqfs.bin", _squashfs_bytes())
        self.assertEqual(triage.format_of(path), "firmware")

    def test_squashfs_facts_carry_the_version_and_the_block_size(self):
        """The superblock carries the version and the block size."""
        path = self.write("sqfs.bin", _squashfs_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["firmware_format"], "squashfs")
        self.assertEqual(facts["version"], "4.0")
        self.assertEqual(facts["block_size"], 131072)


class ClassTests(TriageFixtureMixin, unittest.TestCase):
    """A Java class file."""

    def test_class_is_detected(self):
        """The CAFEBABE magic names a class file."""
        path = self.write("A.class", _class_bytes())
        self.assertEqual(triage.format_of(path), "class")

    def test_class_facts_carry_the_version_and_the_flags(self):
        """The class file says its version and how it is declared."""
        path = self.write("A.class", _class_bytes(major=52))
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["major_version"], 52)
        self.assertEqual(facts["minor_version"], 0)
        self.assertEqual(facts["constant_pool_count"], 3)
        self.assertIn("public", facts["access_flags_names"])
        self.assertEqual(facts["methods_count"], 1)


class OtherFormatTests(TriageFixtureMixin, unittest.TestCase):
    """The formats that are not code."""

    def test_pdf_is_detected(self):
        """The PDF magic names a PDF."""
        path = self.write("a.pdf", b"%PDF-1.7\n%....\n")
        self.assertEqual(triage.format_of(path), "pdf")

    def test_pdf_version_is_read(self):
        """The version is in the first line."""
        path = self.write("a.pdf", b"%PDF-1.7\n%....\n")
        self.assertEqual(triage.identify(path)["facts"]["version"], "1.7")

    def test_gzip_is_detected(self):
        """The gzip magic names a gzip stream."""
        path = self.write("a.gz", gzip.compress(b"hello"))
        self.assertEqual(triage.format_of(path), "gzip")

    def test_sqlite_is_detected(self):
        """The SQLite magic names a database."""
        path = self.write("a.db", _sqlite_bytes())
        self.assertEqual(triage.format_of(path), "sqlite")

    def test_sqlite_facts_carry_the_page_size(self):
        """The database header says the page size."""
        path = self.write("a.db", _sqlite_bytes())
        facts = triage.identify(path)["facts"]
        self.assertEqual(facts["page_size"], 4096)
        self.assertEqual(facts["text_encoding"], "utf-8")

    def test_text_is_detected(self):
        """Printable bytes are a text file."""
        path = self.write("a.txt", b"hello\nworld\n")
        self.assertEqual(triage.format_of(path), "text")

    def test_text_line_count_is_read(self):
        """The number of lines is counted."""
        path = self.write("a.txt", b"hello\nworld\n")
        self.assertEqual(triage.identify(path)["facts"]["lines"], 2)

    def test_unknown_reports_the_entropy(self):
        """A file nothing recognises still says how much entropy it has."""
        path = self.write("a.bin", bytes(range(256)))
        result = triage.identify(path)
        self.assertEqual(result["format"], "unknown")
        self.assertGreater(result["facts"]["entropy"], 7.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
