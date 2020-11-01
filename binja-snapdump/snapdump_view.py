import struct
from binaryninja.binaryview import BinaryView
from binaryninja.architecture import Architecture
from binaryninja.log import log_error, log_info
from binaryninja.enums import SegmentFlag


def u8(x):
    return struct.unpack("B", x)[0]


def u32(x):
    return struct.unpack("<I", x)[0]


def u64(x):
    return struct.unpack("<Q", x)[0]


class Protection:
    Read = 1
    Write = 2
    Execute = 4


sdump_architectures = [Architecture["x86_64"]]


class SdumpEntryId:
    Mapping = 0x5050414d
    Registers = 0x53474552


def perm_to_segment_prot(p):
    result = 0

    if p & Protection.Read:
        result |= SegmentFlag.SegmentReadable
    if p & Protection.Write:
        result |= SegmentFlag.SegmentWritable
    if p & Protection.Execute:
        result |= SegmentFlag.SegmentExecutable

    return result


class SnapdumpView(BinaryView):
    name = "Snapdump"
    long_name = "Snapdump"

    def __init__(self, data):
        BinaryView.__init__(self, parent_view=data, file_metadata=data.file)
        self.data = data

    @classmethod
    def is_valid_for_data(self, data):
        header = data.read(0, 4)

        if len(header) != 4 or header != b"SDMP":
            return False

        arch = data.read(4, 4)

        if len(arch) != 4:
            return False

        arch_id = u32(arch)

        if arch_id < 0 or arch_id >= len(sdump_architectures):
            return False

        # Checking that there is a number of entries
        count = data.read(8, 4)

        if len(count) != 4:
            return False

        return True

    def init(self):
        arch_id = u32(self.data.read(4, 4))
        entry_count = u32(self.data.read(8, 4))
        arch = sdump_architectures[arch_id]
        self.platform = arch.standalone_platform

        if entry_count == 0:
            log_error("sdmp file contains no mappings")
            return False

        file_index = 12

        for i in range(entry_count):
            entry_type = self.data.read(file_index, 4)

            if len(entry_type) != 4:
                log_error("Unexpected eof (entry_type)")
                return False

            entry_type = u32(entry_type)

            if entry_type == SdumpEntryId.Mapping:
                file_index += 4

                perm = self.data.read(file_index, 1)
                start = self.data.read(file_index + 1, 8)
                end = self.data.read(file_index + 1 + 8, 8)

                if len(perm) != 1 or len(start) != 8 or len(end) != 8:
                    log_error("Unexpected eof (mapping header)")
                    return False

                perm = u8(perm)
                start = u64(start)
                end = u64(end)

                if start > end:
                    log_error(f"Entry {i} start > end (start=0x{start:x}, end=0x{end:x})")
                    return False

                file_index += 1 + 8 + 8
                data_size = end - start

                self.add_auto_segment(start, data_size, file_index, data_size,
                                      perm_to_segment_prot(perm))

                file_index += data_size
                log_info(f"[SNAPDUMP] Loading mapping 0x{start:x} -> 0x{end:x}")
            elif entry_type == SdumpEntryId.Registers:
                file_index += 4
                register_data_size = self.data.read(file_index, 4)

                if len(register_data_size) != 4:
                    log_error("Unexpected eof (register data size)")
                    return False

                register_data_size = u32(register_data_size)
                register_data = self.data.read(file_index + 4, register_data_size)

                if len(register_data) != register_data_size:
                    log_error("Unexpected eof (register data)")
                    return False

                log_info(f"[SNAPDUMP] Register data size: {register_data_size}")
                file_index ++ 4 + register_data_size
            else:
                log_error(f"Unknown entry type: 0x{entry_type:x}")
                return False

        return True
