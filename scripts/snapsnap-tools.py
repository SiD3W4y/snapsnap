import gdb
import sys
import struct


def p8(x):
    return struct.pack("B", x)


def p32(x):
    return struct.pack("<I", x)


def p64(x):
    return struct.pack("<Q", x)


class Protection:
    Read = 1
    Write = 2
    Execute = 4


class SdumpArchitecture:
    x86_64 = 0


class SdumpEntryId:
    Mapping = 0x5050414d
    Registers = 0x53474552


class Mapping:
    def __init__(self, start, end, prot):
        self.start = start
        self.end = end
        self.prot = prot


class DumpSymbols(gdb.Command):
    def __init__(self):
        super().__init__("snapsnap-dump-symbols", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        file_name = "symbols.txt"
        args = gdb.string_to_argv(arg)

        if len(args) > 1:
            print("usage: snapsnap-dump-symbols [optional output file]")
            return

        if len(args) == 1:
            file_name = args[0]

        symbols = gdb.execute("info functions", from_tty, True)
        symbols = filter(lambda s: len(s) > 0 and s.startswith("0x"), map(str.strip, symbols.split("\n")))
        symbol_map = {}

        for s in symbols:
            chunks = s.split(" ")
            address, name = int(chunks[0], 16), chunks[-1]

            if name not in symbol_map:
                symbol_map[name] = [address]
            else:
                symbol_map[name].append(address)

        # As some functions appear multiple times we need to suffix them with
        # an identifier. Otherwise binary-ninja won't be happy
        with open(file_name, "w") as out:
            for name, addresses in symbol_map.items():
                if len(addresses) == 1:
                    out.write(f"0x{addresses[0]:x} {name}\n")
                else:
                    for i, e in enumerate(addresses):
                        out.write(f"0x{e:x} {name}_{i}\n")


class DumpSnapshot(gdb.Command):
    def __init__(self):
        super().__init__("snapsnap-snapshot", gdb.COMMAND_USER)

    def get_architecture(self):
        arch_str = gdb.execute("show architecture", False, True)

        if "x86-64" in arch_str:
            return SdumpArchitecture.x86_64

        return None

    def invoke(self, arg, from_tty):
        file_name = "snapshot.sdmp"
        args = gdb.string_to_argv(arg)

        if len(args) > 1:
            print("usage: snapsnap-snapshot [optional output file]")
            return

        if len(args) == 1:
            file_name = args[0]

        # Architecture check
        arch = self.get_architecture()

        if arch is None:
            print("Unsupported architecture")
            return

        # Get pid and mappings
        proc_info = gdb.execute("info proc", from_tty, True).split("\n")
        proc_info = list(filter(lambda a: a.startswith("process"), map(str.strip, proc_info)))

        if len(proc_info) != 1:
            print("Could not find process id")
            return

        pid = proc_info[0].split(" ")[-1]
        print(f"Process id: {pid}")

        proc_maps = open(f"/proc/{pid}/maps", "r").readlines()
        proc_mem = open(f"/proc/{pid}/mem", "rb")
        out = open(file_name, "wb")

        out.write(b"SDMP")  # Magic
        out.write(p32(arch))  # Architecture
        out.write(p32(0))  # Entry count

        for line in proc_maps:
            line = line.strip()
            info = list(filter(lambda a: len(a) > 1 and not a.isspace(), line.split(" ")))

            mapping_range = info[0].split("-")
            start = int(mapping_range[0], 16)
            end = int(mapping_range[1], 16)

            if start > sys.maxsize or end > sys.maxsize:
                print(f"Mapping too high in memory, cannot dump: {line}")
                continue

            perm_str = info[1]
            perm = 0

            for p in perm_str:
                if p == "r":
                    perm |= Protection.Read
                elif p == "w":
                    perm |= Protection.Write
                elif p == "x":
                    perm |= Protection.Execute

            proc_mem.seek(start)

            out.write(p32(SdumpEntryId.Mapping))
            out.write(p8(perm))
            out.write(p64(start))
            out.write(p64(end))

            try:
                data = proc_mem.read(end - start)
                print(f"Dumping range 0x{start:x} -> 0x{end:x} {perm_str}")
                out.write(data)
            except OSError:
                print(f"Could not dump range 0x{start:x} -> 0x{end:x}")
                continue


DumpSymbols()
DumpSnapshot()
