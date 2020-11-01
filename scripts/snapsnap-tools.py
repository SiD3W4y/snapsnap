import gdb


class Protection:
    Read = 1
    Write = 2
    Execute = 4


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


DumpSymbols()
