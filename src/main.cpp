#include "fmt/core.h"
#include "snapsnap/loader.hh"
#include "snapsnap/utility.hh"

int main(int argc, char** argv)
{
    ssnap::Vm vm = ssnap::loader::from_coredump("core.7635", UC_ARCH_X86, UC_MODE_64);
    ssnap::Vm copy = vm;

    copy.add_block_hook([](ssnap::Vm& vm, std::uint64_t address, std::uint32_t size) {
            fmt::print("Basic block: 0x{:x}\n", address);
    });

    ssnap::VmExit exit = vm.run(0x7ffff7df2070, 0, 2);

    fmt::print("VmExit code: {}, pc: 0x{:x}\n", exit.status, exit.pc);

    return 0;
}
