#include "fmt/core.h"
#include "snapsnap/mmu.hh"
#include "snapsnap/vm.hh"

int main(int argc, char** argv)
{
    ssnap::Mmu m;

    m.add_page(0x1000, 0x1000, 7);
    m.add_page(0x3000, 0x1000, 7);

    for (auto& page : m)
        fmt::print("Page address: 0x{:016x} Size: {:x}\n", page.address, page.size);

    ssnap::Vm vm(UC_ARCH_X86, UC_MODE_64, std::move(m));

    std::string h("hello world");

    if (!vm.write(0x1000, h.c_str(), h.size()))
        fmt::print("Write failed :(\n");

    return 0;
}
