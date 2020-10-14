#include "fmt/core.h"
#include "snapsnap/mmu.hh"

int main(int argc, char** argv)
{
    ssnap::Mmu m;

    m.add_page(0x2000, 0x2000, 7);
    m.add_page(0x1000, 0x1000, 7);

    for (auto& page : m)
        fmt::print("Page address: 0x{:016x} Size: {:x}\n", page.address, page.size);

    return 0;
}
