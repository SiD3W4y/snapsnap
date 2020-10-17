#include "fmt/core.h"
#include "snapsnap/loader.hh"

int main(int argc, char** argv)
{
    ssnap::Vm vm = ssnap::loader::load_coredump("core.39298", UC_ARCH_X86, UC_MODE_64);

    std::vector<std::uint8_t> data;
    data.resize(100);

    return 0;
}
