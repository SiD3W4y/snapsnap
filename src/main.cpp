#include "fmt/core.h"
#include "snapsnap/loader.hh"
#include "snapsnap/utility.hh"

int main(int argc, char** argv)
{
    ssnap::Vm vm = ssnap::loader::from_coredump("core.1116", UC_ARCH_X86, UC_MODE_64);
    ssnap::utility::print_cpu_state(vm);

    return 0;
}
