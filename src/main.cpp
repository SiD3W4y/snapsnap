#include "fmt/core.h"
#include "snapsnap/loader.hh"
#include "snapsnap/utility.hh"

int main(int argc, char** argv)
{
    ssnap::Vm vm = ssnap::loader::from_coredump("core.7635", UC_ARCH_X86, UC_MODE_64);
    ssnap::utility::print_cpu_state(vm);

    int local_var = 42;

    auto hook = [&local_var](ssnap::Vm& vm, std::uint64_t address, int size, std::int64_t value) -> bool {
        fmt::print("Hook called !! (local var: {})\n", local_var);
        return false;
    };

    vm.add_unmapped_hook(hook);
    vm.run(0);

    return 0;
}
