#ifndef UTILITY_HH
#define UTILITY_HH

#include "snapsnap/vm.hh"

namespace ssnap
{

namespace utility
{

const std::vector<int>& get_user_regs_struct(ssnap::VmArch arch);
void print_cpu_state(Vm& vm);

}

}


#endif
