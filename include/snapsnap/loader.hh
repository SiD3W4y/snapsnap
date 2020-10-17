#ifndef LOADER_HH
#define LOADER_HH

#include <string>
#include "snapsnap/vm.hh"

namespace ssnap
{

namespace loader
{

Vm from_coredump(std::string path, uc_arch arch, uc_mode mode);

}

}

#endif
