#ifndef LOADER_HH
#define LOADER_HH

#include <string>
#include "snapsnap/vm.hh"

namespace ssnap
{

namespace loader
{

Vm from_coredump(std::string path, VmArch arch);
Vm from_snapdump(std::string path);

}

}

#endif
