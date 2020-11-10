#ifndef SNAPSNAP_INTERNAL_HH
#define SNAPSNAP_INTERNAL_HH

#include "snapsnap/vm.hh"
#include "unicorn/unicorn.h"

namespace ssnappriv
{

// Gets the unicorn arch and mode from a ssnap::VmArch architecture.
void vmarch_to_unicorn(ssnap::VmArch arch, uc_arch& vm_arch, uc_mode& vm_mode);

};

#endif
