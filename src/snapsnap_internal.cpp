#include "snapsnap_internal.hh"

namespace ssnappriv
{

void vmarch_to_unicorn(ssnap::VmArch arch, uc_arch& out_arch, uc_mode& out_mode)
{
    switch (arch)
    {
    case ssnap::VmArch::x86_64:
        out_arch = UC_ARCH_X86;
        out_mode = UC_MODE_64;
        break;
    default:
        out_arch = UC_ARCH_MAX;
        break;
    }
}
}
