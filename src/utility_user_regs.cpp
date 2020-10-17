#include <stdexcept>
#include "snapsnap/utility.hh"
#include "unicorn/x86.h"


namespace ssnap
{

namespace utility
{

namespace
{

std::vector<int> x86_64_user_regs_struct = {
    UC_X86_REG_R15, UC_X86_REG_R14, UC_X86_REG_R13, UC_X86_REG_R12,
    UC_X86_REG_RBP, UC_X86_REG_RBX, UC_X86_REG_R11, UC_X86_REG_R10,
    UC_X86_REG_R9, UC_X86_REG_R8, UC_X86_REG_RAX, UC_X86_REG_RCX,
    UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_FS_BASE, // FS_BASE is orig rax but unicorn doesn't have it
    UC_X86_REG_RIP, UC_X86_REG_CS, UC_X86_REG_EFLAGS, UC_X86_REG_RSP,
    UC_X86_REG_SS, UC_X86_REG_FS_BASE, UC_X86_REG_GS_BASE, UC_X86_REG_DS,
    UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS
};

}

const std::vector<int>& get_user_regs_struct(uc_arch arch, uc_mode mode)
{
    if (arch != UC_ARCH_X86 || mode != UC_MODE_64)
        throw std::runtime_error("Only x86_64 is supported for now");

    return x86_64_user_regs_struct;
}


}

}
