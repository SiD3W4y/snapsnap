#include <stdexcept>
#include <map>
#include "fmt/core.h"
#include "unicorn/x86.h"
#include "snapsnap/utility.hh"
#include "snapsnap/vm.hh"


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
    UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RSP, // FS_BASE is orig rax but unicorn doesn't have it
    UC_X86_REG_RIP, UC_X86_REG_CS, UC_X86_REG_EFLAGS, UC_X86_REG_RSP,
    UC_X86_REG_SS, UC_X86_REG_FS_BASE, UC_X86_REG_GS_BASE, UC_X86_REG_DS,
    UC_X86_REG_ES, UC_X86_REG_FS, UC_X86_REG_GS
};

std::map<int, std::string> x86_64_reg_to_str = {
    {UC_X86_REG_R15, "r15"},
    {UC_X86_REG_R14, "r14"},
    {UC_X86_REG_R13, "r13"},
    {UC_X86_REG_R12, "r12"},
    {UC_X86_REG_RBP, "rbp"},
    {UC_X86_REG_RBX, "rbx"},
    {UC_X86_REG_R11, "r11"},
    {UC_X86_REG_R10, "r10"},
    {UC_X86_REG_R9, "r9"},
    {UC_X86_REG_R8, "r8"},
    {UC_X86_REG_RAX, "rax"},
    {UC_X86_REG_RCX, "rcx"},
    {UC_X86_REG_RDX, "rdx"},
    {UC_X86_REG_RSI, "rsi"},
    {UC_X86_REG_RDI, "rdi"},
    {UC_X86_REG_RIP, "rip"},
    {UC_X86_REG_CS, "cs"},
    {UC_X86_REG_EFLAGS, "eflags"},
    {UC_X86_REG_RSP, "rsp"},
    {UC_X86_REG_SS, "ss"},
    {UC_X86_REG_FS_BASE, "fsbase"},
    {UC_X86_REG_GS_BASE, "gsbase"},
    {UC_X86_REG_DS, "ds"},
    {UC_X86_REG_ES, "es"},
    {UC_X86_REG_FS, "fs"},
    {UC_X86_REG_GS, "gs"}
};

}

const std::vector<int>& get_user_regs_struct(uc_arch arch, uc_mode mode)
{
    if (arch != UC_ARCH_X86 || mode != UC_MODE_64)
        throw std::runtime_error("Only x86_64 is supported for now");

    return x86_64_user_regs_struct;
}

void print_cpu_state(Vm& vm)
{
    if (vm.arch() != UC_ARCH_X86 || vm.mode() != UC_MODE_64)
        throw std::runtime_error("Only x86_64 is supported for now");

    std::size_t count = 0;

    for (auto& [id, name] : x86_64_reg_to_str)
    {
        if (count > 0 && count % 5 == 0)
            fmt::print("\n");

        fmt::print("{:7}: 0x{:016x}  ", name, vm.get_register(id));
        count++;
    }

    if (count % 5)
        fmt::print("\n");
}


}

}
