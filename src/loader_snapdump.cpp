#include <fstream>
#include <vector>
#include "fmt/core.h"
#include "unicorn/unicorn.h"
#include "snapsnap/loader.hh"
#include "snapsnap/utility.hh"
#include "snapsnap_internal.hh"

namespace ssnap
{

namespace
{

template <typename T>
T read_ifstream(std::ifstream& s)
{
    T result;
    s.read(reinterpret_cast<char*>(&result), sizeof(T));

    if (s.gcount() != sizeof(T))
        throw std::runtime_error("Unexpected eof");

    return result;
}

std::uint32_t read_u32(std::ifstream& is)
{
    return read_ifstream<std::uint32_t>(is);
}

std::uint64_t read_u64(std::ifstream& is)
{
    return read_ifstream<std::uint64_t>(is);
}

std::uint8_t read_u8(std::ifstream& is)
{
    return read_ifstream<std::uint8_t>(is);
}

void load_registers(Vm& vm, std::vector<std::uint8_t>& register_state)
{
    // TODO: Find a cleaner way of doing this (arch argnostic)
    auto& regs_ids = ssnap::utility::get_user_regs_struct(vm.arch());
    std::uint64_t* regs_u64 = reinterpret_cast<std::uint64_t*>(register_state.data());

    if (register_state.size() % sizeof(*regs_u64) != 0)
        throw std::runtime_error("Unaligned register state");

    std::size_t register_count = register_state.size() / sizeof(*regs_u64);

    if (register_count != regs_ids.size())
        throw std::runtime_error(fmt::format("Register count mismatch ({} instead of {})",
                    register_count, regs_ids.size()));

    std::uint64_t fsbase = 0;
    std::uint64_t gsbase = 0;

    for (auto reg : regs_ids)
    {
        std::uint64_t reg_val = *regs_u64++;

        if (reg == UC_X86_REG_FS_BASE)
            fsbase = reg_val;
        else if (reg == UC_X86_REG_GS_BASE)
            gsbase = reg_val;
        else
            vm.set_register(reg, reg_val);
    }

    vm.set_register(UC_X86_REG_FS_BASE, fsbase);
    vm.set_register(UC_X86_REG_GS_BASE, gsbase);
}

}

namespace loader
{

Vm from_snapdump(std::string path)
{
    std::ifstream is(path);

    if (!is)
        throw std::runtime_error("Could not open snapdump file");

    Mmu mmu;

    std::uint32_t magic = read_u32(is);
    std::uint32_t architecture = read_u32(is);
    std::uint32_t entries_count = read_u32(is);

    if (magic != 0x504d4453)
        throw std::runtime_error("Invalid snapdump magic");

    if (architecture != 0)
        throw std::runtime_error("Only supported architecture is x86_64");

    std::vector<std::uint8_t> page_data;
    std::vector<std::uint8_t> register_state;

    for (std::uint32_t i = 0; i < entries_count; i++)
    {
        std::uint32_t entry_magic = read_u32(is);

        if (entry_magic == 0x5050414d)
        {
            // Memory mapping
            std::uint8_t prot = read_u8(is);
            std::uint64_t start = read_u64(is);
            std::uint64_t end = read_u64(is);

            if (start > end)
                throw std::runtime_error("Invalid mapping (start > end)");

            std::uint64_t mapping_size = end - start;
            page_data.resize(mapping_size);

            is.read(reinterpret_cast<char*>(page_data.data()), mapping_size);

            if (is.gcount() != mapping_size)
                throw std::runtime_error("Unexpected eof while reading mapping data");

            mmu.add_page(start, mapping_size, prot, page_data.data());

            fmt::print("[SNAPDUMP] Mapping 0x{:x} -> 0x{:x} prot={}\n", start, end, prot);
        }
        else if (entry_magic == 0x53474552)
        {
            // Registers
            std::uint32_t register_state_size = read_u32(is);
            register_state.resize(register_state_size);

            is.read(reinterpret_cast<char*>(register_state.data()), register_state_size);

            if (is.gcount() != register_state_size)
                throw std::runtime_error("Unexpected eof while reading register state");

            fmt::print("[SNAPDUMP] Loading {} bytes of register state\n", register_state_size);
        }
        else
            throw std::runtime_error(fmt::format("Unexpected entry magic: 0x{:08x}\n", entry_magic));
    }

    Vm vm(VmArch::x86_64, std::move(mmu));
    load_registers(vm, register_state);

    return vm;
}

}

}
