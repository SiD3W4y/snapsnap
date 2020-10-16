#ifndef VM_HH
#define VM_HH

#include "unicorn/unicorn.h"
#include "snapsnap/mmu.hh"

namespace ssnap
{

class Vm
{
public:
    Vm(uc_arch arch, uc_mode mode, Mmu&& mmu);
    Vm(const Vm& other);
    Vm& operator=(const Vm& other);
    Vm(Vm&& other);
    Vm& operator=(Vm&& other);

    ~Vm();

    // Resets the Vm to its original state
    void reset(const Vm& original);

    // Expose parts of the mmu
    bool write_raw(std::uint64_t address, const void* buffer, std::size_t size);
    bool write(std::uint64_t address, const void* buffer, std::size_t size);
    bool read(std::uint64_t address, void* buffer, std::size_t size);

private:
    Mmu mmu_;
    uc_engine* uc_ = nullptr;
    uc_arch arch_;
    uc_mode mode_;
    uc_context* cpu_context_ = nullptr;
};

}

#endif
