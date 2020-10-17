#ifndef VM_HH
#define VM_HH

#include <set>
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

    // Maps a range of pages into unicorn memory.
    //
    // Returns true on success.
    bool map_range(std::uint64_t address, std::size_t size);

    std::uint64_t get_register(int regid);
    void set_register(int regid, std::uint64_t value);

    // Saves the state of the registers to the context.
    void save_cpu_context();

    uc_arch arch() const
    {
        return arch_;
    }

    uc_mode mode() const
    {
        return mode_;
    }

private:
    bool address_mapped_(std::uint64_t address) const;

    Mmu mmu_;
    uc_engine* uc_ = nullptr;
    uc_arch arch_;
    uc_mode mode_;
    uc_context* cpu_context_ = nullptr;
    std::set<std::uint64_t> mapped_pages_;
    std::vector<uc_hook> hooks_;
};

}

#endif
