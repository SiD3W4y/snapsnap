#ifndef VM_HH
#define VM_HH

#include <set>
#include <vector>
#include <functional>
#include "unicorn/unicorn.h"
#include "snapsnap/mmu.hh"

namespace ssnap
{

enum class VmExitStatus
{
    Ok,
    Timeout,
    InvalidInstruction,
    MemoryUnmapped,
    MemoryProtection,
    Unknown
};

/**
 * Represents the status of the vm at exit with additional information if a
 * problem was encountered.
 */
struct VmExit
{
    /**
     * Vm status at program exit.
     */
    VmExitStatus status = VmExitStatus::Ok;

    /**
     * pc where a fault occured.
     */
    std::uint64_t pc = 0;
};

class Vm
{
public:
    using CodeHook = std::function<void(Vm&, std::uint64_t, std::uint32_t)>;
    using CodeHookTpl = std::function<void(std::uint64_t, std::uint32_t size)>;
    using MemOpHook = std::function<void(Vm&, std::uint64_t, int, std::int64_t)>;
    using MemOpTpl = std::function<void(std::uint64_t, int, std::int64_t)>;

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

    // Unicorn hooks
    void add_code_hook(CodeHook hook, std::uint64_t begin = 1, std::uint64_t end = 0);
    void add_block_hook(CodeHook hook, std::uint64_t begin = 1, std::uint64_t end = 0);
    void add_read_hook(MemOpHook hook, std::uint64_t begin = 1, std::uint64_t end = 0);
    void add_write_hook(MemOpHook hook, std::uint64_t begin = 1, std::uint64_t end = 0);

    VmExit run(std::uint64_t target, std::uint64_t timeout = 0, std::size_t count = 0);

    // Stops the emulation
    void stop();

    // Maps a range of pages into unicorn memory.
    //
    // Returns true on success.
    bool map_range(std::uint64_t address, std::size_t size);
    bool address_mapped(std::uint64_t address) const;

    // Called when an address is not mapped. Stops the emulation and sets VmExit
    // status accordingly on error.
    bool handle_pagefault_(std::uint64_t address, std::size_t size);

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
    void install_internal_hooks_();

    Mmu mmu_;
    uc_engine* uc_ = nullptr;
    uc_arch arch_;
    uc_mode mode_;
    uc_context* cpu_context_ = nullptr;
    std::set<std::uint64_t> mapped_pages_;

    // Unicorn hooks
    std::vector<uc_hook> hooks_;
    std::vector<CodeHookTpl*> code_hooks_;
    std::vector<MemOpTpl*> mem_hooks_;
};

}

#endif
