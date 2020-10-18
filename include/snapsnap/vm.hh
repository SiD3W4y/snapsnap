#ifndef VM_HH
#define VM_HH

#include <set>
#include <vector>
#include <functional>
#include "unicorn/unicorn.h"
#include "snapsnap/mmu.hh"

namespace ssnap
{

class Vm
{
public:
    using CodeHook = std::function<void(Vm&, std::uint64_t, std::uint32_t)>;
    using CodeHookTpl = std::function<void(std::uint64_t, std::uint32_t size)>;
    using MemOpHook = std::function<void(Vm&, std::uint64_t, int, std::int64_t)>;
    using MemOpTpl = std::function<void(std::uint64_t, int, std::int64_t)>;
    using MemUnmapHook = std::function<bool(Vm&, std::uint64_t, int, std::int64_t)>;
    using MemUnmapTpl = std::function<bool(std::uint64_t, int, std::uint64_t)>;

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
    void add_unmapped_hook(MemUnmapHook hook, std::uint64_t begin = 1, std::uint64_t end = 0);

    void run(std::uint64_t target, std::uint64_t timeout = 0, std::size_t count = 0);

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

    // Unicorn hooks
    std::vector<uc_hook> hooks_;
    std::vector<CodeHookTpl*> code_hooks_;
    std::vector<MemOpTpl*> mem_hooks_;
    std::vector<MemUnmapTpl*> unmap_hooks_;
};

}

#endif
