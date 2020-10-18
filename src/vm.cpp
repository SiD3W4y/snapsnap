#include <string>
#include <stdexcept>
#include <cstring>
#include "fmt/core.h"
#include "snapsnap/vm.hh"

namespace ssnap
{

Vm::Vm(uc_arch arch, uc_mode mode, Mmu&& mmu)
    : mmu_(std::move(mmu)), arch_(arch), mode_(mode)
{
    uc_err err = uc_open(arch, mode, &uc_);

    if (err != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(err));

    err = uc_context_alloc(uc_, &cpu_context_);

    if (err != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(err));

    // Save the initial context
    uc_context_save(uc_, cpu_context_);
}

Vm& Vm::operator=(const Vm& other)
{
    arch_ = other.arch_;
    mode_ = other.mode_;
    mmu_ = other.mmu_;
    mapped_pages_ = other.mapped_pages_;

    uc_err err = uc_open(arch_, mode_, &uc_);

    if (err != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(err));

    err = uc_context_alloc(uc_, &cpu_context_);

    if (err != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(err));

    uc_context_save(other.uc_, cpu_context_);

    return *this;
}

Vm::Vm(const Vm& other)
{
    *this = other;
}

Vm& Vm::operator=(Vm&& other)
{
    arch_ = other.arch_;
    mode_ = other.mode_;
    mmu_ = std::move(other.mmu_);
    mapped_pages_ = std::move(other.mapped_pages_);
    uc_ = other.uc_;
    cpu_context_ = other.cpu_context_;

    other.uc_ = nullptr;
    other.cpu_context_ = nullptr;

    return *this;
}

Vm::Vm(Vm&& other)
{
    *this = std::move(other);
}

Vm::~Vm()
{
    if (cpu_context_)
        uc_free(cpu_context_);

    if (uc_)
        uc_close(uc_);

    // Destroy lambda hooks
    for (auto hook : code_hooks_)
        delete hook;

    for (auto hook : mem_hooks_)
        delete hook;

    for (auto hook : unmap_hooks_)
        delete hook;
}

void Vm::reset(const Vm& original)
{
    // TODO: Add code to iterate Mmu pages and mark them dirty according to the
    // set of page address written to.
    mmu_.reset(original.mmu_);
    uc_context_save(original.uc_, cpu_context_);
}

bool Vm::write_raw(std::uint64_t address, const void* buffer, std::size_t size)
{
    return mmu_.write_raw(address, buffer, size);
}

bool Vm::write(std::uint64_t address, const void* buffer, std::size_t size)
{
    return mmu_.write_raw(address, buffer, size);
}

bool Vm::read(std::uint64_t address, void* buffer, std::size_t size)
{
    return mmu_.read(address, buffer, size);
}

std::uint64_t Vm::get_register(int regid)
{
    std::uint64_t value;
    uc_err err = uc_reg_read(uc_, regid, &value);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("get_register: {}", uc_strerror(err)));

    return value;
}

void Vm::set_register(int regid, std::uint64_t value)
{
    uc_err err = uc_reg_write(uc_, regid, &value);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("set_register: {}", uc_strerror(err)));
}

void Vm::save_cpu_context()
{
    uc_context_save(uc_, cpu_context_);
}

bool Vm::address_mapped_(std::uint64_t address) const
{
    address &= ~(mmu_.page_size() - 1);
    auto it = mapped_pages_.find(address);

    return it != mapped_pages_.end();
}

bool Vm::map_range(std::uint64_t address, std::size_t size)
{
    while (size > 0)
    {
        const MemoryPage* page = mmu_.get_page(address);

        if (!page)
            return false;

        uc_err err = uc_mem_map_ptr(uc_, page->address, page->size, page->prot, page->data);

        if (err != UC_ERR_OK)
            throw std::runtime_error(fmt::format("map_page: {}", uc_strerror(err)));

        // fmt::print("[VM] Lazy mapping [address=0x{:x}, size=0x{:x}, prot={}]\n",
        //        page->address, page->size, page->prot);

        std::size_t bytes_to_eop = (page->address + page->size) - address;
        std::size_t next_off = std::min(size, bytes_to_eop);
        mapped_pages_.insert(page->address);

        size -= next_off;
        address += next_off;
    }

    return true;
}

void Vm::run(std::uint64_t target, std::uint64_t timeout, std::size_t size)
{
    std::uint64_t start_address = get_register(UC_X86_REG_RIP);
    uc_err err = uc_emu_start(uc_, start_address, target, timeout, size);
}

// Setting up the plumbing for unicorn hooks
namespace
{

void unicorn_code_hook(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data)
{
    Vm::CodeHookTpl& hook = reinterpret_cast<Vm::CodeHookTpl&>(user_data);
    hook(address, size);
}

bool unicorn_unmap_hook(uc_engine* uc, uc_mem_type type, std::uint64_t address, int size, std::int64_t value,
        void* user_data)
{
    Vm::MemUnmapTpl* hook = reinterpret_cast<Vm::MemUnmapTpl*>(user_data);
    return (*hook)(address, size, value);
}

}

void Vm::add_code_hook(CodeHook hook, std::uint64_t begin, std::uint64_t end)
{
    uc_hook unicorn_hook;

    auto cb = new CodeHookTpl([this, hook](std::uint64_t address, std::uint32_t size){
        hook(*this, address, size);
    });

    code_hooks_.push_back(cb);

    uc_err err = uc_hook_add(uc_, &unicorn_hook, UC_HOOK_CODE,
            reinterpret_cast<void*>(&unicorn_code_hook),
            reinterpret_cast<void*>(cb), begin, end);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("add_code_hook: {}", uc_strerror(err)));

    hooks_.push_back(unicorn_hook);
}

void Vm::add_block_hook(CodeHook hook, std::uint64_t begin, std::uint64_t end)
{
    uc_hook unicorn_hook;

    auto cb = new CodeHookTpl([this, hook](std::uint64_t address, std::uint32_t size){
        hook(*this, address, size);
    });

    code_hooks_.push_back(cb);

    uc_err err = uc_hook_add(uc_, &unicorn_hook, UC_HOOK_BLOCK,
            reinterpret_cast<void*>(&unicorn_code_hook),
            reinterpret_cast<void*>(cb), begin, end);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("add_block_hook: {}", uc_strerror(err)));

    hooks_.push_back(unicorn_hook);
}

void Vm::add_read_hook(MemOpHook hook, std::uint64_t begin, std::uint64_t end)
{
    uc_hook unicorn_hook;

    auto cb = new MemOpTpl([this, hook](std::uint64_t address, int size, std::int64_t value){
        hook(*this, address, size, value);
    });

    mem_hooks_.push_back(cb);

    uc_err err = uc_hook_add(uc_, &unicorn_hook, UC_MEM_READ,
            reinterpret_cast<void*>(&unicorn_code_hook),
            reinterpret_cast<void*>(cb), begin, end);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("add_read_hook: {}", uc_strerror(err)));

    hooks_.push_back(unicorn_hook);
}

void Vm::add_write_hook(MemOpHook hook, std::uint64_t begin, std::uint64_t end)
{
    uc_hook unicorn_hook;

    auto cb = new MemOpTpl([this, hook](std::uint64_t address, int size, std::int64_t value){
        hook(*this, address, size, value);
    });

    mem_hooks_.push_back(cb);

    uc_err err = uc_hook_add(uc_, &unicorn_hook, UC_MEM_WRITE,
            reinterpret_cast<void*>(&unicorn_code_hook),
            reinterpret_cast<void*>(cb), begin, end);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("add_write_hook: {}", uc_strerror(err)));

    hooks_.push_back(unicorn_hook);
}

void Vm::add_unmapped_hook(MemUnmapHook hook, std::uint64_t begin, std::uint64_t end)
{
    uc_hook unicorn_hook;

    auto cb = new MemUnmapTpl([this, hook](std::uint64_t address, int size, std::int64_t value) -> bool {
        return hook(*this, address, size, value);
    });

    unmap_hooks_.push_back(cb);

    uc_err err = uc_hook_add(uc_, &unicorn_hook, UC_HOOK_MEM_UNMAPPED,
            reinterpret_cast<void*>(&unicorn_unmap_hook),
            reinterpret_cast<void*>(cb), begin, end);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("add_unmap_hook: {}", uc_strerror(err)));

    hooks_.push_back(unicorn_hook);
}

}
