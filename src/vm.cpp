#include <string>
#include <stdexcept>
#include <cstring>
#include "fmt/core.h"
#include "snapsnap/vm.hh"

namespace ssnap
{

namespace
{

bool unmapped_cb_(uc_engine* uc, uc_mem_type type, std::uint64_t address, int size,
        std::int64_t value, Vm* vm)
{
    fmt::print("[UNMAPPED_HOOK] Address: 0x{:x} size: {}\n", address, size);
    return vm->map_range(address, size);
}

}

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
    install_internal_hooks_();
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
    uc_context_restore(uc_, cpu_context_);
    install_internal_hooks_();

    return *this;
}

Vm::Vm(const Vm& other)
{
    *this = other;
}

/** \brief Move construct a Vm instance.
 *
 * Due to the way the hooks are implemented they cannot be moved or copied thus
 * a new instance of unicorn is created on move construction.
 */
Vm& Vm::operator=(Vm&& other)
{
    arch_ = other.arch_;
    mode_ = other.mode_;
    mmu_ = std::move(other.mmu_);
    mapped_pages_ = {};

    if (uc_)
        uc_close(uc_);

    uc_err err = uc_open(other.arch(), other.mode(), &uc_);

    if (err != UC_ERR_OK)
        throw std::runtime_error("Could not create new unicorn instance");

    cpu_context_ = other.cpu_context_;
    uc_context_restore(uc_, cpu_context_);
    install_internal_hooks_();

    uc_close(other.uc_);

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

    for (auto hook : intr_hooks_)
        delete hook;
}

/** \brief Resets the state of the vm.
 *
 * Resets the cpu state and the mmu state of the current vm according to a
 * reference Vm.
 */
void Vm::reset(const Vm& original)
{
    // TODO: Add code to iterate Mmu pages and mark them dirty according to the
    // set of page address written to.
    mmu_.reset(original.mmu_);
    uc_context_save(original.uc_, cpu_context_);
    uc_context_restore(uc_, cpu_context_);
}

/** \brief Writes data into Vm memory
 *
 * Writes data into vm memory and don't mark the memory as dirty.
 */
bool Vm::write_raw(std::uint64_t address, const void* buffer, std::size_t size)
{
    return mmu_.write_raw(address, buffer, size);
}

/** \brief Writes data into Vm memory.
 *
 * Writes data into vm memory and marks the memory as dirty.
 */
bool Vm::write(std::uint64_t address, const void* buffer, std::size_t size)
{
    return mmu_.write(address, buffer, size);
}

/** \brief Reads Vm memory into a buffer.
 */
bool Vm::read(std::uint64_t address, void* buffer, std::size_t size)
{
    return mmu_.read(address, buffer, size);
}

/** \brief Marks a page containing a given address as dirty.
 */
void Vm::mark_dirty_(std::uint64_t address)
{
    mmu_.mark_dirty(address);
}

/** \brief Returns the value of a register.
 */
std::uint64_t Vm::get_register(int regid)
{
    std::uint64_t value;
    uc_err err = uc_reg_read(uc_, regid, &value);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("get_register: {}", uc_strerror(err)));

    return value;
}

/** \brief Sets the value of a vm register.
 */
void Vm::set_register(int regid, std::uint64_t value)
{
    uc_err err = uc_reg_write(uc_, regid, &value);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("set_register: {}", uc_strerror(err)));
}

/** \brief Saves the current unicorn context.
 *
 * Freezes the current cpu context to internal storage.
 */
void Vm::save_cpu_context()
{
    uc_context_save(uc_, cpu_context_);
}

bool Vm::address_mapped(std::uint64_t address) const
{
    address &= ~(mmu_.page_size() - 1);
    auto it = mapped_pages_.find(address);

    return it != mapped_pages_.end();
}

/** \brief Maps a range of addresses.
 *
 * Maps a range of addresses from the mmu to unicorn. Returns whether all pages
 * were mapped or not.
 */
bool Vm::map_range(std::uint64_t address, std::size_t size)
{
    while (size > 0)
    {
        const MemoryPage* page = mmu_.get_page(address);

        if (!page)
            return false;

        bool page_mapped = mapped_pages_.find(address) != mapped_pages_.end();
        std::size_t bytes_to_eop = (page->address + page->size) - address;
        std::size_t next_off = std::min(size, bytes_to_eop);

        if (!page_mapped)
        {
            uc_err err = uc_mem_map_ptr(uc_, page->address, page->size, page->prot, page->data);

            if (err != UC_ERR_OK)
                throw std::runtime_error(fmt::format("map_page: {}", uc_strerror(err)));

            fmt::print("[VM] Lazy mapping [address=0x{:x}, size=0x{:x}, prot={}]\n",
                   page->address, page->size, page->prot);

            mapped_pages_.insert(page->address);
        }

        size -= next_off;
        address += next_off;
    }

    return true;
}

/** \brief Starts the emulation from the current pc.
 *
 * Starts the emulation starting from pc and until target. Optionally a timeout
 * and a limit count of instructions can be given.
 */
VmExit Vm::run(std::uint64_t target, std::uint64_t timeout, std::size_t count)
{
    exit_status_.status = VmExitStatus::Ok;
    exit_status_.pc = 0;

    std::uint64_t start_address = get_register(UC_X86_REG_RIP);
    uc_err err = uc_emu_start(uc_, start_address, target, timeout, count);

    if (exit_status_.status != VmExitStatus::Ok)
        return exit_status_;

    exit_status_.pc = get_register(UC_X86_REG_RIP);

    switch (err)
    {
    case UC_ERR_READ_UNMAPPED:
    case UC_ERR_WRITE_UNMAPPED:
    case UC_ERR_FETCH_UNMAPPED:
        exit_status_.status = VmExitStatus::MemoryUnmapped;
        break;
    case UC_ERR_READ_PROT:
    case UC_ERR_WRITE_PROT:
    case UC_ERR_FETCH_PROT:
        exit_status_.status = VmExitStatus::MemoryProtection;
    case UC_ERR_INSN_INVALID:
        exit_status_.status = VmExitStatus::InvalidInstruction;
    case UC_ERR_EXCEPTION:
        exit_status_.status = VmExitStatus::Trap;
        break;
    case UC_ERR_OK:
        exit_status_.status = VmExitStatus::Ok;
        break;
    default:
        exit_status_.status = VmExitStatus::Unknown;
    }

    if (exit_status_.status != VmExitStatus::Unknown)
        return exit_status_;

    std::size_t is_timeout = 0;

    // XXX: Maybe do error checking
    uc_query(uc_, UC_QUERY_TIMEOUT, &is_timeout);

    if (is_timeout || exit_status_.pc != target)
        exit_status_.status = VmExitStatus::Timeout;

    return exit_status_;
}

void Vm::stop(VmExit status)
{
    exit_status_ = status;
    uc_emu_stop(uc_);
}

void Vm::add_page(std::uint64_t address, std::size_t size, int prot)
{
    mmu_.add_page(address, size, prot);
}

void Vm::add_page(std::uint64_t address, std::size_t size, int prot, const void* data)
{
    mmu_.add_page(address, size, prot, data);
}

// Setting up the plumbing for unicorn hooks
namespace
{

void unicorn_code_hook(uc_engine* uc, std::uint64_t address, std::uint32_t size, void* user_data)
{
    Vm::CodeHookTpl* hook = reinterpret_cast<Vm::CodeHookTpl*>(user_data);
    hook->operator()(address, size);
}

void unicorn_mem_hook(uc_engine* uc, uc_mem_type type, std::uint64_t address, int size, std::int64_t value,
        void *user_data)
{
    Vm::MemOpTpl* hook = reinterpret_cast<Vm::MemOpTpl*>(user_data);
    hook->operator()(address, size, value);
}

void unicorn_intr_hook(uc_engine* uc, std::uint32_t intno, void* user_data)
{
    Vm::IntHookTpl* hook = reinterpret_cast<Vm::IntHookTpl*>(user_data);
    hook->operator()(intno);
}

}

/** \brief Registers a vm instruction hook.
 *
 * Registers a hook that will be executed on every instruction. Optionally a
 * range can be supplied.
 */
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

/** \brief Registers a vm basic block hook.
 *
 * Registers a hook that will be executed on every basic block. Optionally a
 * range can be supplied.
 */
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

/** \brief Registers a read hook.
 *
 * Registers a vm hook that will be executed on every read operation. Optionally
 * a range can be supplied.
 */
void Vm::add_read_hook(MemOpHook hook, std::uint64_t begin, std::uint64_t end)
{
    uc_hook unicorn_hook;

    auto cb = new MemOpTpl([this, hook](std::uint64_t address, int size, std::int64_t value){
        hook(*this, address, size, value);
    });

    mem_hooks_.push_back(cb);

    uc_err err = uc_hook_add(uc_, &unicorn_hook, UC_HOOK_MEM_READ,
            reinterpret_cast<void*>(&unicorn_mem_hook),
            reinterpret_cast<void*>(cb), begin, end);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("add_read_hook: {}", uc_strerror(err)));

    hooks_.push_back(unicorn_hook);
}

/** \brief Registers a write hook.
 *
 * Registers a vm hook that will be executed on every write operation. Optionally
 * a range can be supplied.
 */
void Vm::add_write_hook(MemOpHook hook, std::uint64_t begin, std::uint64_t end)
{
    uc_hook unicorn_hook;

    auto cb = new MemOpTpl([this, hook](std::uint64_t address, int size, std::int64_t value){
        hook(*this, address, size, value);
    });

    mem_hooks_.push_back(cb);

    uc_err err = uc_hook_add(uc_, &unicorn_hook, UC_HOOK_MEM_WRITE,
            reinterpret_cast<void*>(&unicorn_mem_hook),
            reinterpret_cast<void*>(cb), begin, end);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("add_write_hook: {}", uc_strerror(err)));

    hooks_.push_back(unicorn_hook);
}

void Vm::add_intr_hook(IntHook hook, std::uint64_t begin, std::uint64_t end)
{
    uc_hook unicorn_hook;

    auto cb = new IntHookTpl([this, hook](std::uint64_t intno) {
            hook(*this, intno);
    });

    intr_hooks_.push_back(cb);

    uc_err err = uc_hook_add(uc_, &unicorn_hook, UC_HOOK_INTR,
            reinterpret_cast<void*>(&unicorn_intr_hook),
            reinterpret_cast<void*>(cb), begin, end);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("add_intr_hook: {}", uc_strerror(err)));

    hooks_.push_back(unicorn_hook);
}

void Vm::install_internal_hooks_()
{
    // Install mem unmapped hook
    uc_hook unmapped_hook;

    uc_err err = uc_hook_add(uc_, &unmapped_hook, UC_HOOK_MEM_UNMAPPED,
            reinterpret_cast<void*>(&unmapped_cb_),
            reinterpret_cast<void*>(this), 1, 0);

    if (err != UC_ERR_OK)
        throw std::runtime_error(fmt::format("unmap_hook_add: {}", uc_strerror(err)));
}

}
