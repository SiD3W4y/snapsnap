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

    // Map the mmu pages into unicorn
    map_mmu_unicorn_();
}

Vm& Vm::operator=(const Vm& other)
{
    arch_ = other.arch_;
    mode_ = other.mode_;
    mmu_ = other.mmu_;

    uc_err err = uc_open(arch_, mode_, &uc_);

    if (err != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(err));

    err = uc_context_alloc(uc_, &cpu_context_);

    if (err != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(err));

    uc_context_save(other.uc_, cpu_context_);

    map_mmu_unicorn_();

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
}

void Vm::reset(const Vm& original)
{
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

void Vm::map_mmu_unicorn_()
{
    for (MemoryPage& page : mmu_)
    {
        uc_err err = uc_mem_map_ptr(uc_, page.address, page.size, page.prot, page.data);

        if (err != UC_ERR_OK)
            throw std::runtime_error(fmt::format("map_mmu_unicorn: {}", uc_strerror(err)));
    }
}

}
