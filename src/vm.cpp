#include <string>
#include <stdexcept>
#include <cstring>
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

    uc_err err = uc_open(arch_, mode_, &uc_);

    if (err != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(err));

    err = uc_context_alloc(uc_, &cpu_context_);

    if (err != UC_ERR_OK)
        throw std::runtime_error(uc_strerror(err));

    std::size_t context_size = uc_context_size(uc_);
    std::memcpy(cpu_context_, other.cpu_context_, context_size);

    return *this;
}

Vm::Vm(const Vm& other)
{
    *this = other;
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
    return mmu_.write_raw(address, buffer, size);
}

}
