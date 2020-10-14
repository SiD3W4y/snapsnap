#include <algorithm>
#include <stdexcept>
#include <cstring>
#include "snapsnap/mmu.hh"

namespace ssnap
{

MemoryPage::MemoryPage(MemoryPage&& other)
{
    *this = std::move(other);
}

MemoryPage& MemoryPage::operator=(MemoryPage&& other)
{
    if (this == &other)
        return *this;

    if (data)
        delete[] data;

    data = other.data;
    size = other.size;
    address = other.address;
    other.data = nullptr;

    return *this;
}

Mmu::Mmu()
{}

void Mmu::add_page(std::uint64_t address, std::size_t size, int prot)
{
    // TODO: Maybe check address/size is page aligned ?
    std::uint8_t* data = new std::uint8_t[size];
    std::memset(data, 0, size);
    pages_.emplace_back(address, data, size, prot);
    dirty_.push_back(false);

    std::sort(pages_.begin(), pages_.end(), [](MemoryPage& a, MemoryPage& b) {
            return a.address < b.address;
    });
}

void Mmu::add_page(std::uint64_t address, std::size_t size, int prot, void* data)
{
    // TODO: Maybe check size is page aligned ?
    std::uint8_t* page_data = new std::uint8_t[size];
    std::memcpy(page_data, data, size);
    pages_.emplace_back(address, page_data, size, prot);
    dirty_.push_back(false);

    std::sort(pages_.begin(), pages_.end(), [](MemoryPage& a, MemoryPage& b) {
            return a.address < b.address;
    });
}

void Mmu::reset(const Mmu& other)
{
    // TODO: Implement current error type
    if (pages_.size() != other.pages_.size())
        throw std::runtime_error("Different number of pages");

    for (std::size_t i = 0; i < pages_.size(); i++)
    {
        auto& dst = pages_[i];
        auto& src = other.pages_[i];

        if (dst.address != src.size)
            throw std::runtime_error("Page address mismatch");

        if (dst.size != src.size)
            throw std::runtime_error("Page size mismatch");

        if (dst.prot != src.prot)
            throw std::runtime_error("Page permissions mismatch");

        std::memcpy(dst.data, src.data, src.size);
    }
}

void Mmu::write(std::uint64_t address, void* buffer, std::size_t size)
{
}

}
