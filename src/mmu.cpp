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

MemoryPage::MemoryPage(const MemoryPage& other)
{
    *this = other;
}

MemoryPage& MemoryPage::operator=(const MemoryPage& other)
{
    if (this == &other)
        return *this;

    if (data)
        delete[] data;

    address = other.address;
    data = new std::uint8_t[other.size];
    size = other.size;
    prot = other.prot;

    std::memcpy(data, other.data, size);

    return *this;
}


Mmu::Mmu(std::uint64_t page_size)
    : page_size_(page_size)
{}

Mmu::Mmu(Mmu&& other)
{
    *this = std::move(other);
}

Mmu& Mmu::operator=(Mmu&& other)
{
    pages_ = std::move(other.pages_);

    return *this;
}

Mmu::Mmu(const Mmu& other)
{
    *this = other;
}

Mmu& Mmu::operator=(const Mmu& other)
{
    pages_ = other.pages_;

    return *this;
}

void Mmu::add_page(std::uint64_t address, std::size_t size, int prot)
{
    if (address & (page_size_ - 1))
        throw std::runtime_error("Address not page aligned");

    if (size & (page_size_ - 1))
        throw std::runtime_error("Address not page aligned");

    std::uint8_t* data = new std::uint8_t[size];
    std::memset(data, 0, size);
    pages_.emplace_back(address, data, size, prot);

    std::sort(pages_.begin(), pages_.end(), [](MemoryPage& a, MemoryPage& b) {
            return a.address < b.address;
    });
}

void Mmu::add_page(std::uint64_t address, std::size_t size, int prot, void* data)
{
    if (address & (page_size_ - 1))
        throw std::runtime_error("Address not page aligned");

    if (size & (page_size_ - 1))
        throw std::runtime_error("Address not page aligned");

    std::uint8_t* page_data = new std::uint8_t[size];
    std::memcpy(page_data, data, size);
    pages_.emplace_back(address, page_data, size, prot);

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

void Mmu::clear_dirty()
{
    for (MemoryPage& page : pages_)
        page.dirty = false;
}

bool Mmu::write_raw(std::uint64_t address, void* buffer, std::size_t size)
{
    return write_internal_(address, buffer, size, false);
}

bool Mmu::write(std::uint64_t address, void* buffer, std::size_t size)
{
    return write_internal_(address, buffer, size, true);
}

bool Mmu::read(std::uint64_t address, void* buffer, std::size_t size)
{
    // XXX: This is a linear search, use a better algorithm if it becomes a bottleneck
    auto it = std::find_if(pages_.begin(), pages_.end(), [address](MemoryPage& p) {
            return address >= p.address && address < (p.address + p.size);
    });

    if (it == pages_.end())
        return false;

    std::uint8_t* data_ptr = reinterpret_cast<std::uint8_t*>(buffer);

    while (size > 0 && it != pages_.end())
    {
        if (address < it->address || address >= (it->address + it->size))
            return false;

        std::size_t offset_in_page = address - it->address;
        std::size_t bytes_to_eop = (it->address + it->size) - address;
        std::size_t bytes_read = std::min(size, bytes_to_eop);

        std::memcpy(data_ptr, it->data + offset_in_page, bytes_read);

        data_ptr += bytes_read;
        address += bytes_read;
        size -= bytes_read;
        ++it;
    }

    if (size > 0 && it == pages_.end())
        return false;

    return true;
}

bool Mmu::write_internal_(std::uint64_t address, void* buffer, std::size_t size, bool dirty)
{
    // XXX: This is a linear search, use a better algorithm if it becomes a bottleneck
    auto it = std::find_if(pages_.begin(), pages_.end(), [address](MemoryPage& p) {
            return address >= p.address && address < (p.address + p.size);
    });

    if (it == pages_.end())
        return false;

    std::uint8_t* data_ptr = reinterpret_cast<std::uint8_t*>(buffer);

    while (size > 0 && it != pages_.end())
    {
        if (address < it->address || address >= (it->address + it->size))
            return false;

        if (dirty)
            it->dirty = true;

        std::size_t offset_in_page = address - it->address;
        std::size_t bytes_to_eop = (it->address + it->size) - address;
        std::size_t bytes_written = std::min(size, bytes_to_eop);

        std::memcpy(it->data + offset_in_page, data_ptr, bytes_written);

        data_ptr += bytes_written;
        address += bytes_written;
        size -= bytes_written;
        ++it;
    }

    if (size > 0 && it == pages_.end())
        return false;

    return true;
}

}
