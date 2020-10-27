#include <algorithm>
#include <stdexcept>
#include <cstring>
#include "fmt/core.h"
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
    prot = other.prot;
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
    add_page_internal_(address, size, prot);
}

void Mmu::add_page(std::uint64_t address, std::size_t size, int prot, const void* data)
{
    add_page_internal_(address, size, prot, data);
}

void Mmu::add_page_internal_(std::uint64_t address, std::size_t size, int prot, const void* data)
{
    if (address & (page_size_ - 1))
        throw std::runtime_error("Address not page aligned");

    if (size & (page_size_ - 1))
        throw std::runtime_error("Size not page aligned");

    const std::uint8_t* data_ptr = reinterpret_cast<const std::uint8_t*>(data);

    while (size > 0)
    {
        auto it = pages_.find(address);

        if (it != pages_.end())
            throw std::runtime_error(fmt::format("Current page allocation overlaps with page at 0x{:x}", address));

        std::uint8_t* page_data = new std::uint8_t[page_size_];

        if (data)
            std::memcpy(page_data, data_ptr, page_size_);
        else
            std::memset(page_data, 0, page_size_);

        MemoryPage page(address, page_data, page_size_, prot);
        pages_.emplace(address, std::move(page));

        address += page_size_;
        data_ptr += page_size_;
        size -= page_size_;
    }
}

void Mmu::reset(const Mmu& other)
{
    // TODO: Implement current error type
    if (pages_.size() != other.pages_.size())
        throw std::runtime_error("Different number of pages");

    for (std::uint64_t dirty_page : dirty_pages_)
    {
        auto dst_it = pages_.find(dirty_page);
        auto src_it = other.pages_.find(dirty_page);

        if (dst_it == pages_.end())
            throw std::runtime_error(fmt::format("Page 0x{:x} not found in current mmu", dirty_page));

        if (src_it == other.pages_.end())
            throw std::runtime_error(fmt::format("Page 0x{:x} not found in original mmu", dirty_page));

        auto& dst = dst_it->second;
        auto& src = src_it->second;

        if (dst.address != src.address)
            throw std::runtime_error("Page address mismatch");

        if (dst.size != src.size)
            throw std::runtime_error("Page size mismatch");

        if (dst.prot != src.prot)
            throw std::runtime_error("Page permissions mismatch");

        std::memcpy(dst.data, src.data, src.size);
    }

    dirty_pages_.clear();
}

bool Mmu::write_raw(std::uint64_t address, const void* buffer, std::size_t size)
{
    return write_internal_(address, buffer, size, false);
}

bool Mmu::write(std::uint64_t address, const void* buffer, std::size_t size)
{
    return write_internal_(address, buffer, size, true);
}

bool Mmu::read(std::uint64_t address, void* buffer, std::size_t size)
{
    auto page_address = address & ~(page_size_ - 1);
    auto it = pages_.find(page_address);

    if (it == pages_.end())
        return false;

    std::uint8_t* data_ptr = reinterpret_cast<std::uint8_t*>(buffer);

    while (size > 0 && it != pages_.end())
    {
        auto& page = it->second;

        if (address < page.address || address >= (page.address + page.size))
            return false;

        std::size_t offset_in_page = address - page.address;
        std::size_t bytes_to_eop = (page.address + page.size) - address;
        std::size_t bytes_read = std::min(size, bytes_to_eop);

        std::memcpy(data_ptr, page.data + offset_in_page, bytes_read);

        data_ptr += bytes_read;
        address += bytes_read;
        size -= bytes_read;
        ++it;
    }

    if (size > 0 && it == pages_.end())
        return false;

    return true;
}

bool Mmu::write_internal_(std::uint64_t address, const void* buffer, std::size_t size, bool dirty)
{
    auto page_address = address & ~(page_size_ - 1);
    auto it = pages_.find(page_address);

    if (it == pages_.end())
        return false;

    const std::uint8_t* data_ptr = reinterpret_cast<const std::uint8_t*>(buffer);

    while (size > 0 && it != pages_.end())
    {
        auto& page = it->second;

        if (address < page.address || address >= (page.address + page.size))
            return false;

        std::size_t offset_in_page = address - page.address;
        std::size_t bytes_to_eop = (page.address + page.size) - address;
        std::size_t bytes_written = std::min(size, bytes_to_eop);

        std::memcpy(page.data + offset_in_page, data_ptr, bytes_written);

        data_ptr += bytes_written;
        address += bytes_written;
        size -= bytes_written;
        ++it;
    }

    if (size > 0 && it == pages_.end())
        return false;

    return true;
}

void Mmu::clear_dirty()
{
    dirty_pages_.clear();
}

void Mmu::mark_dirty(std::uint64_t address)
{
    address &= ~(page_size_ - 1);
    dirty_pages_.insert(address);
}

}
