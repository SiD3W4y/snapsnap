#ifndef MMU_HH
#define MMU_HH

#include <vector>
#include <cstdint>

namespace ssnap
{

enum MemoryProtection
{
    Read = 1,
    Write = 2,
    Execute = 4
};

struct MemoryPage
{
    MemoryPage() = delete;
    MemoryPage(const MemoryPage& other) = delete;
    MemoryPage& operator=(const MemoryPage& other) = delete;

    MemoryPage(std::uint64_t address, std::uint8_t* data, std::size_t size, int prot)
        : address(address), data(data), size(size), prot(prot)
    {}

    ~MemoryPage()
    {
        if (data)
            delete[] data;
    }

    MemoryPage(MemoryPage&& other);
    MemoryPage& operator=(MemoryPage&& other);

    std::uint64_t address;
    std::uint8_t* data = nullptr;
    std::size_t size;
    int prot;
};

class Mmu
{
public:
    // TODO: Implement
    Mmu();
    Mmu(const Mmu& other) = delete;
    Mmu(Mmu&& other) = delete;

    // Allocates a new zeroed out page
    void add_page(std::uint64_t address, std::size_t size, int prot);

    // Allocates a new page and fill it with given data
    void add_page(std::uint64_t address, std::size_t size, int prot, void* data);

    // Reset the Mmu state to the one in other. The function will throw an
    // exception if the pages addresses and sizes are not matching, meaning you
    // can only reset from an Mmu that has the same set of pages as you.
    void reset(const Mmu& other);

    // Write data into memory without affecting the dirty bits and without
    // checking for page permissions. This function can be used to setup
    // the memory before a fuzz case.
    void write(std::uint64_t address, void* buffer, std::size_t size);

    // **Implementing** const iterators so a user can iterate over the pages
    // present in the mmu.
    auto begin()
    {
        return pages_.cbegin();
    }

    auto end()
    {
        return pages_.cend();
    }

private:
    std::vector<MemoryPage> pages_;
    std::vector<bool> dirty_;
};

}

#endif
