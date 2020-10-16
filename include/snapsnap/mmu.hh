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
    MemoryPage(const MemoryPage& other);
    MemoryPage& operator=(const MemoryPage& other);

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
    bool dirty = false;
    int prot;
};

class Mmu
{
public:
    Mmu(std::uint64_t page_size = 0x1000);

    Mmu(Mmu&& other);
    Mmu& operator=(Mmu&& other);

    Mmu(const Mmu& other);
    Mmu& operator=(const Mmu& other);

    // Allocates a new zeroed out page
    void add_page(std::uint64_t address, std::size_t size, int prot);

    // Allocates a new page and fill it with given data
    void add_page(std::uint64_t address, std::size_t size, int prot, void* data);

    // Reset the Mmu state to the one in other. The function will throw an
    // exception if the pages addresses and sizes are not matching, meaning you
    // can only reset from an Mmu that has the same set of pages as you.
    void reset(const Mmu& other);

    // Clears the dirty bits
    void clear_dirty();

    // Write data into memory without affecting the dirty bits and without
    // checking for page permissions. This function can be used to setup
    // the memory before a fuzz case.
    //
    // Returns true if the write succeeded.
    bool write_raw(std::uint64_t address, const void* buffer, std::size_t size);

    // Write data into memory and set the dirty bit if needed.
    //
    // Returns true if the write succeeded.
    bool write(std::uint64_t address, const void* buffer, std::size_t size);

    // Reads data from memory
    bool read(std::uint64_t address, void* buffer, std::size_t size);

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
    bool write_internal_(std::uint64_t address, const void* buffer, std::size_t size, bool dirty);

    // Checks whether a range overlaps with a page
    bool range_overlap_page_(std::uint64_t address, std::size_t size);

    std::uint64_t page_size_;
    std::vector<MemoryPage> pages_;
};

}

#endif
