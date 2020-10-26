#ifndef BUMPALLOCATOR_HH
#define BUMPALLOCATOR_HH

#include <cstdint>
#include <vector>

namespace ssnap
{

class BumpAllocator
{
public:
    BumpAllocator(std::uint64_t base, std::uint64_t size);

    bool check_access(std::uint64_t address, std::uint64_t size) const;
    std::uint64_t alloc(std::uint64_t size);

    std::uint64_t size() const
    {
        return heap_size_;
    }

    std::uint64_t base() const
    {
        return heap_base_;
    }

    void reset();

private:
    struct Block
    {
        std::uint64_t start;
        std::uint64_t end;

        Block(std::uint64_t s, std::uint64_t e)
            : start(s), end(e)
        {};
    };


    std::uint64_t heap_base_;
    std::uint64_t heap_size_;
    std::uint64_t heap_offset_;

    std::vector<Block> allocated_;
};

}

#endif
