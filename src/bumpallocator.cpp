#include "snapsnap/bumpallocator.hh"

namespace ssnap
{

BumpAllocator::BumpAllocator(std::uint64_t base, std::uint64_t size)
    : heap_base_(base), heap_size_(size), heap_offset_(0)
{}

/** \brief Checks whether a memory access in the heap is valid.
 */
bool BumpAllocator::check_access(std::uint64_t address, std::uint64_t size) const
{
    for (auto& block : allocated_)
    {
        if (address < block.start && address >= block.end)
            continue;

        // Out of bound access
        if (address + size > block.end)
            return false;

        // Access is valid
        return true;
    }

    return false;
}

/** \brief Allocates a memory block from the given size.
 *
 * Allocates a 16 bytes aligned memory block from the given size. Note that
 * there is not padding at the end of the virtually created block even if
 * the requested size is not 16 bytes aligned.
 */
std::uint64_t BumpAllocator::alloc(std::uint64_t size)
{
    if (heap_offset_ + size > heap_size_)
        return 0;

    std::uint64_t alloc_offset = heap_offset_;
    std::uint64_t alloc_address = alloc_offset + heap_base_;
    heap_offset_ += size;

    // We need to align to 16 bytes for simd instructions requiring aligned
    // accesses.
    if (heap_offset_ % 16 != 0)
        heap_offset_ += (16 - (heap_offset_ % 16));

    allocated_.emplace_back(alloc_address, size);

    return heap_base_ + alloc_offset;
}

void BumpAllocator::reset()
{
    allocated_.clear();
}

}
