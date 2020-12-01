#ifndef BLOCKHASHER_HH
#define BLOCKHASHER_HH

#include <cstdint>

namespace ssnap
{

/**
 * Utility for producing a series of hashes given a series of basic blocks
 * (used for the bitmap).
 */
class BlockHasher
{
public:
    /**
     * Initializes the block hasher with a random starting value.
     */
    BlockHasher();

    BlockHasher(std::uint64_t seed)
        : seed_(seed), current_(seed)
    {}

    /**
     * Returns the next hash given the current basic block address.
     * Shamelessly stolen from afl-qemu
     */
    inline std::uint64_t next(std::uint64_t address)
    {
        std::uint64_t ret = current_ ^ ((address >> 4) ^ (address << 8));
        current_ = ret >> 1;
        return ret;
    }

    void reset()
    {
        current_ = seed_;
    }

private:
    std::uint64_t seed_;
    std::uint64_t current_;
};

}

#endif
