#ifndef RANDOM_HH
#define RANDOM_HH

#include <cstdint>

namespace ssnap
{

// https://github.com/wangyi-fudan/wyhash/blob/master/wyhash32.h
class Prng
{
public:
    /**
     * Initializes the prng with a random seed.
     */
    Prng();

    Prng(std::uint64_t seed)
        : seed_(seed)
    {}

    inline std::uint64_t operator()()
    {
        seed_ += 0xa0761d6478bd642full;
        std::uint64_t see1 = seed_ ^ 0xe7037ed1a0b428dbull;
        see1 *= (see1 >> 32) | (see1 << 32);
        return  (seed_* ((seed_ >> 32) | (seed_ << 32))) ^ ((see1 >> 32) | (see1 << 32));
    }

private:
    std::uint64_t seed_;
};

};

#endif
