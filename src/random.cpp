#include <random>
#include "snapsnap/random.hh"

namespace ssnap
{

Prng::Prng()
{
    std::random_device rd;
    seed_ = (static_cast<std::uint64_t>(rd()) << 32) | (rd());
}

}
