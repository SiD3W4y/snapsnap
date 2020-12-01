#include <random>
#include "snapsnap/blockhasher.hh"

namespace ssnap
{

BlockHasher::BlockHasher()
{
    std::random_device rd;
    seed_ = (static_cast<std::uint64_t>(rd()) << 32) | (rd());
    current_ = seed_;
}

}
