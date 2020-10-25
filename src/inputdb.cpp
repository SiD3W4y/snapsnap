#include <random>
#include <ctime>
#include "snapsnap/inputdb.hh"

namespace ssnap
{

InputDB::InputDB()
    : prng_(std::time(nullptr))
{
}

InputDB::InputDB(std::size_t seed)
    : prng_(seed)
{
}

void InputDB::add_input(std::vector<std::uint8_t> input)
{
    for (auto& dbin : inputs_)
    {
        if (dbin == input)
            return;
    }

    inputs_.push_back(input);
}

void InputDB::mutate_bitflip_(std::vector<std::uint8_t>& input)
{
    std::size_t index = prng_() % input.size();
    std::size_t bitindex = prng_() % 8;

    input[index] ^= (1 << bitindex);
}

void InputDB::mutate_byteflip_(std::vector<std::uint8_t>& input)
{
    std::size_t index = prng_() % input.size();
    std::uint8_t randbyte = prng_() & 0xff;

    input[index] ^= randbyte;
}

void InputDB::get_random_input(std::vector<std::uint8_t>& new_input, std::size_t mutations)
{
    if (inputs_.size() == 0)
        return;

    new_input = inputs_[prng_() % inputs_.size()];
    std::size_t mutation_count = prng_() % (mutations + 1);
    constexpr std::size_t mutations_method_count = 2;

    for (std::size_t i = 0; i < mutation_count; i++)
    {
        std::size_t mutation_method = prng_() % mutations_method_count;

        switch (mutation_method) {
            case 0:
                mutate_bitflip_(new_input);
                break;
            case 1:
                mutate_byteflip_(new_input);
                break;
            default:
                break;
        }
    }
}


}
