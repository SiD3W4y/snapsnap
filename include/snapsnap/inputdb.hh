#ifndef INPUTDB_HH
#define INPUTDB_HH

#include <vector>
#include <cstdint>
#include "random.hh"

namespace ssnap
{

// Database containing the input corpus
class InputDB
{
public:
    InputDB() = default;
    InputDB(std::size_t seed);

    void add_input(std::vector<std::uint8_t> input);
    void get_random_input(std::vector<std::uint8_t>& new_input, std::size_t mutations);

    std::size_t size() const
    {
        return inputs_.size();
    }

private:
    void mutate_bitflip_(std::vector<std::uint8_t>& input);
    void mutate_byteflip_(std::vector<std::uint8_t>& input);
    void mutate_delete_(std::vector<std::uint8_t>& input);

    std::vector<std::vector<std::uint8_t>> inputs_;
    Prng prng_;
};

}

#endif
