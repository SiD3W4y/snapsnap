#include <map>
#include <string>
#include <sstream>
#include <fstream>
#include <thread>
#include <chrono>
#include "fmt/core.h"
#include "snapsnap/vm.hh"
#include "snapsnap/loader.hh"
#include "snapsnap/inputdb.hh"
#include "snapsnap/utility.hh"

// Symbols gathered by gdb while taking the coredump
std::map<std::string, std::uint64_t> symbol_to_addr;
std::map<std::uint64_t, std::string> addr_to_symbol;

std::uint8_t bitmap[1 << 18] = {0};
std::size_t coverage = 0;
std::size_t execution_count = 0;
std::size_t corpus_size = 0;

uint64_t pc_hash(uint64_t key)
{
    key ^= key >> 33;
    key *= 0xff51afd7ed558ccd;
    key ^= key >> 33;
    key *= 0xc4ceb9fe1a85ec53;
    key ^= key >> 33;

    return key;
}

void stats_thread()
{
    auto start_time = std::chrono::system_clock::now();

    for (;;)
    {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        auto epoch = std::chrono::system_clock::now() - start_time;
        double epoch_s = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();

        fmt::print("[FUZZER] Executions: {:10} | exec/s: {:10.2f} | Coverage: {:10} | Corpus: {:10}\n",
                execution_count,
                execution_count / epoch_s,
                coverage,
                corpus_size);
    }
}

void load_symbols(const char* path)
{
    std::ifstream is(path);

    if (!is)
        throw std::runtime_error(fmt::format("Could not open symbol file: {}", path));

    std::string line;

    while (std::getline(is, line))
    {
        std::stringstream ss(line);

        std::uint64_t address;
        std::string name;

        ss >> std::hex >> address;

        if (!ss)
            throw std::runtime_error(fmt::format("Could not parse address in line: {}", line));

        ss >> name;

        if (!ss)
            throw std::runtime_error(fmt::format("Could not parse symbol name in line: {}", line));

        symbol_to_addr.emplace(name, address);
        addr_to_symbol.emplace(address, name);
    }

    fmt::print("[SYMBOLS] Symbol count: {}\n", symbol_to_addr.size());
}

ssnap::InputDB initial_input_db()
{
    ssnap::InputDB db;

    // Unitest input
    // db.add_input({
    //     0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    //     0x0a, 0x5f, 0x6e, 0x6f, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x04,
    //     0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00,
    //     0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0b, 0x08, 0x6d, 0x69,
    //     0x6e, 0x69, 0x32, 0x30, 0x31, 0x38, 0xc0, 0x0c,
    // });
    std::vector<std::uint8_t> t;

    for (unsigned i = 0; i < 256; i++)
        t.push_back(0x41);

    db.add_input(t);

    return db;
}

void fuzzing_thread(ssnap::Vm& original_vm)
{
    constexpr std::uint64_t coverage_constant = 0xdeadbeefdeadbeefULL;

    // Edit if core file was re-dumped
    constexpr std::uint64_t end_address = 0x555555555459;

    ssnap::Vm fuzzing_vm = original_vm;
    std::uint64_t coverage_hash = coverage_constant;

    std::vector<std::uint8_t> input;
    ssnap::InputDB db = initial_input_db();

    // Coverage hook
    fuzzing_vm.add_block_hook([&](ssnap::Vm& vm, std::uint64_t address, std::uint32_t size) {
            coverage_hash ^= pc_hash(address);
            std::size_t index = coverage_hash % sizeof(bitmap);

            if (!bitmap[index])
            {
                bitmap[index] ^= 1;
                coverage++;

                db.add_input(input);
                corpus_size = db.size();

                auto it = addr_to_symbol.find(address);

                if (it != addr_to_symbol.end())
                    fmt::print("BLOCK: 0x{:x} ({})\n", address, it->second);
                else
                    fmt::print("BLOCK: 0x{:x}\n", address);
            }
    });

    for (;;)
    {
        // Write input into memory
        input.clear();
        db.get_random_input(input, 0);

        // auto rdx = fuzzing_vm.get_register(UC_X86_REG_RDX);
        // fuzzing_vm.write(rdx, input.data(), input.size());
        // fuzzing_vm.set_register(UC_X86_REG_RCX, input.size());
        std::uint32_t is_avx = 0;
        std::uint64_t is_avx_addr = 0x7ffff7ffc5bc;

        fuzzing_vm.write(is_avx_addr, &is_avx, sizeof(is_avx));

        ssnap::VmExit vmexit = fuzzing_vm.run(end_address);

        if (vmexit.status != ssnap::VmExitStatus::Ok) {
            fmt::print("Fault at address 0x{:x}\n", vmexit.pc);
            break;
        }

        fuzzing_vm.reset(original_vm);

        execution_count++;
        coverage_hash = coverage_constant;
    }
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        fmt::print("usage: {} <core file> <symbol file>\n", argv[0]);
        return 1;
    }

    ssnap::Vm original_vm = ssnap::loader::from_coredump(argv[1], UC_ARCH_X86, UC_MODE_64);
    load_symbols(argv[2]);

    fmt::print("[VM] Starting state\n");
    ssnap::utility::print_cpu_state(original_vm);

    std::thread stats(&stats_thread);

    constexpr unsigned thread_count = 1;
    std::vector<std::thread> threads;

    for (unsigned i = 0; i < thread_count; i++)
        threads.emplace_back(&fuzzing_thread, std::ref(original_vm));

    stats.join();

    return 0;
}
