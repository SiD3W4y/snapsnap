#include <map>
#include <atomic>
#include <string>
#include <sstream>
#include <fstream>
#include <thread>
#include <mutex>
#include <unordered_set>
#include <chrono>
#include "fmt/core.h"

#include "snapsnap/vm.hh"
#include "snapsnap/loader.hh"
#include "snapsnap/inputdb.hh"
#include "snapsnap/utility.hh"
#include "snapsnap/bumpallocator.hh"

// Symbols gathered by gdb while taking the coredump
std::map<std::string, std::uint64_t> symbol_to_addr;
std::map<std::uint64_t, std::string> addr_to_symbol;
std::unordered_set<std::uint64_t> coverage_bbs;
std::mutex coverage_bbs_mutex;

// TODO: Use atomics
std::uint8_t bitmap[1 << 18] = {0};
std::size_t coverage = 0;
std::size_t execution_count = 0;
std::size_t corpus_size = 0;
std::size_t active_workers = 0;

constexpr std::uint64_t heap_start = 0x13370000;
constexpr std::size_t heap_size = 0x1000 * 100;

void stats_thread()
{
    auto start_time = std::chrono::system_clock::now();

    for (;;)
    {
        if (active_workers == 0)
            break;

        std::this_thread::sleep_for(std::chrono::seconds(2));
        auto epoch = std::chrono::system_clock::now() - start_time;
        double epoch_s = std::chrono::duration_cast<std::chrono::seconds>(epoch).count();

        fmt::print("| Executions: {:10} | exec/s: {:10.2f} | Coverage: {:10} | Corpus: {:10} |\n",
                execution_count,
                execution_count / epoch_s,
                coverage,
                corpus_size);

        // Dump coverage to file
        {
            std::lock_guard<std::mutex> lock(coverage_bbs_mutex);
            std::ofstream of("fuzzer.cov");

            for (std::uint64_t bbaddr : coverage_bbs)
                of << fmt::format("0x{:x}\n", bbaddr);
        }
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

// Apply patches to the image before execution (here mostly redirect AVX -> SSE)
void apply_patches(ssnap::Vm& vm)
{
    std::uint64_t strchrnul_patch_addr = 0x7ffff7e6400b;
    std::uint8_t strchrnul_patch_val = 0xeb;

    std::uint64_t strchrnul_slot_addr = 0x7ffff7f93be8;
    std::uint64_t strchrnul_slot_val = 0x7ffff7e70e60;

    vm.write_raw(strchrnul_patch_addr, &strchrnul_patch_val, sizeof(strchrnul_patch_val));
    vm.write_raw(strchrnul_slot_addr, &strchrnul_slot_val, sizeof(strchrnul_slot_val));
}

ssnap::InputDB initial_input_db()
{
    ssnap::InputDB db;

    // Unit test input
    db.add_input({
        0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x0a, 0x5f, 0x6e, 0x6f, 0x6d, 0x61, 0x63, 0x68, 0x69, 0x6e, 0x65, 0x04,
        0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00,
        0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0b, 0x08, 0x6d, 0x69,
        0x6e, 0x69, 0x32, 0x30, 0x31, 0x38, 0xc0, 0x0c,
    });

   db.add_input({
       0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x08, 0x4f, 0x75, 0x65,
       0x73, 0x73, 0x61, 0x6e, 0x74, 0x0c, 0x5f, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x2d, 0x69, 0x6e,
       0x66, 0x6f, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x10,
       0x80, 0x01, 0x00, 0x00, 0x29, 0x05, 0xa0, 0x00, 0x00, 0x11, 0x94, 0x00, 0x12, 0x00, 0x04, 0x00,
       0x0e, 0x00, 0x08, 0xac, 0xde, 0x48, 0x00, 0x11, 0x22, 0xa4, 0x83, 0xe7, 0x6f, 0x0a, 0xaf
   });

   db.add_input({
       0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x34, 0x01, 0x63,
       0x01, 0x38, 0x01, 0x30, 0x01, 0x64, 0x01, 0x39, 0x01, 0x65, 0x01, 0x66, 0x01, 0x66, 0x01, 0x66,
       0x01, 0x61, 0x01, 0x63, 0x01, 0x38, 0x01, 0x32, 0x01, 0x61, 0x01, 0x37, 0x01, 0x30, 0x01, 0x30,
       0x01, 0x65, 0x01, 0x34, 0x01, 0x35, 0x01, 0x33, 0x01, 0x38, 0x01, 0x30, 0x01, 0x30, 0x01, 0x30,
       0x01, 0x62, 0x01, 0x63, 0x01, 0x31, 0x01, 0x30, 0x01, 0x61, 0x01, 0x32, 0x03, 0x69, 0x70, 0x36,
       0x04, 0x61, 0x72, 0x70, 0x61, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x01, 0x66, 0x01, 0x34, 0x01, 0x61,
       0x01, 0x65, 0x01, 0x30, 0x01, 0x62, 0x01, 0x35, 0x01, 0x36, 0x01, 0x32, 0x01, 0x33, 0x01, 0x31,
       0x01, 0x34, 0x01, 0x61, 0x01, 0x33, 0x01, 0x30, 0x01, 0x63, 0xc0, 0x2c, 0x00, 0x0c, 0x00, 0x01
   });

   corpus_size = db.size();

    return db;
}

void fuzzing_thread(ssnap::Vm& original_vm)
{
    constexpr std::uint64_t coverage_constant = 0xdeadbeefdeadbeefULL;

    // Edit if core file was re-dumped
    constexpr std::uint64_t end_address = 0x555555555459;

    ssnap::Vm fuzzing_vm = original_vm;
    std::uint64_t coverage_hash = coverage_constant;
    bool new_input = false;

    std::vector<std::uint8_t> input;
    ssnap::InputDB db = initial_input_db();

    ssnap::BumpAllocator checked_allocator(heap_start, heap_size);
    apply_patches(fuzzing_vm);

    // Coverage hook
    fuzzing_vm.add_block_hook([&](ssnap::Vm& vm, std::uint64_t address, std::uint32_t size) {
            std::uint64_t cur_loc = (address >> 4) ^ (address << 8);
            cur_loc %= sizeof(bitmap);
            std::size_t index = (coverage_constant ^ cur_loc) % sizeof(bitmap);
            coverage_hash = cur_loc >> 1;

            if (!bitmap[index])
            {
                std::lock_guard<std::mutex> lock(coverage_bbs_mutex);

                if (coverage_bbs.find(address) != coverage_bbs.end())
                     return;

                bitmap[index] = 1;
                coverage++;

                new_input = true;
                coverage_bbs.insert(address);
                auto it = addr_to_symbol.find(address);

                if (it != addr_to_symbol.end())
                    fmt::print("BLOCK: 0x{:x} ({})\n", address, it->second);
                else
                    fmt::print("BLOCK: 0x{:x}\n", address);
            }
    }, 0x555555555000, 0x55555555a000);


    // Hook calloc
    auto calloc_addr = symbol_to_addr["calloc@plt_0"];

    fuzzing_vm.add_code_hook([&](ssnap::Vm& vm, std::uint64_t address, std::uint32_t size) {
            auto nmemb = vm.get_register(UC_X86_REG_RDI);
            auto memb_size = vm.get_register(UC_X86_REG_RSI);
            auto alloc_size = nmemb * memb_size;

            auto rsp = vm.get_register(UC_X86_REG_RSP);

            std::uint64_t return_address = 0;
            vm.read(rsp, &return_address, sizeof(return_address));

            std::uint64_t alloc = checked_allocator.alloc(alloc_size);

            if (alloc == 0)
            {
                fmt::print("calloc failed\n");
                vm.stop(ssnap::VmExit(ssnap::VmExitStatus::OutOfMemory, address));
                return;
            }

            // fmt::print("[ALLOCATOR] calloc at 0x{:x} of size 0x{:x}\n", alloc, alloc_size);

            vm.set_register(UC_X86_REG_RIP, return_address);
            vm.set_register(UC_X86_REG_RAX, alloc);
    }, calloc_addr, calloc_addr+1);

    // Hook malloc
    auto malloc_addr = symbol_to_addr["malloc@plt_0"];
    fuzzing_vm.add_code_hook([&](ssnap::Vm& vm, std::uint64_t address, std::uint32_t size) {
            auto alloc_size = vm.get_register(UC_X86_REG_RAX);
            auto rsp = vm.get_register(UC_X86_REG_RSP);

            std::uint64_t return_address = 0;
            vm.read(rsp, &return_address, sizeof(return_address));

            std::uint64_t alloc = checked_allocator.alloc(alloc_size);

            if (alloc == 0)
            {
                fmt::print("malloc failed\n");
                vm.stop(ssnap::VmExit(ssnap::VmExitStatus::OutOfMemory, address));
                return;
            }

            // fmt::print("[ALLOCATOR] malloc at 0x{:x} of size 0x{:x}\n", alloc, alloc_size);

            vm.set_register(UC_X86_REG_RIP, return_address);
            vm.set_register(UC_X86_REG_RAX, alloc);
    }, malloc_addr, malloc_addr+1);

    // Hook free
    auto free_addr = symbol_to_addr["free@plt_0"];
    fuzzing_vm.add_code_hook([&](ssnap::Vm& vm, std::uint64_t address, std::uint32_t size) {
            auto free_addr = vm.get_register(UC_X86_REG_RAX);
            auto rsp = vm.get_register(UC_X86_REG_RSP);

            std::uint64_t return_address = 0;
            vm.read(rsp, &return_address, sizeof(return_address));

            // fmt::print("[ALLOCATOR] free 0x{:x}\n", free_addr);

            if (!checked_allocator.free(free_addr))
            {
                fmt::print("free failed for address 0x{:x}\n", free_addr);
                vm.stop(ssnap::VmExit(ssnap::VmExitStatus::OutOfMemory, address));
                return;
            }

            vm.set_register(UC_X86_REG_RIP, return_address);
    }, free_addr, free_addr + 1);

    // Hook errno
    // TODO: Check why it crashes when not hooked
    auto errno_addr = symbol_to_addr["__errno_location@plt"];
    fuzzing_vm.add_code_hook([](ssnap::Vm& vm, std::uint64_t address, std::uint32_t size) {
            vm.stop(ssnap::VmExit(ssnap::VmExitStatus::Ok, address));
            return;
    }, errno_addr, errno_addr + 1);

    // Hook mem write
    fuzzing_vm.add_write_hook([&](ssnap::Vm& vm, std::uint64_t address, int size, std::int64_t value) {
            vm.mark_dirty_(address);
            vm.mark_dirty_(address + size);
    });

    for (;;)
    {
        // Write input into memory
        input.clear();
        db.get_random_input(input, 3);

        auto rdx = fuzzing_vm.get_register(UC_X86_REG_RDX);
        fuzzing_vm.write(rdx, input.data(), input.size());
        fuzzing_vm.set_register(UC_X86_REG_RCX, input.size());

        ssnap::VmExit vmexit = fuzzing_vm.run(end_address);

        if (vmexit.status != ssnap::VmExitStatus::Ok) {
            fmt::print("Fault at address 0x{:x}\n", vmexit.pc);
            fmt::print("fault: {}\n", vmexit.status);

            for (auto b : input)
                fmt::print("0x{:02x}, ", b);

            fmt::print("\n");

            ssnap::utility::print_cpu_state(fuzzing_vm);
            break;
        }

        if (new_input)
        {
            corpus_size++;
            db.add_input(input);
        }

        fuzzing_vm.reset(original_vm);
        checked_allocator.reset();

        execution_count++;
        coverage_hash = coverage_constant;
        new_input = false;
    }

    active_workers--;
}

int main(int argc, char** argv)
{
    if (argc != 3)
    {
        fmt::print("usage: {} <snapshot file> <symbol file>\n", argv[0]);
        return 1;
    }

    // ssnap::Vm original_vm = ssnap::loader::from_coredump(argv[1], UC_ARCH_X86, UC_MODE_64);
    ssnap::Vm original_vm = ssnap::loader::from_snapdump(argv[1]);
    load_symbols(argv[2]);

    // Adding memory for the allocator hooks
    original_vm.add_page(heap_start, heap_size, ssnap::MemoryProtection::Read | ssnap::MemoryProtection::Write);

    fmt::print("[VM] Starting state\n");
    ssnap::utility::print_cpu_state(original_vm);

    std::thread stats(&stats_thread);

    constexpr unsigned thread_count = 8;
    std::vector<std::thread> threads;

    for (unsigned i = 0; i < thread_count; i++)
    {
        active_workers++;
        threads.emplace_back(&fuzzing_thread, std::ref(original_vm));
    }

    for (auto& t : threads)
        t.join();

    stats.join();

    return 0;
}
