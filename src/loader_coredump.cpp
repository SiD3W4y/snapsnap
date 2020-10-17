#include "fmt/core.h"
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdexcept>
#include "snapsnap/loader.hh"

namespace ssnap
{

namespace loader
{

Vm load_coredump(std::string path, uc_arch arch, uc_mode mode)
{
    int fd = open(path.c_str(), O_RDONLY, 0);

    if (fd == -1)
        throw std::runtime_error("Could not open core file");

    elf_version(EV_CURRENT);
    Elf* elf = elf_begin(fd, ELF_C_READ, NULL);

    if (!elf)
        throw std::runtime_error(fmt::format("Could not parse elf: {}", elf_errmsg(elf_errno())));

    Elf64_Ehdr* ehdr = elf64_getehdr(elf);

    if (!ehdr)
        throw std::runtime_error("Only 64 bits binaries are supported for now");

    if (ehdr->e_type != ET_CORE)
        throw std::runtime_error("Only core dumps are supported");

    Elf64_Phdr* phdr = elf64_getphdr(elf);
    std::size_t len;
    const char* elf_base = elf_rawfile(elf, &len);

    Mmu m;

    // Load the pages into memory
    for (std::size_t i = 0; i < ehdr->e_phnum; i++)
    {
        if (phdr->p_type != PT_LOAD)
        {
            phdr++;
            continue;
        }

        m.add_page(phdr->p_vaddr, phdr->p_memsz, 7, elf_base + phdr->p_offset);

        fmt::print("[COREDUMP] Loading segment [addr=0x{:x} size=0x{:x}]\n", phdr->p_vaddr,
                phdr->p_memsz);

        phdr++;
    }

    Vm vm(arch, mode, std::move(m));

    elf_end(elf);

    return vm;
}

}

}
