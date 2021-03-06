#include "fmt/core.h"
#include <unistd.h>
#include <fcntl.h>
#include <libelf.h>
#include <stdexcept>
#include "unicorn/unicorn.h"
#include "snapsnap/loader.hh"
#include "snapsnap/utility.hh"
#include "snapsnap_internal.hh"

namespace ssnap
{

namespace loader
{

namespace
{

// https://github.com/evaitl/Xcore64/blob/master/read_pc.h
struct elf_siginfo {
    int si_signo;
    int si_code;
    int si_errno;
};

struct elf_prstatus {
    struct elf_siginfo pr_info;
    short pr_cursig;
    unsigned long pr_sigpend;
    unsigned long pr_sighold;
    pid_t       pr_pid;
    pid_t       pr_ppid;
    pid_t       pr_pgrp;
    pid_t       pr_sid;
    struct timeval pr_utime;
    struct timeval pr_stime;
    struct timeval pr_cutime;
    struct timeval pr_cstime;
    // struct user_regs_struct regs;
    // int pr_fpvalid;
};

std::size_t align_size(std::size_t input, std::size_t align)
{
    if (input % align == 0)
        return input;

    return input + (align - (input % align));
}

Mmu load_pages(Elf* elf)
{
    std::size_t phdr_num;
    elf_getphdrnum(elf, &phdr_num);

    Elf64_Phdr* phdr = elf64_getphdr(elf);

    std::size_t len;
    const char* elf_base = elf_rawfile(elf, &len);

    Mmu m;

    // Load the pages into memory
    for (std::size_t i = 0; i < phdr_num; i++)
    {
        if (phdr->p_type != PT_LOAD)
        {
            phdr++;
            continue;
        }

        int prot = 0;
        char prot_str[4] = {'-', '-', '-', 0};

        if (phdr->p_flags & 1)
        {
            prot |= MemoryProtection::Execute;
            prot_str[2] = 'x';
        }
        if (phdr->p_flags & 2)
        {
            prot |= MemoryProtection::Write;
            prot_str[1] = 'w';
        }
        if (phdr->p_flags & 4)
        {
            prot |= MemoryProtection::Read;
            prot_str[0] = 'r';
        }

        m.add_page(phdr->p_vaddr, phdr->p_memsz, prot, elf_base + phdr->p_offset);

        fmt::print("[COREDUMP] Loading segment [addr=0x{:x} size=0x{:x} perms={}]\n", phdr->p_vaddr,
                phdr->p_memsz, prot_str);

        phdr++;
    }

    return m;
}

void load_regs(Elf* elf, Vm& vm)
{
    std::size_t phdr_num;
    elf_getphdrnum(elf, &phdr_num);

    Elf64_Phdr* phdr = elf64_getphdr(elf);
    Elf64_Phdr *notes = nullptr;

    std::size_t len;
    const char* elf_base = elf_rawfile(elf, &len);

    // Find the note section
    for (std::size_t i = 0; i < phdr_num;i ++)
    {
        if (phdr->p_type == PT_NOTE)
        {
            notes = phdr;
            break;
        }
    }

    if (!notes)
        throw std::runtime_error("Could not find notes segment");

    std::size_t idx = 0;
    const char* notes_base = elf_base + phdr->p_offset;
    const std::uint64_t* regs_base = nullptr;

    // Find the prstatus notes
    while (idx < notes->p_filesz)
    {
        const Elf64_Nhdr* note = reinterpret_cast<const Elf64_Nhdr*>(notes_base + idx);
        std::size_t name_size_pad = align_size(note->n_namesz, 4);
        std::size_t desc_size_pad = align_size(note->n_descsz, 4);

        if (note->n_type == NT_PRSTATUS)
        {
            std::size_t desc_off = idx + sizeof(*note) + name_size_pad + sizeof(elf_prstatus);
            regs_base = reinterpret_cast<const std::uint64_t*>(notes_base + desc_off);
            break;
        }

        idx += sizeof(*note);
        idx += name_size_pad;
        idx += desc_size_pad;
    }

    if (!regs_base)
        throw std::runtime_error("Could not find registers");

    auto& regs_ids = ssnap::utility::get_user_regs_struct(vm.arch());
    std::uint64_t fsbase = 0;
    std::uint64_t gsbase = 0;

    for (auto id : regs_ids)
    {
        if (id == UC_X86_REG_FS_BASE)
            fsbase = *regs_base;
        else if (id == UC_X86_REG_GS_BASE)
            gsbase = *regs_base;
        else
            vm.set_register(id, *regs_base);
        regs_base++;

    }

    // For some obscure reason, setting fs_base and gs_base before fs and gs is
    // a noop in unicorn. We have to remember their values and set them afterwards.
    vm.set_register(UC_X86_REG_FS_BASE, fsbase);
    vm.set_register(UC_X86_REG_GS_BASE, gsbase);

    vm.save_cpu_context();
}

}

Vm from_coredump(std::string path, VmArch arch)
{
    if (arch != VmArch::x86_64)
        throw std::runtime_error("Only x86_64 is supported for now");

    int fd = open(path.c_str(), O_RDONLY, 0);

    if (fd == -1)
        throw std::runtime_error("Could not open core file");

    elf_version(EV_CURRENT);
    Elf* elf = elf_begin(fd, ELF_C_READ_MMAP_PRIVATE, NULL);

    if (!elf)
        throw std::runtime_error(fmt::format("Could not parse elf: {}", elf_errmsg(elf_errno())));

    Elf64_Ehdr* ehdr = elf64_getehdr(elf);

    if (!ehdr)
        throw std::runtime_error("Only 64 bits binaries are supported for now");

    if (ehdr->e_type != ET_CORE)
        throw std::runtime_error("Only core dumps are supported");


    Vm vm(arch, load_pages(elf));
    load_regs(elf, vm);

    elf_end(elf);

    return vm;
}

}

}
