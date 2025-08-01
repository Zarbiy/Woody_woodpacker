#include "woody_packer.h"

unsigned char *add_section_64(unsigned char *file, t_elf *elf, unsigned long file_size, unsigned long *new_file_size, Elf64_Off *func_offset, Elf64_Xword *func_size, Elf64_Addr *func_vaddr) {
    const char new_data[] =
        "\x48\x31\xc0"                  // xor    rax, rax
        "\x48\xc7\xc7\x01\x00\x00\x00"  // mov    rdi, 1
        "\x48\x8d\x35\x20\x00\x00\x00"  // lea    rsi, [rip+0x20]
        "\xba\x0f\x00\x00\x00"          // mov    edx, 14
        "\xb8\x01\x00\x00\x00"          // mov    eax, 1
        "\x0f\x05"                      // syscall (write)
        "\x48\x31\xff"                  // xor    edi, edi
        "\xb8\x3c\x00\x00\x00"          // mov    eax, 60
        "\x0f\x05"                      // syscall (exit)
        "....WOODY....\n";

    const char *new_section_name = ".add";
    size_t new_data_size = sizeof(new_data) - 1;
    size_t new_name_size = strlen(new_section_name) + 1;
    size_t align = 0x1000;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Phdr *ph_table = (Elf64_Phdr *)(file + ehdr->e_phoff);

    // Trouver dernier PT_LOAD, son adresse de base (p_vaddr - p_offset) et ses limites
    Elf64_Addr max_vaddr = 0;
    Elf64_Off max_offset = 0;
    Elf64_Addr base_vaddr = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (ph_table[i].p_type == PT_LOAD) {
            Elf64_Addr end_vaddr = ph_table[i].p_vaddr + ph_table[i].p_memsz;
            Elf64_Off end_offset = ph_table[i].p_offset + ph_table[i].p_filesz;
            if (end_vaddr > max_vaddr) {
                max_vaddr = end_vaddr;
                max_offset = end_offset;
                base_vaddr = ph_table[i].p_vaddr - ph_table[i].p_offset;
            }
        }
    }

    Elf64_Off aligned_max_offset = (max_offset + align - 1) & ~(align - 1);
    Elf64_Addr new_vaddr = base_vaddr + aligned_max_offset;
    Elf64_Off code_offset = aligned_max_offset; // offset dans le fichier aligné

    Elf64_Shdr *sh_table = (Elf64_Shdr *)(file + elf->offset_section_table);
    Elf64_Shdr *shstrtab = &sh_table[ehdr->e_shstrndx];

    size_t shstrtab_offset = shstrtab->sh_offset;
    size_t name_offset = shstrtab->sh_size;

    size_t min_needed = shstrtab_offset + shstrtab->sh_size + new_name_size;
    size_t new_section_table_offset = (code_offset + new_data_size + align - 1) & ~(align - 1);
    size_t new_ph_table_offset = new_section_table_offset + (ehdr->e_shnum + 1) * sizeof(Elf64_Shdr);
    size_t phdr_end = new_ph_table_offset + (ehdr->e_phnum + 1) * sizeof(Elf64_Phdr);
    if (*new_file_size < min_needed)
        *new_file_size = min_needed;
    if (*new_file_size < phdr_end)
        *new_file_size = phdr_end;

    unsigned char *new_file = calloc(1, *new_file_size);
    if (!new_file)
        return NULL;

    memcpy(new_file, file, file_size);

    memcpy(new_file + code_offset, new_data, new_data_size);

    memcpy(new_file + shstrtab_offset, file + shstrtab_offset, shstrtab->sh_size);
    memcpy(new_file + shstrtab_offset + name_offset, new_section_name, new_name_size);

    Elf64_Shdr *new_sh_table = (Elf64_Shdr *)(new_file + new_section_table_offset);
    memcpy(new_sh_table, sh_table, ehdr->e_shnum * sizeof(Elf64_Shdr));

    Elf64_Shdr *new_sh = &new_sh_table[ehdr->e_shnum];
    memset(new_sh, 0, sizeof(Elf64_Shdr));
    new_sh->sh_name = name_offset;
    new_sh->sh_type = SHT_PROGBITS;
    new_sh->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_sh->sh_offset = code_offset;
    new_sh->sh_addr = new_vaddr;
    new_sh->sh_size = new_data_size;
    new_sh->sh_addralign = 16;

    Elf64_Shdr *new_shstrtab = &new_sh_table[ehdr->e_shstrndx];
    new_shstrtab->sh_offset = shstrtab_offset;
    new_shstrtab->sh_size += new_name_size;

    Elf64_Phdr *new_ph_table = (Elf64_Phdr *)(new_file + new_ph_table_offset);
    memcpy(new_ph_table, ph_table, ehdr->e_phnum * sizeof(Elf64_Phdr));

    Elf64_Phdr *new_ph = &new_ph_table[ehdr->e_phnum];
    memset(new_ph, 0, sizeof(Elf64_Phdr));
    new_ph->p_type = PT_LOAD;
    new_ph->p_offset = code_offset;
    new_ph->p_vaddr = new_vaddr;
    new_ph->p_paddr = new_vaddr;
    new_ph->p_filesz = new_data_size;
    new_ph->p_memsz = new_data_size;
    new_ph->p_flags = PF_R | PF_X;
    new_ph->p_align = align;

    Elf64_Ehdr *new_ehdr = (Elf64_Ehdr *)new_file;
    new_ehdr->e_shoff = new_section_table_offset;
    new_ehdr->e_shnum += 1;
    new_ehdr->e_phoff = new_ph_table_offset;
    new_ehdr->e_phnum += 1;

    *func_vaddr = new_sh->sh_addr;
    *func_offset = new_sh->sh_offset;
    *func_size = new_sh->sh_size;

    return new_file;
}

