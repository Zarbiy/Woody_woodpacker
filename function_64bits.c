#include "woody_packer.h"

unsigned char *add_section_64(unsigned char *file, t_elf *elf, unsigned long file_size, unsigned long *new_file_size, Elf64_Off *func_offset, Elf64_Xword *func_size, Elf64_Addr *func_vaddr) {
    const char new_data[] =
        "\x48\x31\xc0"                                  // xor    rax, rax
        "\x48\xc7\xc7\x01\x00\x00\x00"                  // mov    rdi, 1
        "\x48\x8d\x35\x10\x00\x00\x00"                  // lea    rsi, [rip+0x10]
        "\xba\x0f\x00\x00\x00"                          // mov    edx, 14
        "\xb8\x01\x00\x00\x00"                          // mov    eax, 1
        "\x0f\x05"                                      // syscall
        "....WOODY....\n";

    const char *new_section_name = ".func";
    size_t new_data_size = sizeof(new_data) - 1;
    size_t new_name_size = strlen(new_section_name) + 1;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *sh_table = (Elf64_Shdr *)(file + elf->offset_section_table);
    Elf64_Shdr *shstrtab = &sh_table[ehdr->e_shstrndx];

    // Nouveau offset aligné pour code .func
    size_t align = 8;
    size_t code_offset = (file_size + align - 1) & ~(align - 1);

    // Nouveau offset aligné pour .shstrtab (après le code)
    size_t shstrtab_offset = (code_offset + new_data_size + align - 1) & ~(align - 1);

    // Nouvelle taille totale (inclut nouvelle shstrtab + table section)
    size_t new_section_table_offset = (shstrtab_offset + shstrtab->sh_size + new_name_size + align - 1) & ~(align - 1);
    *new_file_size = new_section_table_offset + (ehdr->e_shnum + 1) * sizeof(Elf64_Shdr);

    // Allocation
    unsigned char *new_file = calloc(1, *new_file_size);
    if (!new_file)
        return NULL;

    // Copie ancien file
    memcpy(new_file, file, file_size);

    // === Section .func
    memcpy(new_file + code_offset, new_data, new_data_size);

    // === Nouvelle .shstrtab (copie + ajout nom section)
    memcpy(new_file + shstrtab_offset, file + shstrtab->sh_offset, shstrtab->sh_size);
    size_t name_offset = shstrtab->sh_size;  // position dans .shstrtab
    memcpy(new_file + shstrtab_offset + name_offset, new_section_name, new_name_size);

    // === Mise à jour header de .shstrtab
    Elf64_Shdr *new_sh_table = (Elf64_Shdr *)(new_file + new_section_table_offset);
    memcpy(new_sh_table, sh_table, ehdr->e_shnum * sizeof(Elf64_Shdr));

    Elf64_Shdr *new_shstrtab = &new_sh_table[ehdr->e_shstrndx];
    new_shstrtab->sh_offset = shstrtab_offset;
    new_shstrtab->sh_size += new_name_size;

    // === Création section .func
    Elf64_Shdr *new_sh = &new_sh_table[ehdr->e_shnum];
    memset(new_sh, 0, sizeof(Elf64_Shdr));
    new_sh->sh_name = name_offset;
    new_sh->sh_type = SHT_PROGBITS;
    new_sh->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_sh->sh_offset = code_offset;
    new_sh->sh_size = new_data_size;
    new_sh->sh_addralign = 1;

    // Calcul de l'adresse virtuelle (sh_addr) via segment exécutable
    Elf64_Phdr *phdr = (Elf64_Phdr *)(new_file + ehdr->e_phoff);
    int found = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            new_sh->sh_addr = phdr[i].p_vaddr + (new_sh->sh_offset - phdr[i].p_offset);
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "ERROR: No executable LOAD segment found\n");
        free(new_file);
        return NULL;
    }

    // Redirection e_entry → vers .func
    Elf64_Ehdr *new_ehdr = (Elf64_Ehdr *)new_file;
    new_ehdr->e_shoff = new_section_table_offset;
    new_ehdr->e_shnum += 1;
    // new_ehdr->e_entry = new_sh->sh_addr;
    
    *func_vaddr = new_sh->sh_addr;
    *func_offset = new_sh->sh_offset;
    *func_size = new_sh->sh_size;
    return new_file;
}

void update_load_segment_to_execute_64(unsigned char *file, Elf64_Off func_offset, Elf64_Xword func_size) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(file + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            Elf64_Off seg_end = phdr[i].p_offset + phdr[i].p_filesz;
            Elf64_Off func_end = func_offset + func_size;
            if (func_end > seg_end) {
                Elf64_Word extend_size = func_end - phdr[i].p_offset;
                phdr[i].p_filesz = extend_size;
                phdr[i].p_memsz = extend_size;
            }
            break;
        }
    }
}

Elf64_Off get_file_offset_64(Elf64_Ehdr *ehdr, Elf64_Addr vaddr) {
    Elf64_Phdr *ph = (Elf64_Phdr *)((char *)ehdr + ehdr->e_phoff);
    for(int i = 0; i < ehdr->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            Elf64_Addr seg_start = ph[i].p_vaddr;
            Elf64_Addr seg_end   = seg_start + ph[i].p_memsz;
            if (vaddr >= seg_start && vaddr < seg_end) {
                return ph[i].p_offset + (vaddr - seg_start);
            }
        }
    }
    return 0;
}

void patch_entry_to_func_64(unsigned char *file, Elf64_Ehdr *ehdr, Elf64_Addr func_addr)
{
    Elf64_Off entry_offset = get_file_offset_64(ehdr, ehdr->e_entry);
    Elf64_Addr old_entry   = ehdr->e_entry;
    // Calcul du rel32
    int32_t rel = (int32_t)(func_addr - (old_entry + 5));

    // On patch en mémoire mappée
    unsigned char *p = file + entry_offset;
    p[0] = 0xE9; // opcode jmp rel32
    memcpy(p + 1, &rel, 4);

    // Si tu veux écraser plus d’instructions, pad avec NOPs
    // for(int i = 5; i < N; i++) p[i] = 0x90;

    // enfin, mets à jour e_entry pour conserver la cohérence au debug
    ehdr->e_entry = old_entry; // ou reste sur func_addr, selon ton choix
}
