#include "woody_packer.h"

long space_between_fini_rodata_64(unsigned char *file) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)file;

    Elf64_Shdr *sections = (Elf64_Shdr *)(file + eh->e_shoff);
    Elf64_Shdr *sh_strtab = &sections[eh->e_shstrndx];
    const char *strtab = (const char *)(file + sh_strtab->sh_offset);

    Elf64_Addr fini_end = 0, rodata_start = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *name = strtab + sections[i].sh_name;
        if (strcmp(name, ".fini") == 0)
            fini_end = sections[i].sh_addr + sections[i].sh_size;
        else if (strcmp(name, ".rodata") == 0)
            rodata_start = sections[i].sh_addr;
    }

    if (!fini_end || !rodata_start) {
        fprintf(stderr, "Sections .fini ou .rodata introuvables\n");
        return -1;
    }

    return (long)(rodata_start - fini_end);
}

Elf64_Off find_text_offset_64(unsigned char *file) {
    Elf64_Ehdr *header64 = (Elf64_Ehdr *)file;
    void *section_table = (Elf64_Shdr *)(file + header64->e_shoff);
    void *section_name = &((Elf64_Shdr *)section_table)[header64->e_shstrndx];
    char *start_name_section = (char *)(file + ((Elf64_Shdr *)section_name)->sh_offset);
    int shnum = header64->e_shnum;

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *section = &((Elf64_Shdr *)section_table)[i];
        char *name_section = start_name_section + section->sh_name;
        if (!ft_strcmp(name_section, ".text"))
            return section->sh_offset;
    }
    return 0;
}

Elf64_Addr find_text_addr_64(unsigned char *file) {
    Elf64_Ehdr *header64 = (Elf64_Ehdr *)file;
    void *section_table = (Elf64_Shdr *)(file + header64->e_shoff);
    void *section_name = &((Elf64_Shdr *)section_table)[header64->e_shstrndx];
    char *start_name_section = (char *)(file + ((Elf64_Shdr *)section_name)->sh_offset);
    int shnum = header64->e_shnum;

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *section = &((Elf64_Shdr *)section_table)[i];
        char *name_section = start_name_section + section->sh_name;
        if (!ft_strcmp(name_section, ".text"))
            return section->sh_addr;
    }
    return 0;
}

Elf64_Addr find_text_size_64(unsigned char *file) {
    Elf64_Ehdr *header64 = (Elf64_Ehdr *)file;
    void *section_table = (Elf64_Shdr *)(file + header64->e_shoff);
    void *section_name = &((Elf64_Shdr *)section_table)[header64->e_shstrndx];
    char *start_name_section = (char *)(file + ((Elf64_Shdr *)section_name)->sh_offset);
    int shnum = header64->e_shnum;

    for (int i = 0; i < shnum; i++) {
        Elf64_Shdr *section = &((Elf64_Shdr *)section_table)[i];
        char *name_section = start_name_section + section->sh_name;
        if (!ft_strcmp(name_section, ".text"))
            return section->sh_size;
    }
    return 0;
}

Elf64_Off find_main_offset_64(unsigned char *file) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (!ft_strcmp(section_name, ".symtab"))
            symtab = &shdr[i];
        else if (!ft_strcmp(section_name, ".strtab"))
            strtab = &shdr[i];
    }

    if (!symtab || !strtab) {
        printf("relevant section not found\n");
        return 0;
    }

    Elf64_Sym *symbols = (Elf64_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);

    Elf64_Addr main_addr = 0;
    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!ft_strcmp(name, "main")) {
            main_addr = symbols[i].st_value;
            break;
        }
    }

    if (!main_addr) {
        printf("main not found\n");
        return 0;
    }

    Elf64_Phdr *phdr = (Elf64_Phdr *)(file + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            Elf64_Addr start = phdr[i].p_vaddr;
            Elf64_Addr end = start + phdr[i].p_memsz;

            if (main_addr >= start && main_addr < end) {
                Elf64_Off offset = phdr[i].p_offset + (main_addr - start);
                return offset;
            }
        }
    }
    return 0;
}


Elf64_Addr find_main_addr_64(unsigned char *file) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (!ft_strcmp(section_name, ".symtab"))
            symtab = &shdr[i];
        else if (!ft_strcmp(section_name, ".strtab"))
            strtab = &shdr[i];
    }

    if (!symtab || !strtab) {
        printf("relevant section not found\n");
        return 0;
    }

    Elf64_Sym *symbols = (Elf64_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!ft_strcmp(name, "main"))
            return symbols[i].st_value;
    }

    printf("main addr not found\n");
    return 0;
}

Elf64_Addr find_main_size_64(unsigned char *file) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (!ft_strcmp(section_name, ".symtab"))
            symtab = &shdr[i];
        else if (!ft_strcmp(section_name, ".strtab"))
            strtab = &shdr[i];
    }

    if (!symtab || !strtab) {
        printf("relevant section not found\n");
        return 0;
    }

    Elf64_Sym *symbols = (Elf64_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!ft_strcmp(name, "main"))
            return symbols[i].st_size;
    }

    printf("main size not found\n");
    return 0;
}
