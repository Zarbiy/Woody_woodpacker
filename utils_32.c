#include "woody_packer.h"

long space_between_fini_rodata_32(unsigned char *file) {
    Elf32_Ehdr *eh = (Elf32_Ehdr *)file;

    Elf32_Shdr *sections = (Elf32_Shdr *)(file + eh->e_shoff);
    Elf32_Shdr *sh_strtab = &sections[eh->e_shstrndx];
    const char *strtab = (const char *)(file + sh_strtab->sh_offset);

    Elf32_Addr fini_end = 0, rodata_start = 0;

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

Elf32_Off find_text_offset_32(unsigned char *file) {
    Elf32_Ehdr *header32 = (Elf32_Ehdr *)file;
    void *section_table = (Elf32_Shdr *)(file + header32->e_shoff);
    void *section_name = &((Elf32_Shdr *)section_table)[header32->e_shstrndx];
    char *start_name_section = (char *)(file + ((Elf32_Shdr *)section_name)->sh_offset);
    int shnum = header32->e_shnum;

    for (int i = 0; i < shnum; i++) {
        Elf32_Shdr *section = &((Elf32_Shdr *)section_table)[i];
        char *name_section = start_name_section + section->sh_name;
        if (!ft_strcmp(name_section, ".text"))
            return section->sh_offset;
    }
    return 0;
}

Elf32_Addr find_text_addr_32(unsigned char *file) {
    Elf32_Ehdr *header32 = (Elf32_Ehdr *)file;
    void *section_table = (Elf32_Shdr *)(file + header32->e_shoff);
    void *section_name = &((Elf32_Shdr *)section_table)[header32->e_shstrndx];
    char *start_name_section = (char *)(file + ((Elf32_Shdr *)section_name)->sh_offset);
    int shnum = header32->e_shnum;

    for (int i = 0; i < shnum; i++) {
        Elf32_Shdr *section = &((Elf32_Shdr *)section_table)[i];
        char *name_section = start_name_section + section->sh_name;
        if (!ft_strcmp(name_section, ".text"))
            return section->sh_addr;
    }
    return 0;
}

Elf32_Addr find_text_size_32(unsigned char *file) {
    Elf32_Ehdr *header32 = (Elf32_Ehdr *)file;
    void *section_table = (Elf32_Shdr *)(file + header32->e_shoff);
    void *section_name = &((Elf32_Shdr *)section_table)[header32->e_shstrndx];
    char *start_name_section = (char *)(file + ((Elf32_Shdr *)section_name)->sh_offset);
    int shnum = header32->e_shnum;

    for (int i = 0; i < shnum; i++) {
        Elf32_Shdr *section = &((Elf32_Shdr *)section_table)[i];
        char *name_section = start_name_section + section->sh_name;
        if (!ft_strcmp(name_section, ".text"))
            return section->sh_size;
    }
    return 0;
}

Elf32_Off find_main_offset_32(unsigned char *file) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf32_Shdr *symtab = NULL;
    Elf32_Shdr *strtab = NULL;

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

    Elf32_Sym *symbols = (Elf32_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf32_Sym);

    Elf32_Addr main_addr = 0;
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

    Elf32_Phdr *phdr = (Elf32_Phdr *)(file + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            Elf32_Addr start = phdr[i].p_vaddr;
            Elf32_Addr end = start + phdr[i].p_memsz;

            if (main_addr >= start && main_addr < end) {
                Elf32_Off offset = phdr[i].p_offset + (main_addr - start);
                return offset;
            }
        }
    }
    return 0;
}


Elf32_Addr find_main_addr_32(unsigned char *file) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf32_Shdr *symtab = NULL;
    Elf32_Shdr *strtab = NULL;

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

    Elf32_Sym *symbols = (Elf32_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf32_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!ft_strcmp(name, "main"))
            return symbols[i].st_value;
    }

    printf("main addr not found\n");
    return 0;
}

Elf32_Addr find_main_size_32(unsigned char *file) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf32_Shdr *symtab = NULL;
    Elf32_Shdr *strtab = NULL;

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

    Elf32_Sym *symbols = (Elf32_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf32_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!ft_strcmp(name, "main"))
            return symbols[i].st_size;
    }

    printf("main size not found");
    return 0;
}