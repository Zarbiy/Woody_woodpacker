#include "woody_packer.h"

uint64_t extract_bytes(unsigned char *file, uint8_t start, uint8_t end, uint64_t add_value) {
    uint64_t result = 0;
    for (int i = 0; i <= end - start; i++) {
        result |= ((uint64_t)file[add_value + start + i]) << (8 * i);
    }
    return result;
}

int read_elf_with_header(unsigned char *file) {
    // printf("Avec header elf\n\n");
    Elf32_Ehdr *header32 = NULL;
    Elf64_Ehdr *header64 = NULL;
    void *section_table = NULL;
    void *section_name = NULL;
    char *start_name_section = NULL;
    int shnum = 0;

    if (file[4] == 1) {
        header32 = (Elf32_Ehdr *)file;
        section_table = (Elf32_Shdr *)(file + header32->e_shoff);
        section_name = &((Elf32_Shdr *)section_table)[header32->e_shstrndx];
        start_name_section = (char *)(file + ((Elf32_Shdr *)section_name)->sh_offset);
        shnum = header32->e_shnum;

        // printf("%lx %lu\n", header32->e_shoff, header32->e_shoff);
        // printf("%lx %lu\n", section_name->sh_offset, section_name->sh_offset);

        printf("Type : %i\n", file[4]);
        printf("Nb sections : %d\n", header32->e_shnum);
        printf("Size sections : %d\n", header32->e_shentsize);
        printf("index section name : %d\n\n", header32->e_shstrndx);
    }
    else if (file[4] == 2) {
        header64 = (Elf64_Ehdr *)file;
        section_table = (Elf64_Shdr *)(file + header64->e_shoff);
        section_name = &((Elf64_Shdr *)section_table)[header64->e_shstrndx];
        start_name_section = (char *)(file + ((Elf64_Shdr *)section_name)->sh_offset);
        shnum = header64->e_shnum;

        // printf("%lx %lu\n", header64->e_shoff, header64->e_shoff);
        // printf("%lx %lu\n", section_name->sh_offset, section_name->sh_offset);

        printf("Type : %i\n", file[4]);
        printf("Nb sections : %d\n", header64->e_shnum);
        printf("Size sections : %d\n", header64->e_shentsize);
        printf("index section name : %d\n\n", header64->e_shstrndx);
    }
    else {
        write(2, "Error header elf\n", 18);
        return -1;
    }

    for (int i = 0; i < shnum; i++) {
        if (file[4] == 1) {
            Elf32_Shdr *section = &((Elf32_Shdr *)section_table)[i];
            char *name_section = start_name_section + section->sh_name;
            printf("%2d | %20s | %8x | %4x | %4u(dec) %6x(hex) | %i\n", i, name_section, section->sh_addr, section->sh_offset, section->sh_size, section->sh_size, section->sh_name);
            if (!strcmp(name_section, ".dynamic") || !strcmp(name_section, ".text")) {
                unsigned char *str_text = file + section->sh_offset;
                for (int i = 0; i < section->sh_size; i++) {
                    printf("%02x ", str_text[i]);
                }
                printf("\n");
            }
        }
        else {
            Elf64_Shdr *section = &((Elf64_Shdr *)section_table)[i];
            char *name_section = start_name_section + section->sh_name;
            printf("%2d | %20s | %8lx | %4lx | %4lu(dec) %6lx(hex) | %i\n", i, start_name_section + section->sh_name, section->sh_addr, section->sh_offset, section->sh_size, section->sh_size, section->sh_name);
            // if (!strcmp(name_section, ".dynamic") || !strcmp(name_section, ".text")) {
            //     unsigned char *str_text = file + section->sh_offset;
            //     for (int i = 0; i < section->sh_size; i++) {
            //         printf("%02x ", str_text[i]);
            //     }
            //     printf("\n");
            // }
        }
    }
    return 0;
}