#include "woody_packer.h"

uint64_t extract_bytes(unsigned char *file, uint8_t start, uint8_t end, uint64_t add_value) {
    uint64_t result = 0;
    for (int i = 0; i <= end - start; i++) {
        result |= ((uint64_t)file[add_value + start + i]) << (8 * i);
    }
    return result;
}

int main(int ac, char **av){
    if (ac != 2) {
        write(2, "Wrong number of argument !\n", 27);
        return 0;
    }

    int fd = open(av[1], O_RDWR);
    if (fd == -1){
        perror("");
        return 0;
    }
    long file_size = lseek(fd, 0, SEEK_END);
    if (file_size <= 0){
        write(2, "File empty\n", 11);
        close(fd);
        return 0;
    }

    unsigned char *file = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 0;
    }

    // V1 avec header elf.h
    printf("Avec header elf\n\n");
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
        return 1;
    }

    for (int i = 0; i < shnum; i++) {
        if (file[4] == 1) {
            Elf32_Shdr *section = &((Elf32_Shdr *)section_table)[i];
            printf("%2d | %20s | %8x | %4x | %4u(dec) %6x(hex) | %i\n", i, start_name_section + section->sh_name, section->sh_addr, section->sh_offset, section->sh_size, section->sh_size, section->sh_name);
        }
        else {
            Elf64_Shdr *section = &((Elf64_Shdr *)section_table)[i];
            printf("%2d | %20s | %8lx | %4lx | %4lu(dec) %6lx(hex) | %i\n", i, start_name_section + section->sh_name, section->sh_addr, section->sh_offset, section->sh_size, section->sh_size, section->sh_name);
        }
    }

    // V2 sans header elf.h
    printf("\n\nSans header elf\n\n");

    t_index_struct_elf elf;
    t_index_program_header program;
    t_index_symtab symtab_struct;

    elf.architecture = file[4];
    if (init_struct_elf_program(&elf, &program, &symtab_struct) < 0) {
        write(2, "Error init struct elf\n", 22);
        return 0;
    }
    
    t_elf value_efl;

    value_efl.size_section = file[elf.size_section[0]] | (file[elf.size_section[1]] << 8);
    value_efl.number_section = file[elf.number_section[0]] | (file[elf.number_section[1]] << 8);
    value_efl.index_section_name_section = file[elf.num_section_name_section[0]] | (file[elf.num_section_name_section[1]] << 8);
    printf("Type : %i\n", elf.architecture);
    printf("Section taille : %lu\n", value_efl.size_section);
    printf("Number section : %lu\n", value_efl.number_section);
    printf("index section name : %lu\n", value_efl.index_section_name_section);

    value_efl.offset_section_table = extract_bytes(file, elf.offset_section_header[0], elf.offset_section_header[1], 0);
    printf("offset section table : hex: %lx (dec: %li)\n", value_efl.offset_section_table, value_efl.offset_section_table);

    value_efl.section_name_entry_offset = value_efl.offset_section_table + ((uint64_t)value_efl.index_section_name_section * value_efl.size_section);
    value_efl.section_name_start = extract_bytes(file, program.offset[0], program.offset[1], value_efl.section_name_entry_offset);
    char *all_section_name = (char *)(file + value_efl.section_name_start);

    uint64_t text_addr = 0;
    uint64_t text_offset = 0;

    printf("   |     addr | offs | size | name start | name\n");
    for (int i = 0; i < value_efl.number_section; i++) {
        size_t section_offset = value_efl.offset_section_table + (i * value_efl.size_section);
        unsigned char *section = file + section_offset;

        uint64_t sh_name = extract_bytes(file, program.sh_name[0], program.sh_name[1], section_offset);
        uint64_t addr = extract_bytes(file, program.addr[0], program.addr[1], section_offset);
        uint64_t offset = extract_bytes(file, program.offset[0], program.offset[1], section_offset);
        uint64_t size = extract_bytes(file, program.size[0], program.size[1], section_offset);

        char *name_section = all_section_name + sh_name;

        printf("%2d | %8lx | %4lx | %4lu | %10lu | %s\n", i, addr, offset, size, sh_name, name_section);

        if (!strcmp(name_section, ".text")) {
            text_addr = addr;
            text_offset = offset;
            unsigned char *str_text = file + sh_name;
            for (int i = 0; i < size; i++) {
                printf("%02x ", str_text[i]);
                // printf("%c ", str_text[i]);
            }
            printf("\n");
        }

        // on a trouve symtab maintenant il faur aller lire strtab pour trouve ou sont le _start/ main
        if (!strcmp(name_section, ".symtab")) { 
            uint64_t symtab_offset = offset;
            uint64_t symtab_size = size;

            size_t entsize_offset = section_offset + (elf.architecture == 2 ? 56 : 36);
            uint64_t sym_entry_size = (elf.architecture == 2) ? 24 : 16;

            uint64_t strtab_offset = 0;
            for (int j = 0; j < value_efl.number_section; j++) {
                size_t s_off = value_efl.offset_section_table + (j * value_efl.size_section);
                uint64_t sh_name_tmp = extract_bytes(file, program.sh_name[0], program.sh_name[1], s_off);
                char *name_tmp = all_section_name + sh_name_tmp;
                if (!strcmp(name_tmp, ".strtab")) {
                    strtab_offset = extract_bytes(file, program.offset[0], program.offset[1], s_off);
                    break;
                }
            }

            for (size_t k = 0; k + sym_entry_size <= symtab_size; k += sym_entry_size) {
                size_t entry_offset = symtab_offset + k;

                uint32_t st_name = extract_bytes(file, symtab_struct.st_name[0], symtab_struct.st_name[1], entry_offset);
                uint64_t st_value = extract_bytes(file, symtab_struct.st_value[0], symtab_struct.st_value[1], entry_offset);
                uint64_t st_size = extract_bytes(file, symtab_struct.st_size[0], symtab_struct.st_size[1], entry_offset);
                uint8_t st_info = file[entry_offset + symtab_struct.st_info[0]];
                uint8_t st_other = file[entry_offset + symtab_struct.st_other[0]];
                uint16_t st_shndx = extract_bytes(file, symtab_struct.st_shndx[0], symtab_struct.st_shndx[1], entry_offset);

                const char *sym_name = (char *)(file + strtab_offset + st_name);

                // printf("name: %40s, addr: %8lx, size: %5lu\n", sym_name, st_value, st_size);
                if (!strcmp(sym_name, "_start") || !strcmp(sym_name, "main")) {
                    printf("%8s addr: %lx Size %lu\n", sym_name, st_value, st_size);
                    unsigned char *start_code = file + (st_value - text_addr + text_offset);
                    for (size_t i = 0; i < st_size; i++) {
                        if (start_code[i] == 0xe9 || start_code[i] == 0xeb)
                            printf("\033[31;01m%02x (use jump)\033[00m ", start_code[i]);
                        else if (start_code[i] == 0xff && (start_code[i + 1] == 0x15 || start_code[i + 1] == 0x25))
                            printf("\033[31;01m%02x (use QWORD)\033[00m ", start_code[i]);
                        else
                            printf("%02x ", start_code[i]);
                    }
                    printf("\n");
                }
            }
        }
    }
    return 0;
}
