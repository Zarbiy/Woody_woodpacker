#include "woody_packer.h"

uint64_t extract_bytes(unsigned char *file, uint8_t start, uint8_t end, uint64_t add_value) {
    uint64_t result = 0;
    for (int i = 0; i <= end - start; i++) {
        result |= ((uint64_t)file[add_value + start + i]) << (8 * i);
    }
    return result;
}

int init_struct_elf_program(t_index_struct_elf *elf, t_index_program_header *program) {
    if (elf->architecture == 1) {
        // init index header elf
        elf->program_entry_offset[0] = 24;
        elf->program_entry_offset[1] = 27;
        elf->offset_section_header[0] = 32;
        elf->offset_section_header[1] = 35;
        elf->size_section[0] = 46;
        elf->size_section[1] = 47;
        elf->number_section[0] = 48;
        elf->number_section[1] = 49;
        elf->num_section_name_section[0] = 50;
        elf->num_section_name_section[1] = 51;

        // init index header section
        program->sh_name[0] = 0;
        program->sh_name[1] = 3;
        program->addr[0] = 12;
        program->addr[1] = 15;
        program->offset[0] = 16;
        program->offset[1] = 19;
        program->size[0] = 20;
        program->size[1] = 23;
    }
    else if (elf->architecture == 2) {
        // init index header elf
        elf->program_entry_offset[0] = 24;
        elf->program_entry_offset[1] = 31;
        elf->offset_section_header[0] = 40;
        elf->offset_section_header[1] = 47;
        elf->size_section[0] = 58;
        elf->size_section[1] = 59;
        elf->number_section[0] = 60;
        elf->number_section[1] = 61;
        elf->num_section_name_section[0] = 62;
        elf->num_section_name_section[1] = 63;

        // init index header section
        program->sh_name[0] = 0;
        program->sh_name[1] = 3;
        program->addr[0] = 16;
        program->addr[1] = 23;
        program->offset[0] = 24;
        program->offset[1] = 31;
        program->size[0] = 32;
        program->size[1] = 39;
    }
    else
        return -1;
    return 0;
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
    elf.architecture = file[4];
    if (init_struct_elf_program(&elf, &program) < 0) {
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
            unsigned char *str_text = file + sh_name;
            for (int i = 0; i < size; i++) {
                printf("%02x ", str_text[i]);
            }
            printf("\n");
        }
    }
    return 0;
}
