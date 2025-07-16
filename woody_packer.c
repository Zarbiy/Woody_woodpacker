#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <elf.h>

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

    // // V1 avec header elf.h
    printf("Avec header elf\n\n");
    Elf64_Ehdr *header_elf = (Elf64_Ehdr *)file;                            // contient le header de elf
    Elf64_Shdr *section_table = (Elf64_Shdr *)(file + header_elf->e_shoff); // avance dans le header de e_shoff pour aller au debut de section table
    Elf64_Shdr *section_name = &section_table[header_elf->e_shstrndx];      // renvoie vers le position qui contient les noms des sections  

    char *start_name_section = (char *)(file + section_name->sh_offset);
    
    printf("%lx %lu\n", header_elf->e_shoff, header_elf->e_shoff);
    printf("%lx %lu\n", section_name->sh_offset, section_name->sh_offset);
    printf("Type : %i\n", header_elf->e_type);
    printf("Nb sections : %d\n\n", header_elf->e_shnum);

    for (int i = 0; i < header_elf->e_shnum; i++) {
        char *section_name = start_name_section + section_table[i].sh_name;
        printf("%2d | %20s | %6lx | %4lx | %4lu\n", i, section_name, section_table[i].sh_addr, section_table[i].sh_offset, section_table[i].sh_size);
    }

    // V2 sans header elf.h
    printf("\n\nSans header elf\n\n");

    uint64_t type = file[4];
    uint64_t size_section = file[58] | (file[59] << 8);
    uint64_t number_section = file[60] | (file[61] << 8);
    uint64_t index_section_name_section = file[62] | (file[63] << 8);
    printf("Type : %lu\n", type);
    printf("Section taille : %lu\n", size_section);
    printf("Number section : %lu\n", number_section);
    printf("index section name : %lu\n", index_section_name_section);

    uint64_t offset_section_table = file[40] | ((uint64_t)file[41] << 8) | ((uint64_t)file[42] << 16) | ((uint64_t)file[43] << 24) | ((uint64_t)file[44] << 32) | ((uint64_t)file[45] << 40) | ((uint64_t)file[46] << 48) | ((uint64_t)file[47] << 56);
    printf("offset section table : hex: %lx (dec: %li)\n", offset_section_table, offset_section_table);

    uint64_t section_name_entry_offset = offset_section_table + ((uint64_t)index_section_name_section * size_section);
    uint64_t section_name_start =
        ((uint64_t)file[section_name_entry_offset + 24]) |
        ((uint64_t)file[section_name_entry_offset + 25] << 8) |
        ((uint64_t)file[section_name_entry_offset + 26] << 16) |
        ((uint64_t)file[section_name_entry_offset + 27] << 24) |
        ((uint64_t)file[section_name_entry_offset + 28] << 32) |
        ((uint64_t)file[section_name_entry_offset + 29] << 40) |
        ((uint64_t)file[section_name_entry_offset + 30] << 48) |
        ((uint64_t)file[section_name_entry_offset + 31] << 56);

    uint64_t section_name_size =
        ((uint64_t)file[section_name_entry_offset + 32]) |
        ((uint64_t)file[section_name_entry_offset + 33] << 8) |
        ((uint64_t)file[section_name_entry_offset + 34] << 16) |
        ((uint64_t)file[section_name_entry_offset + 35] << 24) |
        ((uint64_t)file[section_name_entry_offset + 36] << 32) |
        ((uint64_t)file[section_name_entry_offset + 37] << 40) |
        ((uint64_t)file[section_name_entry_offset + 38] << 48) |
        ((uint64_t)file[section_name_entry_offset + 39] << 56);

    printf("offset section nom: hex: %lx (dec: %li)\n", section_name_start, section_name_start);
    printf("size section nom: hex: %lx (dec: %li)\n", section_name_size, section_name_size);

    for (uint64_t i = section_name_start; i < section_name_start + section_name_size; i++) {
        printf("%c", file[i]);
    }
    return 0;
}
