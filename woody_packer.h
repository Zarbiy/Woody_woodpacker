#ifndef WOODY_PAQCKER
#define WOODY_PAQCKER

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <elf.h>

typedef struct s_index_struct_elf {
    uint8_t architecture;
    uint8_t program_entry_offset[2];
    uint8_t offset_section_header[2];
    uint8_t size_section[2];
    uint8_t number_section[2];
    uint8_t num_section_name_section[2];
} t_index_struct_elf;

typedef struct s_index_program_header {
    uint8_t sh_name[2];
    uint8_t addr[2];
    uint8_t offset[2];
    uint8_t size[2];
} t_index_program_header;

typedef struct s_index_symtab {
    uint8_t st_name[2];
    uint8_t st_info[2];
    uint8_t st_other[2];
    uint8_t st_shndx[2];
    uint8_t st_value[2];
    uint8_t st_size[2];
} t_index_symtab;

typedef struct s_elf {
    uint64_t type;
    uint64_t size_section;
    uint64_t number_section;
    uint64_t index_section_name_section;
    uint64_t offset_section_table;
    uint64_t section_name_entry_offset;
    uint64_t section_name_start;
    uint64_t section_name_size;
    char *tab_name;
} t_elf;

typedef struct s_section {
    uint64_t        sh_name;
    uint64_t        sh_addr;
    uint64_t        sh_offset;
    uint64_t        sh_size;
} t_section;



// init.c
int init_struct_elf_program(t_index_struct_elf *elf, t_index_program_header *program, t_index_symtab *symtab);

#endif