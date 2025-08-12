#ifndef WOODY_PAQCKER
#define WOODY_PAQCKER

#include <unistd.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <string.h>
#include <elf.h>

#include <stdbool.h>

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

// utils_32.c
long space_between_fini_rodata_32(unsigned char *file);
Elf32_Addr find_main_size_32(unsigned char *file);
Elf32_Addr find_main_addr_32(unsigned char *file);
Elf32_Off find_main_offset_32(unsigned char *file);

Elf32_Addr find_text_size_32(unsigned char *file);
Elf32_Addr find_text_addr_32(unsigned char *file);
Elf32_Off find_text_offset_32(unsigned char *file);

// function_32bits.c
unsigned char *add_section_32(unsigned char *file, unsigned long file_size, unsigned long *new_file_size, Elf32_Off *func_offset, Elf32_Xword *func_size, Elf32_Addr *func_vaddr);

// utils_64.c
long space_between_fini_rodata_64(unsigned char *file);
Elf64_Addr find_main_size_64(unsigned char *file);
Elf64_Addr find_main_addr_64(unsigned char *file);
Elf64_Off find_main_offset_64(unsigned char *file);

Elf64_Addr find_text_size_64(unsigned char *file);
Elf64_Addr find_text_addr_64(unsigned char *file);
Elf64_Off find_text_offset_64(unsigned char *file);

// function_64bits.c
unsigned char *add_section_64(unsigned char *file, unsigned long file_size, unsigned long *new_file_size, Elf64_Off *func_offset, Elf64_Xword *func_size, Elf64_Addr *func_vaddr);

// crypt.c
void crypt_main_64(unsigned char *file, char *key);
void crypt_main_32(unsigned char *file, char *key);

// utils.c
uint64_t extract_bytes(unsigned char *file, uint8_t start, uint8_t end, uint64_t add_value);
int read_elf_with_header(unsigned char *file);
char *generate_key(size_t len_key, char *char_accepted);
int calc_size_key(unsigned char *file, int archi);
int verif_len_key(int len, unsigned char *file);
int	ft_atoi(const char *nptr);
int	ft_strncmp(const char *s1, const char *s2, size_t n);
int ft_strcmp(const char *s1, const char *s2);
size_t	ft_strlen(const char *str);

#endif