#include "woody_packer.h"

int init_struct_elf_program(t_index_struct_elf *elf, t_index_program_header *program, t_index_symtab *symtab) {
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

        // init index symtab
        symtab->st_name[0] = 0;
        symtab->st_name[1] = 3;
        symtab->st_value[0] = 4;
        symtab->st_value[1] = 7;
        symtab->st_size[0] = 8;
        symtab->st_size[1] = 11;
        symtab->st_info[0] = 12;
        symtab->st_info[1] = 12;
        symtab->st_other[0] = 13;
        symtab->st_other[1] = 13;
        symtab->st_shndx[0] = 14;
        symtab->st_shndx[1] = 15;
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
        
        // init index symtab
        symtab->st_name[0] = 0;
        symtab->st_name[1] = 3;
        symtab->st_value[0] = 8;
        symtab->st_value[1] = 15;
        symtab->st_size[0] = 16;
        symtab->st_size[1] = 23;
        symtab->st_info[0] = 4;
        symtab->st_info[1] = 4;
        symtab->st_other[0] = 5;
        symtab->st_other[1] = 5;
        symtab->st_shndx[0] = 6;
        symtab->st_shndx[1] = 7;
    }
    else
        return -1;
    return 0;
}