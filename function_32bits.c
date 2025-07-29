#include "woody_packer.h"

unsigned char *add_section_32(unsigned char *file, t_elf *elf, unsigned long file_size, unsigned long *new_file_size, Elf32_Off *func_offset, Elf32_Xword *func_size, Elf32_Addr *func_vaddr) {
    // new_data a modifier pour le 32 bits !!!!
    const char new_data[] = "\x48\x31\xc0\x48\xc7\xc7\x01\x00\x00\x00\x48\x8d\x35\x05\x00\x00\x00\xba\x0f\x00\x00\x00\xb8\x01\x00\x00\x00\x0f\x05....WOODY....\n";
    const char *new_section_name = ".func";
    size_t new_data_size = sizeof(new_data) - 1;
    size_t new_name_size = strlen(new_section_name) + 1;

    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Shdr *sh_table = (Elf32_Shdr *)(file + elf->offset_section_table);
    Elf32_Shdr *shstrtab = &sh_table[ehdr->e_shstrndx];

    // === Etend .shstrtab
    size_t name_offset = shstrtab->sh_size;
    size_t shstrtab_end = shstrtab->sh_offset + shstrtab->sh_size;

    // Alignement 4 pour la section .func
    size_t align = 4;
    size_t data_offset = (file_size + align - 1) & ~(align - 1);

    size_t new_sh_offset = (data_offset + new_data_size + align - 1) & ~(align - 1);
    *new_file_size = new_sh_offset + (ehdr->e_shnum + 1) * sizeof(Elf32_Shdr);

    // create nouveau fichier
    unsigned char *new_file = calloc(1, *new_file_size);
    if (!new_file) 
        return NULL;

    // Copie copie dans le nouveau file
    memcpy(new_file, file, file_size);

    // add les nouvelles data
    memcpy(new_file + data_offset, new_data, new_data_size);

    // add le nom de la nouvelle section
    memcpy(new_file + shstrtab_end, new_section_name, new_name_size);

    // update size de .shstrtab
    ((Elf32_Shdr *)(new_file + elf->offset_section_table))[ehdr->e_shstrndx].sh_size += new_name_size;

    // Update la table des section du header
    Elf32_Shdr *new_sh_table = (Elf32_Shdr *)(new_file + new_sh_offset);
    memcpy(new_sh_table, file + elf->offset_section_table, ehdr->e_shnum * sizeof(Elf32_Shdr));

    // add le header de la nouvelle section
    Elf32_Shdr *new_sh = &new_sh_table[ehdr->e_shnum];
    memset(new_sh, 0, sizeof(Elf32_Shdr));
    new_sh->sh_name = name_offset;
    new_sh->sh_type = SHT_PROGBITS;
    new_sh->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_sh->sh_offset = data_offset;
    new_sh->sh_size = new_data_size;
    new_sh->sh_addralign = 1;

    Elf32_Phdr *phdr = (Elf32_Phdr *)(new_file + ehdr->e_phoff);
    int found = 0;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            new_sh->sh_addr = phdr[i].p_vaddr + (new_sh->sh_offset - phdr[i].p_offset);
            found = 1;
            break;
        }
    }

    if (!found) {
        fprintf(stderr, "ERROR\n");
        free(new_file);
        return NULL;
    }

    // Update header ELF
    ehdr = (Elf32_Ehdr *)new_file;
    ehdr->e_shoff = new_sh_offset;
    ehdr->e_shnum += 1;

    // redirige au lancement sur l'adresse de ma fonction
    // ehdr->e_entry = new_sh->sh_addr;

    *func_vaddr = new_sh->sh_addr;
    *func_offset = new_sh->sh_offset;
    *func_size = new_sh->sh_size;
    return new_file;
}

void update_load_segment_to_execute_32(unsigned char *file, Elf32_Off func_offset, Elf32_Word func_size) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Phdr *phdr = (Elf32_Phdr *)(file + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD && (phdr[i].p_flags & PF_X)) {
            Elf32_Off seg_end  = phdr[i].p_offset + phdr[i].p_filesz;
            Elf32_Off func_end = func_offset + func_size;
            if (func_end > seg_end) {
                Elf32_Word new_size = func_end - phdr[i].p_offset;
                phdr[i].p_filesz = new_size;
                phdr[i].p_memsz  = new_size;
            }
            break;
        }
    }
}

Elf32_Off get_file_offset_32(Elf32_Ehdr *ehdr, Elf32_Addr vaddr) {
    Elf32_Phdr *ph = (Elf32_Phdr *)((char *)ehdr + ehdr->e_phoff);
    for(int i = 0; i < ehdr->e_phnum; i++) {
        if (ph[i].p_type == PT_LOAD) {
            Elf32_Addr seg_start = ph[i].p_vaddr;
            Elf32_Addr seg_end   = seg_start + ph[i].p_memsz;
            if (vaddr >= seg_start && vaddr < seg_end) {
                return ph[i].p_offset + (vaddr - seg_start);
            }
        }
    }
    return 0;
}

void patch_entry_to_func_32(unsigned char *file, Elf32_Ehdr *ehdr, Elf32_Addr func_addr)
{
    Elf32_Off entry_offset = get_file_offset_32(ehdr, ehdr->e_entry);
    Elf32_Addr old_entry   = ehdr->e_entry;
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