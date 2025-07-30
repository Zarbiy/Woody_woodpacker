#include "woody_packer.h"

void fix_dynamic_entries_64(Elf64_Ehdr *ehdr, unsigned char *file, size_t delta) {
    Elf64_Phdr *ph_table = (Elf64_Phdr *)(file + ehdr->e_phoff);
    Elf64_Dyn *dynamic = NULL;
    size_t dyn_size = 0;

    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &ph_table[i];
        if (ph->p_type == PT_DYNAMIC) {
            dynamic = (Elf64_Dyn *)(file + ph->p_offset);
            dyn_size = ph->p_filesz;
            break;
        }
    }
    if (!dynamic) return;

    size_t dyn_count = dyn_size / sizeof(Elf64_Dyn);
    for (size_t i = 0; i < dyn_count; i++) {
        switch (dynamic[i].d_tag) {
            case DT_INIT:
            case DT_FINI:
            case DT_INIT_ARRAY:
            case DT_FINI_ARRAY:
            case DT_STRTAB:
            case DT_SYMTAB:
            case DT_JMPREL:
            case DT_REL:
            case DT_RELA:
            case DT_PLTGOT:
            case DT_VERDEF:
            case DT_VERNEED:
            case DT_VERSYM:
            case DT_GNU_HASH:
            case DT_HASH:
                dynamic[i].d_un.d_ptr += delta;
                break;

            case DT_NEEDED:
            case DT_SONAME:
            case DT_RPATH:
            case DT_RUNPATH:
            case DT_VERNEEDNUM:
                break;

            default:
                break;
        }
    }
}

void update_size_pt_load_64(unsigned char *file, size_t new_code_size) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Phdr *ph_table = (Elf64_Phdr *)(file + ehdr->e_phoff);

    Elf64_Shdr *sh_table = (Elf64_Shdr *)(file + ehdr->e_shoff);
    Elf64_Shdr *shstrtab = &sh_table[ehdr->e_shstrndx];
    const char *shstrtab_p = (const char *)(file + shstrtab->sh_offset);

    int text_idx = -1;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *sec_name = shstrtab_p + sh_table[i].sh_name;
        if (strcmp(sec_name, ".text") == 0) {
            text_idx = i;
            break;
        }
    }
    if (text_idx == -1) {
        fprintf(stderr, "ERROR: .text section not found\n");
        return;
    }

    Elf64_Shdr *text_section = &sh_table[text_idx];
    uint64_t text_start = text_section->sh_offset;
    uint64_t text_end   = text_start + text_section->sh_size;

    // agrandi pt_load de .text
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &ph_table[i];

        if (ph->p_type == PT_LOAD &&
            text_start >= ph->p_offset &&
            text_start < ph->p_offset + ph->p_filesz) {
            
            ph->p_filesz += new_code_size;
            ph->p_memsz  += new_code_size;
        }
        if (ph->p_type == PT_DYNAMIC) {
            ph->p_offset += new_code_size;
            ph->p_vaddr  += new_code_size;
            ph->p_paddr  += new_code_size;
        }
    }

    // update les autres pt_load
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &ph_table[i];
        if (ph->p_type == PT_LOAD && ph->p_offset > text_start) {
            ph->p_offset += new_code_size;
            ph->p_vaddr += new_code_size;
            ph->p_paddr += new_code_size;

            size_t mod = ph->p_align;
            size_t new_off = ph->p_offset;
            size_t new_vaddr = ph->p_vaddr;

            if ((new_off % mod) != (new_vaddr % mod)) {
                size_t desired = new_vaddr % mod;
                new_off = ((new_off / mod) * mod) + desired;
                ph->p_offset = new_off;
            }
        }
    }
}


void fix_section_addresses_64(Elf64_Ehdr *ehdr, unsigned char *file) {
    Elf64_Shdr *sh_table = (Elf64_Shdr *)(file + ehdr->e_shoff);
    Elf64_Phdr *ph_table = (Elf64_Phdr *)(file + ehdr->e_phoff);

    for (int i = 0; i < ehdr->e_shnum; i++) {
        Elf64_Shdr *sh = &sh_table[i];

        for (int j = 0; j < ehdr->e_phnum; j++) {
            Elf64_Phdr *ph = &ph_table[j];
            if (sh->sh_offset >= ph->p_offset &&
                sh->sh_offset < ph->p_offset + ph->p_filesz) {

                sh->sh_addr = ph->p_vaddr + (sh->sh_offset - ph->p_offset);
                break;
            }
        }
    }
}

size_t add_size_section_and_shift_64(unsigned char **pfile, size_t *pfile_size, size_t new_code_size) {
    unsigned char *file = *pfile;
    size_t file_size = *pfile_size;

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *sh_table = (Elf64_Shdr *)(file + ehdr->e_shoff);
    Elf64_Shdr *shstrtab = &sh_table[ehdr->e_shstrndx];
    const char *shstrtab_p = (const char *)(file + shstrtab->sh_offset);

    if (ehdr->e_shoff + sizeof(Elf64_Shdr) * ehdr->e_shnum > file_size) {
        printf("ERROR\n");
        return -1;
    }

    // Trouver l'index de .text
    int text_idx = -1;
    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *sec_name = shstrtab_p + sh_table[i].sh_name;
        if (strcmp(sec_name, ".text") == 0) {
            text_idx = i;
            break;
        }
    }
    if (text_idx == -1) {
        printf("ERROR\n");
        return -1;
    }

    size_t old_text_size = sh_table[text_idx].sh_size;
    size_t old_text_offset = sh_table[text_idx].sh_offset;

    // Nouvelle taille du fichier = ancienne + taille ajoutee dans .text
    size_t new_size = file_size + new_code_size;
    unsigned char *new_file = calloc(1, new_size);
    if (!new_file) {
        printf("ERROR\n");
        return -1;
    }

    // Nouveau offset de la table des sections (on la decale après insertion)
    size_t old_shoff = ehdr->e_shoff;
    size_t new_shoff = old_shoff + new_code_size;

    // 1) Copier tout le contenu jusqu'a la fin de .text (ancienne fin)
    size_t copy_until = old_text_offset + old_text_size;
    memcpy(new_file, file, copy_until);

    // 2) Copier le reste du fichier (tout après .text) a sa nouvelle position decalee
    size_t rest_offset = copy_until;
    size_t rest_size = file_size - rest_offset;
    memcpy(new_file + rest_offset + new_code_size, file + rest_offset, rest_size);

    // 3) Copier la table des sections a sa nouvelle position decalee
    memcpy(new_file + new_shoff, file + old_shoff, sizeof(Elf64_Shdr) * ehdr->e_shnum);

    // 4) Mettre a jour le header ELF dans new_file
    Elf64_Ehdr *new_ehdr = (Elf64_Ehdr *)new_file;
    new_ehdr->e_shoff = new_shoff;

    // 5) Modifier la table des sections dans new_file
    Elf64_Shdr *new_sh_table = (Elf64_Shdr *)(new_file + new_shoff);

    // Agrandir la section .text
    new_sh_table[text_idx].sh_size += new_code_size;

    // Decaler les sections qui viennent APRES .text dans le fichier
    for (int i = 0; i < ehdr->e_shnum; i++) {
        if (i == text_idx) continue;
        if (new_sh_table[i].sh_offset > old_text_offset) {
            new_sh_table[i].sh_offset += new_code_size;
        }
    }

    // 6) Liberer l'ancien fichier (qui venait de mmap)
    munmap(file, file_size);

    // 7) Remplacer pointeurs et taille
    *pfile = new_file;
    *pfile_size = new_size;

    update_size_pt_load_64(new_file, new_code_size);
    fix_section_addresses_64(new_ehdr, new_file);
    fix_dynamic_entries_64(new_ehdr, new_file, new_code_size);

    // Retourner l'offset dans le nouveau fichier où inserer ton nouveau code (fin ancienne .text)
    return copy_until;
}