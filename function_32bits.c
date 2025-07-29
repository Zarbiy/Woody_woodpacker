#include "woody_packer.h"

size_t add_size_section_and_shift_32(unsigned char **pfile, size_t *pfile_size, size_t new_code_size) {
    unsigned char *file = *pfile;
    size_t file_size = *pfile_size;

    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Shdr *sh_table = (Elf32_Shdr *)(file + ehdr->e_shoff);
    Elf32_Shdr *shstrtab = &sh_table[ehdr->e_shstrndx];
    const char *shstrtab_p = (const char *)(file + shstrtab->sh_offset);

    if (ehdr->e_shoff + sizeof(Elf32_Shdr) * ehdr->e_shnum > file_size) {
        printf("ERROR: section table outside file\n");
        return 0;
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
        printf("ERROR: .text section not found\n");
        return 0;
    }

    size_t old_text_size = sh_table[text_idx].sh_size;
    size_t old_text_offset = sh_table[text_idx].sh_offset;

    // Nouvelle taille du fichier = ancienne + taille ajoutee dans .text
    size_t new_size = file_size + new_code_size;
    unsigned char *new_file = calloc(1, new_size);
    if (!new_file) {
        printf("ERROR: malloc failed\n");
        return 0;
    }

    // Nouveau offset de la table des sections (on la decale après insertion)
    size_t old_shoff = ehdr->e_shoff;
    size_t new_shoff = old_shoff + new_code_size;

    // 1) Copier tout le contenu jusqu'a la fin de .text (ancienne fin)
    size_t offset_end_old_text = old_text_offset + old_text_size;
    memcpy(new_file, file, offset_end_old_text);

    // 2) Copier le reste du fichier (tout après .text) a sa nouvelle position decalee
    size_t rest_offset = offset_end_old_text;
    size_t rest_size = file_size - rest_offset;
    memcpy(new_file + rest_offset + new_code_size, file + rest_offset, rest_size);

    // 3) Copier la table des sections a sa nouvelle position decalee
    memcpy(new_file + new_shoff, file + old_shoff, sizeof(Elf32_Shdr) * ehdr->e_shnum);

    // 4) Mettre a jour le header ELF dans new_file
    Elf32_Ehdr *new_ehdr = (Elf32_Ehdr *)new_file;
    new_ehdr->e_shoff = new_shoff;

    // 5) Modifier la table des sections dans new_file
    Elf32_Shdr *new_sh_table = (Elf32_Shdr *)(new_file + new_shoff);

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

    // Retourner l'offset dans le nouveau fichier où inserer ton nouveau code (fin ancienne .text)
    return offset_end_old_text;
}

void update_size_pt_load_32(unsigned char *file, size_t new_code_size) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Phdr *ph_table = (Elf32_Phdr *)(file + ehdr->e_phoff);

    Elf32_Shdr *sh_table = (Elf32_Shdr *)(file + ehdr->e_shoff);
    Elf32_Shdr *shstrtab = &sh_table[ehdr->e_shstrndx];
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
        printf("ERROR: .text section not found\n");
        return;
    }

    Elf32_Shdr *text_section = &sh_table[text_idx];
    uint32_t text_start = text_section->sh_offset;
    uint32_t text_end = text_start + text_section->sh_size;

    // Parcourir les segments
    for (int i = 0; i < ehdr->e_phnum; i++) {
        Elf32_Phdr *ph = &ph_table[i];
        if (ph->p_type == PT_LOAD && (ph->p_flags & PF_X)) {
            printf("Modif segment %d\n", i);
            ph->p_filesz += new_code_size;
            ph->p_memsz += new_code_size;
            break;
        }
    }
}