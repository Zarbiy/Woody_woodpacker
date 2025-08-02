#include "woody_packer.h"

unsigned char *add_section_64(unsigned char *file, t_elf *elf, unsigned long file_size, unsigned long *new_file_size, Elf64_Off *func_offset, Elf64_Xword *func_size, Elf64_Addr *func_vaddr) {
    const unsigned char payload_write_woody[] =
    "\x48\x31\xc0"                  // xor rax, rax
    "\x48\xc7\xc7\x01\x00\x00\x00"  // mov rdi, 1
    "\x48\x8d\x35\x16\x00\x00\x00"  // lea rsi, [rip + 22]
    "\xba\x0e\x00\x00\x00"          // mov edx, 14
    "\xb8\x01\x00\x00\x00"          // mov eax, 1
    "\x0f\x05"                      // syscall
    "\x48\x31\xff"                  // xor rdi, rdi
    "\xb8\x3c\x00\x00\x00"          // mov eax, 60
    "\x0f\x05"                      // syscall
    "....WOODY....\n";

    const char new_section_name[] = ".test";

    size_t payload_size = sizeof(payload_write_woody) - 1; // Sans le \0 final
    size_t new_section_name_len = strlen(new_section_name) + 1; // inclure le '\0'

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(file + ehdr->e_phoff);
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);

    // Trouver un PT_LOAD exécutable
    Elf64_Phdr *exec_segment = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if ((phdr[i].p_type == PT_LOAD) && (phdr[i].p_flags & PF_X)) {
            exec_segment = &phdr[i];
            break;
        }
    }
    if (!exec_segment) {
        write(2, "No executable PT_LOAD segment found\n", 36);
        return NULL;
    }

    // Trouver la section .shstrtab
    Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
    const char *old_shstrtab = (const char *)(file + shstrtab->sh_offset);

    // Calculer le nouvel offset pour injection payload
    Elf64_Off injection_offset = exec_segment->p_offset + exec_segment->p_filesz;
    Elf64_Addr injection_vaddr = exec_segment->p_vaddr + exec_segment->p_filesz;

    // Nouveau offset pour la .shstrtab étendue (après payload)
    Elf64_Off new_shstrtab_offset = injection_offset + payload_size;

    // Nouvelle taille pour .shstrtab (ancienne taille + nouveau nom)
    size_t new_shstrtab_size = shstrtab->sh_size + new_section_name_len;

    // Taille totale du nouveau fichier :
    // ancien fichier + payload + nouvelle section header + extension .shstrtab
    size_t extended_size = file_size + payload_size + sizeof(Elf64_Shdr) + new_section_name_len;

    unsigned char *new_file = calloc(1, extended_size);
    if (!new_file)
        return NULL;

    // Copier l'ancien fichier dans le nouveau buffer
    memcpy(new_file, file, file_size);

    // Copier le payload à l'offset d'injection
    memcpy(new_file + injection_offset, payload_write_woody, payload_size);

    // Mettre à jour le segment PT_LOAD exécutable pour inclure la payload
    Elf64_Phdr *new_phdr = (Elf64_Phdr *)(new_file + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if ((new_phdr[i].p_type == PT_LOAD) && (new_phdr[i].p_flags & PF_X)) {
            new_phdr[i].p_filesz += payload_size;
            new_phdr[i].p_memsz += payload_size;
            break;
        }
    }

    // Copier et étendre .shstrtab à son nouvel emplacement
    char *new_shstrtab = (char *)(new_file + new_shstrtab_offset);
    memcpy(new_shstrtab, old_shstrtab, shstrtab->sh_size);
    strcpy(new_shstrtab + shstrtab->sh_size, new_section_name);

    // Mettre à jour le header de la .shstrtab
    Elf64_Shdr *new_shdr = (Elf64_Shdr *)(new_file + ehdr->e_shoff);
    new_shdr[ehdr->e_shstrndx].sh_offset = new_shstrtab_offset;
    new_shdr[ehdr->e_shstrndx].sh_size = new_shstrtab_size;

    // Ajouter la nouvelle section à la table des sections
    int shnum = ehdr->e_shnum;
    Elf64_Shdr *new_section = &new_shdr[shnum];
    new_section->sh_name = shstrtab->sh_size;
    new_section->sh_type = SHT_PROGBITS;
    new_section->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_section->sh_addr = injection_vaddr;
    new_section->sh_offset = injection_offset;
    new_section->sh_size = payload_size;
    new_section->sh_addralign = 0x10;

    // Mettre à jour le nombre de sections
    ehdr = (Elf64_Ehdr *)new_file;
    ehdr->e_shnum += 1;
    ehdr->e_entry = injection_vaddr;

    // Renseigner les infos pour le retour
    *new_file_size = extended_size;
    *func_offset = injection_offset;
    *func_size = payload_size;
    *func_vaddr = injection_vaddr;

    return new_file;
}
