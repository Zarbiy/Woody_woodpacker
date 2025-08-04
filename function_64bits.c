#include "woody_packer.h"

Elf64_Addr find_main_addr_64(unsigned char *file) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (strcmp(section_name, ".symtab") == 0) {
            symtab = &shdr[i];
        } else if (strcmp(section_name, ".strtab") == 0) {
            strtab = &shdr[i];
        }
    }

    if (!symtab || !strtab) {
        printf("relevant section not found");
        return 0;
    }

    Elf64_Sym *symbols = (Elf64_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (strcmp(name, "main") == 0) {
            return symbols[i].st_value;
        }
    }

    printf("main addr not found");
    return 0;
}

Elf64_Addr find_main_size_64(unsigned char *file) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (strcmp(section_name, ".symtab") == 0) {
            symtab = &shdr[i];
        } else if (strcmp(section_name, ".strtab") == 0) {
            strtab = &shdr[i];
        }
    }

    if (!symtab || !strtab) {
        printf("relevant section not found");
        return 0;
    }

    Elf64_Sym *symbols = (Elf64_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (strcmp(name, "main") == 0) {
            return symbols[i].st_size;
        }
    }

    printf("main size not found");
    return 0;
}

unsigned char *add_section_64(unsigned char *file, t_elf *elf, unsigned long file_size, unsigned long *new_file_size, Elf64_Off *func_offset, Elf64_Xword *func_size, Elf64_Addr *func_vaddr) {
    
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(file + ehdr->e_phoff);
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
   
    Elf64_Addr start_addr = ehdr->e_entry;
    Elf64_Addr main_addr = find_main_addr_64(file);
    Elf64_Xword main_size = find_main_size_64(file);
    if (main_addr == 0 || main_size == 0) {
        printf("error addr/size main\n");
        return 0;
    }
    printf("Start address: 0x%lx| main adress: 0x%lx\n", start_addr, main_addr);
    printf("main address: 0x%lx| main size: 0x%lx\n", main_addr, main_size);


    unsigned char payload_write_woody[] = {
        0x48, 0x89, 0xe3,                         // mov rbx, rsp
        0x48, 0x31, 0xc0,                         // xor rax, rax
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
        0x48, 0x8d, 0x35, 0x2d, 0x00, 0x00, 0x00, // lea rsi, [rip + 45]
        0xba, 0x0e, 0x00, 0x00, 0x00,             // mov edx, 14
        0xb8, 0x01, 0x00, 0x00, 0x00,             // mov eax, 1
        0x0f, 0x05,                               // syscall

        0x48, 0x89, 0xdc,                         // mov rsp, rbx

        0xbf, 0x01, 0x00, 0x00, 0x00,             // mov edi, 1        ; argc
        0x48, 0x89, 0xe6,                         // mov rsi, rsp      ; argv

        0x48, 0xb8,                               // mov rax, main
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,   // addr main a remplacer
        0xff, 0xd0,                               // call rax

        0x48, 0x31, 0xff,                         // xor edi, edi
        0xb8, 0x3c, 0x00, 0x00, 0x00,             // mov eax, 60       ; exit
        0x0f, 0x05,                               // syscall

        '.', '.', '.', '.', 'W', 'O', 'O', 'D', 'Y', '.', '.', '.', '.', '\n', '\0'
    };

    size_t addr_offset = 45;
    memcpy(&payload_write_woody[addr_offset], &main_addr, sizeof(main_addr));

    const char new_section_name[] = ".test";

    size_t payload_size = sizeof(payload_write_woody) - 1;
    size_t new_section_name_len = strlen(new_section_name) + 1;

    // printf("Payload size: %ld %lx\n", payload_size, payload_size);

    // PT_LOAD E
    Elf64_Phdr *exec_segment = NULL;
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if ((phdr[i].p_type == PT_LOAD) && (phdr[i].p_flags & PF_X)) {
            exec_segment = &phdr[i];
            break;
        }
    }
    if (!exec_segment) {
        write(2, "PT_LOAD segment not found\n", 36);
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

    char *new_shstrtab = (char *)(new_file + new_shstrtab_offset);
    memcpy(new_shstrtab, old_shstrtab, shstrtab->sh_size);
    strcpy(new_shstrtab + shstrtab->sh_size, new_section_name);

    // updqte header .shstrtab
    Elf64_Shdr *new_shdr = (Elf64_Shdr *)(new_file + ehdr->e_shoff);
    new_shdr[ehdr->e_shstrndx].sh_offset = new_shstrtab_offset;
    new_shdr[ehdr->e_shstrndx].sh_size = new_shstrtab_size;

    // add nouvelle section 
    int shnum = ehdr->e_shnum;
    Elf64_Shdr *new_section = &new_shdr[shnum];
    new_section->sh_name = shstrtab->sh_size;
    new_section->sh_type = SHT_PROGBITS;
    new_section->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_section->sh_addr = injection_vaddr;
    new_section->sh_offset = injection_offset;
    new_section->sh_size = payload_size;
    new_section->sh_addralign = 0x10;

    // update header elf
    ehdr = (Elf64_Ehdr *)new_file;
    ehdr->e_shnum += 1;
    ehdr->e_entry = injection_vaddr;

    *new_file_size = extended_size;
    *func_offset = injection_offset;
    *func_size = payload_size;
    *func_vaddr = injection_vaddr;

    return new_file;
}
