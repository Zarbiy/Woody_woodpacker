#include "woody_packer.h"

Elf32_Off find_main_offset_32(unsigned char *file) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf32_Shdr *symtab = NULL;
    Elf32_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (!strcmp(section_name, ".symtab"))
            symtab = &shdr[i];
        else if (!strcmp(section_name, ".strtab"))
            strtab = &shdr[i];
    }

    if (!symtab || !strtab) {
        printf("relevant section not found");
        return 0;
    }

    Elf32_Sym *symbols = (Elf32_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf32_Sym);

    Elf32_Addr main_addr = 0;
    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!strcmp(name, "main")) {
            main_addr = symbols[i].st_value;
            break;
        }
    }

    if (!main_addr) {
        printf("main not found");
        return 0;
    }

    Elf32_Phdr *phdr = (Elf32_Phdr *)(file + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            Elf32_Addr start = phdr[i].p_vaddr;
            Elf32_Addr end = start + phdr[i].p_memsz;

            if (main_addr >= start && main_addr < end) {
                Elf32_Off offset = phdr[i].p_offset + (main_addr - start);
                return offset;
            }
        }
    }
    return 0;
}


Elf32_Addr find_main_addr_32(unsigned char *file) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf32_Shdr *symtab = NULL;
    Elf32_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (!strcmp(section_name, ".symtab")) {
            symtab = &shdr[i];
        } else if (!strcmp(section_name, ".strtab")) {
            strtab = &shdr[i];
        }
    }

    if (!symtab || !strtab) {
        printf("relevant section not found");
        return 0;
    }

    Elf32_Sym *symbols = (Elf32_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf32_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!strcmp(name, "main")) {
            return symbols[i].st_value;
        }
    }

    printf("main addr not found");
    return 0;
}

Elf32_Addr find_main_size_32(unsigned char *file) {
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf32_Shdr *symtab = NULL;
    Elf32_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (!strcmp(section_name, ".symtab")) {
            symtab = &shdr[i];
        } else if (!strcmp(section_name, ".strtab")) {
            strtab = &shdr[i];
        }
    }

    if (!symtab || !strtab) {
        printf("relevant section not found");
        return 0;
    }

    Elf32_Sym *symbols = (Elf32_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf32_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!strcmp(name, "main")) {
            return symbols[i].st_size;
        }
    }

    printf("main size not found");
    return 0;
}

void patch_payload_32(unsigned char *payload, uint32_t main_addr, uint32_t main_size, char *key, uint32_t payload_vaddr) {
    uint32_t page_size = 0x1000;
    uint32_t aligned_addr = main_addr & ~(page_size - 1);
    uint32_t offset = main_addr - aligned_addr;
    uint32_t mprotect_size = ((main_size + offset + page_size - 1) & ~(page_size - 1));
    uint32_t keylen = strlen(key);

    printf("aligned_addr: 0x%x | mprotect_size: 0x%x | keylen: %u\n", aligned_addr, mprotect_size, keylen);

    uint32_t msg_addr_woody = payload_vaddr + 165;
    uint32_t msg_addr_key = payload_vaddr + 180;
    uint32_t key_addr = payload_vaddr + 192;

    memcpy(&payload[11], &msg_addr_woody, 4);

    memcpy(&payload[28], &aligned_addr, 4);

    memcpy(&payload[55], &msg_addr_key, 4);

    memcpy(&payload[77], &key_addr, 4);

    memcpy(&payload[102], &main_addr, 4);

    memcpy(&payload[107], &main_size, 4);

    memcpy(&payload[112], &key_addr, 4);

    memcpy(&payload[150], &main_addr, 4);
}

unsigned char *add_section_32(unsigned char *file, t_elf *elf, unsigned long file_size, unsigned long *new_file_size, Elf32_Off *func_offset, Elf32_Xword *func_size, Elf32_Addr *func_vaddr, char *key) { 
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Phdr *phdr = (Elf32_Phdr *)(file + ehdr->e_phoff);
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file + ehdr->e_shoff);
   
    // Elf32_Addr start_addr = ehdr->e_entry;
    Elf32_Addr main_addr = find_main_addr_32(file);
    Elf32_Xword main_size = find_main_size_32(file);
    Elf32_Off main_offset = find_main_offset_32(file);
    if (main_addr == 0 || main_size == 0 || main_offset == 0) {
        printf("error addr/size/offset main\n");
        return 0;
    }
    // printf("Start address: 0x%lx\n", start_addr);
    printf("main address: 0x%x| main size: 0x%lx| main offset 0x%x\n", main_addr, main_size, main_offset);

    unsigned char payload_write_woody[] = {
        // --- write(1, "....WOODY....", 14) ---
        0xb8, 0x04, 0x00, 0x00, 0x00,             // mov eax, 4 (sys_write)
        0xbb, 0x01, 0x00, 0x00, 0x00,             // mov ebx, 1 (stdout)
        0xb9, 0x00, 0x00, 0x00, 0x00,             // mov ecx, <address msg>
        0xba, 0x0e, 0x00, 0x00, 0x00,             // mov edx, 14
        0xcd, 0x80,                               // int 0x80
        // 22 -- 22

        // --- mprotect(main_page, size, RWX) ---
        0xb8, 0x7d, 0x00, 0x00, 0x00,             // mov eax, 125 (mprotect)
        0xbb, 0x00, 0x00, 0x00, 0x00,             // mov ebx, <main_page>
        0xb9, 0x00, 0x10, 0x00, 0x00,             // mov ecx, 0x1000
        0xba, 0x07, 0x00, 0x00, 0x00,             // mov edx, 7 (RWX)
        0xcd, 0x80,                               // int 0x80
        // 22 -- 44

        // --- write(1, "Enter key: ", 11) ---
        0xb8, 0x04, 0x00, 0x00, 0x00,             // mov eax, 4 (sys_write)
        0xbb, 0x01, 0x00, 0x00, 0x00,             // mov ebx, 1 (stdout)
        0xb9, 0x00, 0x00, 0x00, 0x00,             // mov ecx, <address msg>
        0xba, 0x0b, 0x00, 0x00, 0x00,             // mov edx, 11
        0xcd, 0x80,                               // int 0x80
        // 22 -- 66

        // --- read(0, key, key_len)
        0xb8, 0x03, 0x00, 0x00, 0x00,             // mov eax, 3 (sys_read)
        0xbb, 0x00, 0x00, 0x00, 0x00,             // mov ebx, 0 (stdin)
        0xb9, 0x00, 0x00, 0x00, 0x00,             // mov ecx, <key_addr>
        0xba, 0x28, 0x00, 0x00, 0x00,             // mov edx, 40
        0xcd, 0x80,                               // int 0x80
        0x89, 0xc7,                               // mov edi, eax
        // 24 -- 90

        // --- check \n end key
        0x31, 0xc0,                               // xor eax, eax
        0x4F,                                     // dec edi
        0x8A, 0x04, 0x39,                         // mov al, [ecx + edi]
        0x3C, 0x0A,                               // cmp al, 0x0a
        0x74, 0x01,                               // je +1
        0x47,                                     // inc edi
        // 11 -- 101

        // --- XOR decrypt loop ---
        0xbe, 0x00, 0x00, 0x00, 0x00,             // mov esi, <main_addr>
        0xb9, 0x00, 0x00, 0x00, 0x00,             // mov ecx, <main_size>
        0xba, 0x00, 0x00, 0x00, 0x00,             // mov edx, <key_addr>
        0x31, 0xed,                               // xor ebp, ebp
        0x31, 0xdb,                               // xor ebx, ebx              ; i = 0
        // 19 -- 120

        // loop:
        0x31, 0xc0,                               // xor eax, eax
        0x8a, 0x04, 0x1a,                         // mov al, [edx + ebx]
        0x30, 0x04, 0x2e,                         // xor [esi + ebp], al
        0x45,                                     // inc ebp                   ; i++
        0x43,                                     // inc ebx                   ; j++
        0x39, 0xdf,                               // cmp ebx, edi              ; j < key_len ?
        0x75, 0x02,                               // jne skip_reset
        0x31, 0xdb,                               // xor ebx, ebx              ; j = 0
        // skip_reset:
        0x39, 0xcd,                               // cmp ebp, ecx              ; i < main_size ?
        0x7c, 0xec,                               // jl loop
        // 20 -- 140

        // --- push args and call main ---
        0x8b, 0x04, 0x24,                         // mov eax, [esp]
        0x8d, 0x5c, 0x24, 0x04,                   // lea ebx, [esp+4]
        0x53,                                     // push ebx
        0x50,                                     // push eax
        0xb8, 0x00, 0x00, 0x00, 0x00,             // mov eax, <main_addr>
        0xff, 0xd0,                               // call eax
        // 16 -- 156

        // --- exit(0) ---
        0xb8, 0x01, 0x00, 0x00, 0x00,             // mov eax, 1
        0x31, 0xdb,                               // xor ebx, ebx
        0xcd, 0x80,                               // int 0x80
        // 9 -- 165

        '.', '.', '.', '.', 'W', 'O', 'O', 'D', 'Y', '.', '.', '.', '.', '\n', '\0',
        // 15 -- 180

        'E', 'n', 't', 'e', 'r', ' ', 'k', 'e', 'y', ':', ' ', '\0',
        // 12 -- 192

        // --- key data ---
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };

    const char new_section_name[] = ".test";

    size_t payload_size = sizeof(payload_write_woody) - 1;
    size_t new_section_name_len = strlen(new_section_name) + 1;

    printf("Payload size: %ld %lx\n", payload_size, payload_size);

    // PT_LOAD E
    Elf32_Phdr *exec_segment = NULL;
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
    Elf32_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
    const char *old_shstrtab = (const char *)(file + shstrtab->sh_offset);
    
    // Calculer le nouvel offset pour injection payload
    Elf32_Off injection_offset = exec_segment->p_offset + exec_segment->p_filesz;
    Elf32_Addr injection_vaddr = exec_segment->p_vaddr + exec_segment->p_filesz;

    patch_payload_32(payload_write_woody, main_addr, main_size, key, injection_vaddr);
    
    // Nouveau offset pour la .shstrtab étendue (après payload)
    Elf32_Off new_shstrtab_offset = injection_offset + payload_size;
    
    // Nouvelle taille pour .shstrtab (ancienne taille + nouveau nom)
    size_t new_shstrtab_size = shstrtab->sh_size + new_section_name_len;

    size_t extended_size = file_size + payload_size + sizeof(Elf32_Shdr) + new_section_name_len;

    unsigned char *new_file = calloc(1, extended_size);
    if (!new_file)
        return NULL;

    // Copier l'ancien fichier dans le nouveau buffer
    memcpy(new_file, file, file_size);

    // Copier le payload à l'offset d'injection
    memcpy(new_file + injection_offset, payload_write_woody, payload_size);

    // Mettre à jour le segment PT_LOAD exécutable pour inclure la payload
    Elf32_Phdr *new_phdr = (Elf32_Phdr *)(new_file + ehdr->e_phoff);
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
    Elf32_Shdr *new_shdr = (Elf32_Shdr *)(new_file + ehdr->e_shoff);
    new_shdr[ehdr->e_shstrndx].sh_offset = new_shstrtab_offset;
    new_shdr[ehdr->e_shstrndx].sh_size = new_shstrtab_size;

    // add nouvelle section 
    int shnum = ehdr->e_shnum;
    Elf32_Shdr *new_section = &new_shdr[shnum];
    new_section->sh_name = shstrtab->sh_size;
    new_section->sh_type = SHT_PROGBITS;
    new_section->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_section->sh_addr = injection_vaddr;
    new_section->sh_offset = injection_offset;
    new_section->sh_size = payload_size;
    new_section->sh_addralign = 0x10;

    // update header elf
    ehdr = (Elf32_Ehdr *)new_file;
    ehdr->e_shnum += 1;
    ehdr->e_entry = injection_vaddr;

    *new_file_size = extended_size;
    *func_offset = injection_offset;
    *func_size = payload_size;
    *func_vaddr = injection_vaddr;

    return new_file;
}
