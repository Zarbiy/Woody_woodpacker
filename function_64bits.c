#include "woody_packer.h"

long space_between_fini_rodata_64(unsigned char *file) {
    Elf64_Ehdr *eh = (Elf64_Ehdr *)file;

    Elf64_Shdr *sections = (Elf64_Shdr *)(file + eh->e_shoff);
    Elf64_Shdr *sh_strtab = &sections[eh->e_shstrndx];
    const char *strtab = (const char *)(file + sh_strtab->sh_offset);

    Elf64_Addr fini_end = 0, rodata_start = 0;

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *name = strtab + sections[i].sh_name;
        if (strcmp(name, ".fini") == 0) {
            fini_end = sections[i].sh_addr + sections[i].sh_size;
        }
        else if (strcmp(name, ".rodata") == 0) {
            rodata_start = sections[i].sh_addr;
        }
    }

    if (!fini_end || !rodata_start) {
        fprintf(stderr, "Sections .fini ou .rodata introuvables\n");
        return -1;
    }

    return (long)(rodata_start - fini_end);
}

Elf64_Off find_main_offset_64(unsigned char *file) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (!ft_strcmp(section_name, ".symtab"))
            symtab = &shdr[i];
        else if (!ft_strcmp(section_name, ".strtab"))
            strtab = &shdr[i];
    }

    if (!symtab || !strtab) {
        printf("relevant section not found\n");
        return 0;
    }

    Elf64_Sym *symbols = (Elf64_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);

    Elf64_Addr main_addr = 0;
    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!ft_strcmp(name, "main")) {
            main_addr = symbols[i].st_value;
            break;
        }
    }

    if (!main_addr) {
        printf("main not found\n");
        return 0;
    }

    Elf64_Phdr *phdr = (Elf64_Phdr *)(file + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if (phdr[i].p_type == PT_LOAD) {
            Elf64_Addr start = phdr[i].p_vaddr;
            Elf64_Addr end = start + phdr[i].p_memsz;

            if (main_addr >= start && main_addr < end) {
                Elf64_Off offset = phdr[i].p_offset + (main_addr - start);
                return offset;
            }
        }
    }
    return 0;
}


Elf64_Addr find_main_addr_64(unsigned char *file) {
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
    const char *sh_strtab = (char *)(file + shdr[ehdr->e_shstrndx].sh_offset);

    Elf64_Shdr *symtab = NULL;
    Elf64_Shdr *strtab = NULL;

    for (int i = 0; i < ehdr->e_shnum; i++) {
        const char *section_name = sh_strtab + shdr[i].sh_name;
        if (!ft_strcmp(section_name, ".symtab")) {
            symtab = &shdr[i];
        }
        else if (!ft_strcmp(section_name, ".strtab")) {
            strtab = &shdr[i];
        }
    }

    if (!symtab || !strtab) {
        printf("relevant section not found\n");
        return 0;
    }

    Elf64_Sym *symbols = (Elf64_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!ft_strcmp(name, "main")) {
            return symbols[i].st_value;
        }
    }

    printf("main addr not found\n");
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
        if (!ft_strcmp(section_name, ".symtab")) {
            symtab = &shdr[i];
        }
        else if (!ft_strcmp(section_name, ".strtab")) {
            strtab = &shdr[i];
        }
    }

    if (!symtab || !strtab) {
        printf("relevant section not found\n");
        return 0;
    }

    Elf64_Sym *symbols = (Elf64_Sym *)(file + symtab->sh_offset);
    const char *strtab_data = (char *)(file + strtab->sh_offset);
    int num_symbols = symtab->sh_size / sizeof(Elf64_Sym);

    for (int i = 0; i < num_symbols; i++) {
        const char *name = strtab_data + symbols[i].st_name;
        if (!ft_strcmp(name, "main")) {
            return symbols[i].st_size;
        }
    }

    printf("main size not found\n");
    return 0;
}

void patch_payload_64(unsigned char *payload, uint64_t main_addr, uint64_t main_size, uint64_t payload_vaddr) {
    uint64_t page_size = 0x1000;
    uint64_t aligned_addr = main_addr & ~(page_size - 1);
    uint64_t offset = main_addr - aligned_addr;
    uint64_t mprotect_size = ((main_size + offset + page_size - 1) & ~(page_size - 1));

    // a voir si il faut injecter ca !!!
    printf("aligned_addr %lx| mprotect_size %lx\n", aligned_addr, mprotect_size);

    // addr main
    memcpy(&payload[141], &main_addr, 8);

    // size main
    memcpy(&payload[151], &main_size, 8);
    memcpy(&payload[151], &main_size, 8);

    // addr main
    memcpy(&payload[231], &main_addr, 8);

    uint64_t key_addr = payload_vaddr + 278;
    memcpy(&payload[100], &key_addr, 8);
    printf("%lx\n", key_addr);
}

unsigned char *add_section_64(unsigned char *file, unsigned long file_size, unsigned long *new_file_size, Elf64_Off *func_offset, Elf64_Xword *func_size, Elf64_Addr *func_vaddr) { 
    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file;
    Elf64_Phdr *phdr = (Elf64_Phdr *)(file + ehdr->e_phoff);
    Elf64_Shdr *shdr = (Elf64_Shdr *)(file + ehdr->e_shoff);
   
    // Elf64_Addr start_addr = ehdr->e_entry;
    Elf64_Addr main_addr = find_main_addr_64(file);
    Elf64_Xword main_size = find_main_size_64(file);
    Elf64_Off main_offset = find_main_offset_64(file);
    if (main_addr == 0 || main_size == 0 || main_offset == 0) {
        printf("error addr/size/offset main\n");
        return NULL;
    }
    // printf("Start address: 0x%lx\n", start_addr);
    printf("main address: 0x%lx| main size: 0x%lx| main offset 0x%lx\n", main_addr, main_size, main_offset);

    unsigned char payload_write_woody[] = {
        // --- Save stack ---
        0x48, 0x89, 0xe3,                           // mov rbx, rsp
        0x48, 0x31, 0xc0,                           // xor rax, rax
        // 6 -- 6

        // --- write(1, "....WOODY....", 14) ---
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,   // mov rdi, 1
        0x48, 0x8d, 0x35, 0xe7, 0x00, 0x00, 0x00,   // lea rsi, [rip + 231] ; <msg_woody>
        0xba, 0x0e, 0x00, 0x00, 0x00,               // mov edx, 14
        0xb8, 0x01, 0x00, 0x00, 0x00,               // mov eax, 1
        0x0f, 0x05,                                 // syscall
        // 26 -- 32

        // --- mprotect ---
        0x48, 0xbf, 0x00, 0x10, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rdi, <main_page>
        0x48, 0xbe, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rsi, 0x1000
        0x48, 0xba, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rdx, 7
        0xb8, 0x0a, 0x00, 0x00, 0x00,                                   // mov eax, 10
        0x0f, 0x05,                                                     // syscall
        // 37 -- 69

        // --- write(1, "Enter key: ", 11) ---
        0x48, 0xc7, 0xc7, 0x01, 0x00, 0x00, 0x00,   // mov rdi, 1
        0x48, 0x8d, 0x35, 0xb7, 0x00, 0x00, 0x00,   // lea rsi, [rip + 183] ; <msg_enter>
        0xba, 0x0b, 0x00, 0x00, 0x00,               // mov edx, 11
        0xb8, 0x01, 0x00, 0x00, 0x00,               // mov eax, 1
        0x0f, 0x05,                                 // syscall
        // 26 -- 95

        // --- read(0, key, key_len)
        0x48, 0x31, 0xff,                                               // xor rdi, rdi
        0x48, 0xbe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // mov rsi, <key_addr>
        0xba, 0xf4, 0x01, 0x00, 0x00,                                   // mov edx, 500
        0xb8, 0x00, 0x00, 0x00, 0x00,                                   // mov eax, 0
        0x0f, 0x05,                                                     // syscall
        0x48, 0x89, 0xc7,                                               // mov rdi, rax
        // 28 -- 123

        // --- check \n end key
        0x31, 0xc0,                     // xor eax, eax
        0x48, 0xff, 0xcf,               // dec rdi
        0x8a, 0x44, 0x3e, 0x00,         // mov al, [rsi + rdi]
        0x3c, 0x0a,                     // cmp al, 0x0a
        0x74, 0x03,                     // je skip_inc
        0x48, 0xff, 0xc7,               // inc rdi
        // 16 -- 139

        // --- Decrypt main ---
        0x49, 0xbb,                                         // mov r11, <main_addr>
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // <main_addr>
        0x48, 0xb9,                                         // mov rcx, <main_size>
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,     // <main_size> 
        0x48, 0x8d, 0x1d, 0x70, 0x00, 0x00, 0x00,           // lea rbx, [rip + 112]
        0x48, 0x31, 0xf6,                                   // xor rsi, rsi        ; i = 0
        0x48, 0x31, 0xd2,                                   // xor rdx, rdx        ; j = 0
        // 33 -- 172

        // xor_loop:
        0x4d, 0x31, 0xc9,                           // xor r9, r9
        0x44, 0x8a, 0x0c, 0x13,                     // mov r9b, [rbx + rdx]
        0x45, 0x30, 0x0c, 0x33,                     // xor [r11 + rsi], r9b
        0x48, 0xff, 0xc6,                           // inc rsi             ; ++i
        0x48, 0xff, 0xc2,                           // inc rdx             ; ++j
        // 17 -- 189

        0x48, 0x39, 0xfa,                           // cmp rdx, rdi        ; j < key_len ?
        0x72, 0x03,                                 // jb skip_reset
        0x48, 0x31, 0xd2,                           // xor rdx, rdx        ; j = 0
        // skip_reset:
        0x48, 0xff, 0xc9,                           // dec rcx
        0x75, 0xe2,                                 // jne xor_loop
        // 13 -- 202

        // --- Setup main(argc, argv, envp) ---
        0x48, 0x8b, 0x3c, 0x24,                                     // mov    rdi, [rsp]      ; argc
        0x48, 0x8d, 0x74, 0x24, 0x08,                               // lea    rsi, [rsp+8]    ; argv
        0x48, 0x89, 0xf1,                                           // mov    rcx, rsi        ; rcx = argv
        0x48, 0x8b, 0x01,                                           // mov    rax, [rcx]      ; rax = argv[i]
        0x48, 0x83, 0xc1, 0x08,                                     // add    rcx, 8          ; pointer vers argv[i+1]
        0x48, 0x85, 0xc0,                                           // test   rax, rax
        0x75, 0xf4,                                                 // jnz    -0x0C (loop)
        0x48, 0x89, 0xca,                                           // mov    rdx, rcx        ; rdx = envp
        0x48, 0xb8,                                                 // mov rax, <main_addr>
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,             // <main_addr>
        0xff, 0xd0,                                                 // call rax
        // 39 -- 241

        // --- exit(0) ---
        0x48, 0x31, 0xff,                           // xor edi, edi
        0xb8, 0x3c, 0x00, 0x00, 0x00,               // mov eax, 60
        0x0f, 0x05,                                 // syscall
        // 10 -- 251

        '.', '.', '.', '.', 'W', 'O', 'O', 'D', 'Y', '.', '.', '.', '.', '\n', '\0',
        // 15 -- 266

        'E', 'n', 't', 'e', 'r', ' ', 'k', 'e', 'y', ':', ' ', '\0',
        // 12 -- 278

        // --- key data ---
        0x00
    };

    const char new_section_name[] = ".test";

    size_t payload_size = sizeof(payload_write_woody) - 1;
    size_t new_section_name_len = strlen(new_section_name) + 1;

    // printf("Payload size: %ld %lx\n", payload_size, payload_size);

    // PT_LOAD
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

    // find .shstrtab
    Elf64_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
    const char *old_shstrtab = (const char *)(file + shstrtab->sh_offset);

    // Calculer le nouvel offset pour injection payload
    Elf64_Off injection_offset = exec_segment->p_offset + exec_segment->p_filesz;
    Elf64_Addr injection_vaddr = exec_segment->p_vaddr + exec_segment->p_filesz;

    patch_payload_64(payload_write_woody, main_addr, main_size, injection_vaddr);

    // update offset.shstrtab
    Elf64_Off new_shstrtab_offset = injection_offset + payload_size;

    // update taille .shstrtab
    size_t new_shstrtab_size = shstrtab->sh_size + new_section_name_len;

    size_t extended_size = file_size + payload_size + sizeof(Elf64_Shdr) + new_section_name_len;

    unsigned char *new_file = calloc(1, extended_size);
    if (!new_file)
        return NULL;

    // copie ancien fichier dans le nouveau buffer
    memcpy(new_file, file, file_size);

    // copie payload à l'offset d'injection
    memcpy(new_file + injection_offset, payload_write_woody, payload_size);

    // update PT_LOAD pour inclure le payload
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
