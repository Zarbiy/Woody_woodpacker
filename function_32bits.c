#include "woody_packer.h"

void patch_payload_32(unsigned char *payload, uint32_t text_addr, uint32_t text_size, uint32_t payload_vaddr, uint32_t main_addr) {
    uint32_t page_size = 0x1000;
    uint32_t aligned_addr = text_addr & ~(page_size - 1);
    uint32_t offset = text_addr - aligned_addr;
    uint32_t mprotect_size = ((text_size + offset + page_size - 1) & ~(page_size - 1));

    uint32_t msg_addr_woody = payload_vaddr + 182;
    uint32_t msg_addr_key = payload_vaddr + 197;
    uint32_t key_addr = payload_vaddr + 209;

    ft_memcpy(&payload[11], &msg_addr_woody, 4);

    ft_memcpy(&payload[33], &mprotect_size, 4);

    ft_memcpy(&payload[28], &aligned_addr, 4);

    ft_memcpy(&payload[55], &msg_addr_key, 4);

    ft_memcpy(&payload[77], &key_addr, 4);

    ft_memcpy(&payload[102], &text_addr, 4);

    ft_memcpy(&payload[107], &text_size, 4);

    ft_memcpy(&payload[112], &key_addr, 4);

    ft_memcpy(&payload[167], &main_addr, 4);
}

unsigned char *add_section_32(unsigned char *file, unsigned long file_size, unsigned long *new_file_size, Elf32_Off *func_offset, Elf32_Xword *func_size, Elf32_Addr *func_vaddr) { 
    Elf32_Ehdr *ehdr = (Elf32_Ehdr *)file;
    Elf32_Phdr *phdr = (Elf32_Phdr *)(file + ehdr->e_phoff);
    Elf32_Shdr *shdr = (Elf32_Shdr *)(file + ehdr->e_shoff);
   
    // Elf32_Addr start_addr = ehdr->e_entry;
    Elf32_Addr main_addr = find_main_addr_32(file);
    if (main_addr == 0) {
        printf("error addr main\n");
        return NULL;
    }
    // printf("Start address: 0x%lx\n", start_addr);
    // printf("main address: 0x%x| main size: 0x%lx| main offset 0x%x\n", main_addr, main_size, main_offset);

    Elf32_Addr text_addr = find_text_addr_32(file);
    Elf32_Xword text_size = find_text_size_32(file);
    Elf32_Off text_offset = find_text_offset_32(file);
    if (text_addr == 0 || text_size == 0 || text_offset == 0) {
        printf("error addr/size/offset .text\n");
        return NULL;
    }
    printf("text address: 0x%x| text size: 0x%lx| text offset 0x%x\n", text_addr, text_size, text_offset);

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
        0xba, 0xf4, 0x01, 0x00, 0x00,             // mov edx, 500
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
        0x8b, 0x04, 0x24,                    // mov    eax, [esp]       ; argc
        0x8d, 0x5c, 0x24, 0x04,              // lea    ebx, [esp+4]     ; argv
        0x89, 0xd9,                          // mov    ecx, ebx         ; ecx = argv
        0x8b, 0x01,                          // mov    eax, [ecx]       ; eax = argv[i]
        0x83, 0xc1, 0x04,                    // add    ecx, 4           ; argv[i+1]
        0x85, 0xc0,                          // test   eax, eax
        0x75, 0xf7,                          // jnz    -9               ; boucle jusqu'à NULL
        0x89, 0xca,                          // mov    edx, ecx         ; edx = envp
        0x8b, 0x04, 0x24,                    // mov    eax, [esp]       ; argc
        0x52,                                // push   edx              ; envp
        0x53,                                // push   ebx              ; argv
        0x50,                                // push   eax              ; argc
        0xb8, 0x00, 0x00, 0x00, 0x00,        // mov    eax, <main_addr>
        0xff, 0xd0,                          // call   eax
        // 33 -- 173

        // --- exit(0) ---
        0xb8, 0x01, 0x00, 0x00, 0x00,             // mov eax, 1
        0x31, 0xdb,                               // xor ebx, ebx
        0xcd, 0x80,                               // int 0x80
        // 9 -- 182

        '.', '.', '.', '.', 'W', 'O', 'O', 'D', 'Y', '.', '.', '.', '.', '\n', '\0',
        // 15 -- 197

        'E', 'n', 't', 'e', 'r', ' ', 'k', 'e', 'y', ':', ' ', '\0',
        // 12 -- 209

        // --- key data ---
        0x00
    };

    const char new_section_name[] = ".test";

    size_t payload_size = sizeof(payload_write_woody) - 1;
    size_t new_section_name_len = ft_strlen(new_section_name) + 1;

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
    
    Elf32_Shdr *shstrtab = &shdr[ehdr->e_shstrndx];
    const char *old_shstrtab = (const char *)(file + shstrtab->sh_offset);
    
    Elf32_Off injection_offset = exec_segment->p_offset + exec_segment->p_filesz;
    Elf32_Addr injection_vaddr = exec_segment->p_vaddr + exec_segment->p_filesz;

    patch_payload_32(payload_write_woody, text_addr, text_size, injection_vaddr, main_addr);
    
    Elf32_Off new_shstrtab_offset = injection_offset + payload_size;
    
    size_t new_shstrtab_size = shstrtab->sh_size + new_section_name_len;

    size_t extended_size = file_size + payload_size + sizeof(Elf32_Shdr) + new_section_name_len;

    unsigned char *new_file = calloc(1, extended_size);
    if (!new_file)
        return NULL;

    ft_memcpy(new_file, file, file_size);

    ft_memcpy(new_file + injection_offset, payload_write_woody, payload_size);

    Elf32_Phdr *new_phdr = (Elf32_Phdr *)(new_file + ehdr->e_phoff);
    for (int i = 0; i < ehdr->e_phnum; i++) {
        if ((new_phdr[i].p_type == PT_LOAD) && (new_phdr[i].p_flags & PF_X)) {
            new_phdr[i].p_filesz += payload_size;
            new_phdr[i].p_memsz += payload_size;
            break;
        }
    }

    char *new_shstrtab = (char *)(new_file + new_shstrtab_offset);
    ft_memcpy(new_shstrtab, old_shstrtab, shstrtab->sh_size);
    strcpy(new_shstrtab + shstrtab->sh_size, new_section_name);

    Elf32_Shdr *new_shdr = (Elf32_Shdr *)(new_file + ehdr->e_shoff);
    new_shdr[ehdr->e_shstrndx].sh_offset = new_shstrtab_offset;
    new_shdr[ehdr->e_shstrndx].sh_size = new_shstrtab_size;

    int shnum = ehdr->e_shnum;
    Elf32_Shdr *new_section = &new_shdr[shnum];
    new_section->sh_name = shstrtab->sh_size;
    new_section->sh_type = SHT_PROGBITS;
    new_section->sh_flags = SHF_ALLOC | SHF_EXECINSTR;
    new_section->sh_addr = injection_vaddr;
    new_section->sh_offset = injection_offset;
    new_section->sh_size = payload_size;
    new_section->sh_addralign = 0x10;

    ehdr = (Elf32_Ehdr *)new_file;
    ehdr->e_shnum += 1;
    ehdr->e_entry = injection_vaddr;

    *new_file_size = extended_size;
    *func_offset = injection_offset;
    *func_size = payload_size;
    *func_vaddr = injection_vaddr;

    return new_file;
}
