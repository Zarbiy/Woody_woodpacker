#include "woody_packer.h"

void crypt_main_64(unsigned char *file, char *key) {
    Elf64_Off text_offset = find_text_offset_64(file);
    Elf64_Xword text_size = find_text_size_64(file);
    size_t key_len = ft_strlen(key);

    if (text_offset == 0 || text_size == 0) {
        printf("Error\n");
        return ;
    }

    for (Elf64_Xword i = 0; i < text_size; ++i) {
        file[text_offset + i] ^= key[i % key_len];
    }
}

void crypt_main_32(unsigned char *file, char *key) {
    Elf32_Off text_offset = find_text_offset_32(file);
    Elf32_Xword text_size = find_text_size_32(file);
    size_t key_len = ft_strlen(key);

    if (text_offset == 0 || text_size == 0) {
        printf("Error\n");
        return ;
    }

    for (Elf32_Xword i = 0; i < text_size; ++i) {
        file[text_offset + i] ^= key[i % key_len];
    }
}
