#include "woody_packer.h"

void crypt_main(unsigned char *file, char *key) {
    Elf64_Off main_offset = find_main_offset_64(file);
    Elf64_Xword main_size = find_main_size_64(file);
    size_t key_len = strlen(key);

    if (main_offset == 0 || main_size == 0) {
        printf("Error\n");
        return ;
    }

    for (Elf64_Xword i = 0; i < main_size; ++i) {
        file[main_offset + i] ^= key[i % key_len];
    }
}