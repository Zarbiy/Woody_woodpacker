#include "woody_packer.h"

void crypt_main_64(unsigned char *file, char *key) {
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

void crypt_main_32(unsigned char *file, char *key) {
    Elf32_Off main_offset = find_main_offset_32(file);
    Elf32_Xword main_size = find_main_size_32(file);
    size_t key_len = strlen(key);

    if (main_offset == 0 || main_size == 0) {
        printf("Error\n");
        return ;
    }

    for (Elf32_Xword i = 0; i < main_size; ++i) {
        file[main_offset + i] ^= key[i % key_len];
    }
}

// #include <string.h>
// #include <stdio.h>

// void crypt(char *file, char *key) {
//     size_t key_len = strlen(key);
//     for (int i = 0; i < strlen(file); ++i) {
//         file[i] ^= key[i % key_len];
//     }
// }

// int main() {
//     char file[] = "bonjour je suis bob";
//     char *key = "dqfqfq5q75q";

//     crypt(file, key);
//     printf("File: %s\n", file);
//     crypt(file, key);
//     printf("File: %s\n", file);

//     return 0;
// }