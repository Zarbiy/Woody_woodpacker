#include "woody_packer.h"

uint64_t extract_bytes(unsigned char *file, uint8_t start, uint8_t end, uint64_t add_value) {
    uint64_t result = 0;
    for (int i = 0; i <= end - start; i++) {
        result |= ((uint64_t)file[add_value + start + i]) << (8 * i);
    }
    return result;
}

int read_elf_with_header(unsigned char *file) {
    // printf("Avec header elf\n\n");
    Elf32_Ehdr *header32 = NULL;
    Elf64_Ehdr *header64 = NULL;
    void *section_table = NULL;
    void *section_name = NULL;
    char *start_name_section = NULL;
    int shnum = 0;

    if (file[4] == 1) {
        header32 = (Elf32_Ehdr *)file;
        section_table = (Elf32_Shdr *)(file + header32->e_shoff);
        section_name = &((Elf32_Shdr *)section_table)[header32->e_shstrndx];
        start_name_section = (char *)(file + ((Elf32_Shdr *)section_name)->sh_offset);
        shnum = header32->e_shnum;

        // printf("%lx %lu\n", header32->e_shoff, header32->e_shoff);
        // printf("%lx %lu\n", section_name->sh_offset, section_name->sh_offset);

        printf("Type : %i\n", file[4]);
        printf("Nb sections : %d\n", header32->e_shnum);
        printf("Size sections : %d\n", header32->e_shentsize);
        printf("index section name : %d\n\n", header32->e_shstrndx);
    }
    else if (file[4] == 2) {
        header64 = (Elf64_Ehdr *)file;
        section_table = (Elf64_Shdr *)(file + header64->e_shoff);
        section_name = &((Elf64_Shdr *)section_table)[header64->e_shstrndx];
        start_name_section = (char *)(file + ((Elf64_Shdr *)section_name)->sh_offset);
        shnum = header64->e_shnum;

        // printf("%lx %lu\n", header64->e_shoff, header64->e_shoff);
        // printf("%lx %lu\n", section_name->sh_offset, section_name->sh_offset);

        printf("Type : %i\n", file[4]);
        printf("Nb sections : %d\n", header64->e_shnum);
        printf("Size sections : %d\n", header64->e_shentsize);
        printf("index section name : %d\n\n", header64->e_shstrndx);
    }
    else {
        write(2, "Error header elf\n", 18);
        return -1;
    }

    for (int i = 0; i < shnum; i++) {
        if (file[4] == 1) {
            Elf32_Shdr *section = &((Elf32_Shdr *)section_table)[i];
            char *name_section = start_name_section + section->sh_name;
            printf("%2d | %20s | %8x | %4x | %4u(dec) %6x(hex) | %i\n", i, name_section, section->sh_addr, section->sh_offset, section->sh_size, section->sh_size, section->sh_name);
            if (!strcmp(name_section, ".text")) {
                unsigned char *str_text = file + section->sh_offset;
                for (int i = 0; i < section->sh_size; i++) {
                    printf("%02x ", str_text[i]);
                }
                printf("\n");
            }
        }
        else {
            Elf64_Shdr *section = &((Elf64_Shdr *)section_table)[i];
            char *name_section = start_name_section + section->sh_name;
            printf("%2d | %20s | %8lx | %4lx | %4lu(dec) %6lx(hex) | %i\n", i, start_name_section + section->sh_name, section->sh_addr, section->sh_offset, section->sh_size, section->sh_size, section->sh_name);
            if (!strcmp(name_section, ".text") || !strcmp(name_section, ".test")) {
                unsigned char *str_text = file + section->sh_offset;
                for (int i = 0; i < section->sh_size; i++) {
                    printf("%02x ", str_text[i]);
                }
                printf("\n");
            }
        }
    }
    return 0;
}

int check_duplicate(char *input) {
    bool seen[256] = { false };

    for (const char *p = input; *p; ++p) {
        if (seen[(unsigned char)*p])
            return -1;
        else
            seen[(unsigned char)*p] = true;
    }
    return 0;
}

char *generate_key(size_t len_key, char *char_accepted) {
    if (len_key < 10 || len_key > 20) {
        printf("Key too short or to long (10-20). Using default len: 20\n");
        len_key = 20;
    }

    if (char_accepted == NULL) {
        printf("No string given. Using default string\n");
        char_accepted = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    }
    else if (check_duplicate(char_accepted) == -1) {
        char_accepted = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        printf("String given contains duplicate. Using default string\n");
    }

    size_t len_charset = strlen(char_accepted);

    if (len_charset < 10) {
        printf("not enough accepted characters\n");
        return NULL;
    }

    char *key = malloc(len_key + 1);
    if (!key) {
        printf("error malloc");
        return NULL;
    }

    srand((unsigned int)time(NULL));
    for (size_t i = 0; i < len_key; ++i) {
        key[i] = char_accepted[rand() % len_charset];
    }
    key[len_key] = '\0';
    return key;
}

char *key_to_hex(const char *key) {
    size_t len = strlen(key);
    char *hex = malloc(len * 2 + 1);
    if (!hex) return NULL;

    for (size_t i = 0; i < len; i++) {
        sprintf(hex + i*2, "%02x", (unsigned char)key[i]);
    }
    hex[len * 2] = '\0';
    return hex;
}

int	ft_atoi(const char *nptr)
{
	unsigned int	i;
	unsigned int	compteur;
	int				signe;
	int				valeur;

	compteur = 0;
	valeur = 0;
	i = 0;
	signe = 1;
	while (nptr[i] && (nptr[i] == ' ' || nptr[i] == '\f' || nptr[i] == '\n'
			|| nptr[i] == '\r' || nptr[i] == '\t' || nptr[i] == '\v'))
		i++;
	if (nptr[i] == '-' || nptr[i] == '+')
	{
		if (nptr[i] == '-')
			signe = -1;
		i++;
	}
	while (nptr[i] && nptr[i] >= '0' && nptr[i] <= '9')
	{
		valeur = valeur * 10 + (nptr[i] - '0');
		i++;
	}
	return (signe * valeur);
}