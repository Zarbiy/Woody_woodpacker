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
            // if (!ft_strcmp(name_section, ".text", 5) || !ft_strcmp(name_section, ".test", 5)) {
            //     unsigned char *str_text = file + section->sh_offset;
            //     for (size_t i = 0; i < section->sh_size; i++) {
            //         printf("%02x ", str_text[i]);
            //     }
            //     printf("\n");
            // }
        }
        else {
            Elf64_Shdr *section = &((Elf64_Shdr *)section_table)[i];
            char *name_section = start_name_section + section->sh_name;
            printf("%2d | %20s | %8lx | %4lx | %4lu(dec) %6lx(hex) | %i\n", i, start_name_section + section->sh_name, section->sh_addr, section->sh_offset, section->sh_size, section->sh_size, section->sh_name);
            // if (!ft_strcmp(name_section, ".text", 5) || !ft_strcmp(name_section, ".test", 5)) {
            //     unsigned char *str_text = file + section->sh_offset;
            //     for (size_t i = 0; i < section->sh_size; i++) {
            //         printf("%02x ", str_text[i]);
            //     }
            //     printf("\n");
            // }
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
    if (char_accepted == NULL || check_duplicate(char_accepted) == -1) {
        printf("Error in given string. Using default string\n");
        char_accepted = "123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmopqrstuvwxyz*-+/-_()#@$&";
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

    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        perror("open /dev/urandom");
        free(key);
        return NULL;
    }

    for (size_t i = 0; i < len_key; ++i) {
        unsigned char rnd;
        if (read(fd, &rnd, 1) != 1) {
            perror("read /dev/urandom");
            close(fd);
            free(key);
            return NULL;
        }
        key[i] = char_accepted[rnd % len_charset];
    }
    close(fd);

    key[len_key] = '\0';
    return key;
}

int calc_size_key(unsigned char *file, int archi) {
    long space_available = 0;
    int size_key = 0;

    if (archi == 1) {
        space_available = space_between_fini_rodata_32(file);
        size_key = find_main_size_32(file);
    }
    else if (archi == 2) {
        space_available = space_between_fini_rodata_64(file);
        size_key = find_main_size_64(file);
    }
    else {
        printf("Architecture not found or not valid\n");
        return 0;
    }

    if (size_key > space_available)
        size_key = space_available - 5;
    if (size_key > 499)
        size_key = 499;
    return size_key;
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

int ft_strcmp(const char *s1, const char *s2) {
    while (*s1 && (*s1 == *s2)) {
        s1++;
        s2++;
    }
    return (unsigned char)(*s1) - (unsigned char)(*s2);
}

int	ft_strncmp(const char *s1, const char *s2, size_t n)
{
	size_t			i;
	unsigned int	result;

	if (n == 0)
		return (0);
	i = 0;
	while (i < n - 1 && (unsigned char)s1[i] && (unsigned char)s2[i]
		&& (unsigned char)s1[i] == (unsigned char)s2[i])
		i++;
	result = (unsigned char)s1[i] - (unsigned char)s2[i];
	return (result);
}