#include "woody_packer.h"

int main(int ac, char **av){
    if (ac < 2 || ac > 4) {
        printf("Wrong number of argument ! Use:\n");
        printf("./woody_woodpacker exec_name (len_key) (char_in_key)");
        return 0;
    }

    int fd = open(av[1], O_RDWR);
    if (fd == -1){
        perror("");
        return 0;
    }
    unsigned long file_size = lseek(fd, 0, SEEK_END);
    if (file_size <= 0){
        write(2, "File empty\n", 11);
        close(fd);
        return 0;
    }

    unsigned char *file = mmap(NULL, file_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (file == MAP_FAILED) {
        perror("mmap");
        close(fd);
        return 0;
    }
    close(fd);

    int archi = file[4];
    int size_key = calc_size_key(file, archi);
    if (size_key == 0)
        return 0;
    char *my_key = "";
    if (ac == 3) {
        size_key = verif_len_key(ft_atoi(av[2]), file);
        if (size_key <= 0) {
            printf("Error len key\n");
            return 0;
        }
        my_key = generate_key(size_key, NULL);
    }
    else if (ac == 4) {
        size_key = verif_len_key(ft_atoi(av[2]), file);
        if (size_key <= 0) {
            printf("Error len key\n");
            return 0;
        }
        my_key = generate_key(size_key, av[3]);
    }
    else
        my_key = generate_key(size_key, NULL);
    if (my_key == NULL) 
        return 0;

    unsigned char *new_file;
    unsigned long new_file_size = 0;

    if (archi == 1) {
        Elf32_Off func_offset = 0;
        Elf32_Xword func_size = 0;
        Elf32_Addr func_vaddr = 0;
        new_file = add_section_32(file, file_size, &new_file_size, &func_offset, &func_size, &func_vaddr);
        if (new_file == NULL) {
            free(my_key);
            return 0;
        }
        crypt_main_32(new_file, my_key);
    }
    else if (archi == 2) {
        Elf64_Off func_offset = 0;
        Elf64_Xword func_size = 0;
        Elf64_Addr func_vaddr = 0;
        new_file = add_section_64(file, file_size, &new_file_size, &func_offset, &func_size, &func_vaddr);
        if (new_file == NULL) {
            free(my_key);
            return 0;
        }
        crypt_main_64(new_file, my_key);
    }
    else {
        printf("Architecture not found or not valid\n");
        return 0;
    }

    read_elf(new_file);

    int new_fd = open("woody", O_CREAT | O_WRONLY | O_TRUNC, 0777);
    write(new_fd, new_file, new_file_size);
    close(new_fd);

    printf("Key: %s\n", my_key);
    free(new_file);
    free(my_key);
    return 0;
}