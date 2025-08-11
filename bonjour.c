#include <unistd.h>
#include <stdio.h>
#include <string.h>

int main(int ac, char **argv, char **env){
    write(1, "Bonjour je suis bob\n", 20);
    printf("%d\n", ac);
    for(int i = 0; i < 100; i++) {
        if (i % 3 == 0)
            printf("%d", i);
        else
            printf(".");
    }
    printf("\n");
    char buf[10] = "\0";
    int n = 0;
    n = read(0, buf, 9);

    printf("%s\n", buf);
    printf("%d\n", n);

    printf("%s\n", argv[2]);
    printf("%s\n", env[0]);

    int b = 0;
    while (1){
        if (b == 100)
            break;
        b += 1;
    }

    return 0;
}