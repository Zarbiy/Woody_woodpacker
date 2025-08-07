#include <unistd.h>
#include <stdio.h>
int main(){
    write(1, "Bonjour je suis bob\n", 20);
    for(int i = 0; i < 100; i++) {
        if (i % 3 == 0)
            printf("%d", i);
        else
            printf(".");
    }
    printf("\n");
    char buf[10];
    read(0, buf, 10);
    buf[9] = '\0';

    printf("%s\n", buf);
    return 0;
}