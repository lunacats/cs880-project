/*
tester.c

Tester for stack protection mechanisms.

CS 880
Jordan Chadwick
*/

#include <stdlib.h>
#include <stdio.h>

// read_data function
void read_file(FILE *fp) {
    int buff_size = 255;
    char buff[buff_size];

    if (fgets(buff, buff_size, fp) == NULL);
        return -1;

    printf("buff = %s\n", buff);

    return buff_size;
}

// main function
int main(int argc, char const *argv[]) {

    FILE *fp;
    fp = fopen(argv[1], "r");
    
    chars_read = read_file(fp);
    while(chars_read != -1) {
        chars_read = read_file(fp)
    }

    return 0;
}
