/*
tester.c

Tester for stack protection mechanisms.

CS 880
Jordan Chadwick
*/

#include <stdlib.h>
#include <stdio.h>

// read_data function
void read_data_buffer(FILE *fp) {
    int buff_size = 255;
    char buff[buff_size];

    fgets(buff, buff_size, fp);
    print("buff = %s\n", buff);
}

// main function
int main(int argc, char const *argv[]) {

    FILE *fp;
    fp = fopen(argv[1], "r");
    read_data_buffer(fp);

    return 0;
}
