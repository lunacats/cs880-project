/*
tester.c

Tester for stack protection mechanisms.

CS 880
Jordan Chadwick
*/

#include <stdlib.h>
#include <stdio.h>

// read_file small buffer function
int read_file_small(FILE *fp) {
    int buff_size = 4;
    char buff[buff_size];

    if (fgets(buff, buff_size, fp) == NULL)
        return -1;

    return buff_size;
}


// read_file function
int read_file(FILE *fp) {
    int buff_size = 255;
    char buff[buff_size];

    if (fgets(buff, buff_size, fp) == NULL)
        return -1;

    //printf("buff = %s\n", buff);

    return buff_size;
}


// main function
int main(int argc, char const *argv[]) {
    int total_chars_read = 0;

    FILE *fp;

    // check to ensure an argument is provided
    if(argc != 2) {
        printf("Must provide a file path to read");
        return 1;
    }

    fp = fopen(argv[1], "r");
    
    chars_read = read_file(fp);
    total_chars_read += chars_read;
    while(1) {
        chars_read = read_file(fp);
        total_chars_read += chars_read;
        if(chars_read == -1)
            break;
        chars_read = read_file_small(fp);
        total_chars_read += chars_read;
        if(chars_read == -1)
            break;
    }

    printf("%d chars read", total_chars_read);

    return 0;
}
