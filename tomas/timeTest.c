#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
   int size = 50000000;
   clock_t begin = clock();
   for(int i = 0; i < size; i++) {
       char arr[15];
       strcpy(arr,"1111");
   }
   clock_t end = clock();
   double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
   printf("Time Spent on program: %.4f\n",time_spent);
}
