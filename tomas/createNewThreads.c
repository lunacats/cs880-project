#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

void *thread(void *vargp)
{
   char ptr[15];
   strcpy(ptr,"1111");
   return NULL;
}

int main(int argc, char **argv) {

   int size = 50000000;
   clock_t begin = clock();

   for(int i = 0; i < size; i++) {
       pthread_t thread_id;
       pthread_create(&thread_id, NULL, thread, NULL);
   }

   clock_t end = clock();
   double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
   printf("Time Spent on program: %.4f\n",time_spent);
}
