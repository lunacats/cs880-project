void *thread(void *vargp)
{
   StsHeader *handle = (StsHeader *)vargp;


   while ( StsQueue.pop(handle) != NULL) {
       char ptr[15];
       strcpy(ptr,"1111");
   }
   return NULL;
}

int main(int argc, char **argv) {

   StsHeader *handle = StsQueue.create();

   pthread_t thread1;
   pthread_create(&thread1, NULL, thread, handle);
   clock_t begin = clock();

   int size[] = {5};
   for (int i = 0; i <= 50000000; i++) {
       StsQueue.push(handle, &size[i]);
   }
  
   clock_t end = clock();
   double time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
   printf("Time Spent on program: %.4f\n",time_spent);

   pthread_join(thread1,NULL);
   StsQueue.destroy(handle);
   return 0;
}
