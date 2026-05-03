
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int ct, nf;
int 
main(int argc, char* argv[]) {
   long n = 10000;
   if (argc > 1)
      n = strtol(argv[1], 0, 10);

   int sleeptime = 0;

   const char* stime;
   if ((stime = getenv("SLEEPTIME")))
      sscanf(stime, "%d", &sleeptime);
   if (sleeptime > 0)
      fprintf(stderr, "SLEEPTIME=%d microseconds\n", sleeptime);

   char *args[100];
   for (unsigned j=0; j < 99; j++) {
      args[j] = malloc(256);
      for (unsigned k=0; k < 255; k++)
         args[j][k] = ' ' + (k % 64);
      args[j][255] = '\0';
   }
   args[99] = 0;

   char cmd[100];
   for (int i=0; i < n; i++) {
      sprintf(cmd, "/usr/bin/true_%d_", i);
      if (execv(cmd, args) > 0)
         nf++;
      else if (n < 10)
         perror("execve failed");
      ct++;
      if (sleeptime > 0)
         usleep(sleeptime);
   }

   fprintf(stderr, "execl launched %d times, succeeded %d times\n", ct, nf);
}

