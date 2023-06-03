// Simple grep.  Only supports ^ . * $ operators.
#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"

int
main(int argc, char *argv[])
{
  char *pattern;

  if(argc <= 1){
    fprintf(2, "usage: sleep [int]\n");
    exit(1);
  }
  pattern = argv[1];


  sleep(atoi(pattern));

  exit(0);
}
