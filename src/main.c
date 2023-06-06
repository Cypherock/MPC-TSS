#include "ot.h"
#include <stdio.h>

int main() {
  printf("Oblivious Transfer POC:\n");
  printf("-----------------------\n");
  printf("For c = 0\n");
  ot_poc(0);
  printf("-----------------------\n");
  printf("For c = 1\n");
  ot_poc(1);
  printf("-----------------------\n");
}
