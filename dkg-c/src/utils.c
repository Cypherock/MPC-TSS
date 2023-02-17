#include "utils.h"
#include <process.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "assert.h"
#include "bip39.h"

void printout_struct(void *invar, char *structname) {
  /* dumpstack(void) Got this routine from http://www.whitefang.com/unix/faq_toc.html
    ** Section 6.5. Modified to redirect to file to prevent clutter
    */
  /* This needs to be changed... */
  char dbx[160] = {0};

#ifdef _WIN32
  const char *prog_lname = strrchr(progname, '\\') + 1;
#elif UNIX
  const char *prog_lname = strrchr(progname, '/') + 1;
#endif

  FILE *gdbcmd = fopen("gdbcmds", "w+");
  fprintf(gdbcmd, "p (struct %s)*0x%p\n", structname, invar);
  fclose(gdbcmd);

  sprintf(dbx, "gdb -batch --command=gdbcmds %s %d > dump", prog_lname,
          getpid());
  system(dbx);

#ifdef _WIN32
  sprintf(dbx, "FINDSTR \"^\\$\" dump");
#elif UNIX
  sprintf(dbx, "cat dump | grep \"^\\$\" -a");
#endif
  system(dbx);

  return;
}

void print_hex_array(const char text[],
                     const uint8_t *arr,
                     const uint8_t length) {
  printf("%s %d\n\t", text, length);

  for (uint8_t i = 0U; i < length; i++) {
    printf("%02X ", arr[i]);
  }
  printf("\n");
}

void derive_hdnode_from_path(const uint32_t *path,
                             const size_t path_length,
                             const char *curve,
                             const uint8_t *entropy,
                             HDNode *hdnode) {
  uint8_t seed[64]      = {0};
  const char *mnemonics = mnemonic_from_data(entropy, 24);
  mnemonic_to_seed(mnemonics, "", seed, NULL);
  hdnode_from_seed(seed, 512 / 8, curve, hdnode);
  for (size_t i = 0; i < path_length; i++)
    hdnode_private_ckd(hdnode, path[i]);
  hdnode_fill_public_key(hdnode);
}

void raise_error(char *msg, int status) {
  printf("[%d] %s\n", status, msg);
  assert(false);
}