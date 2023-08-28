#include "mpc_utils.h"
#include <stdio.h>
#include <assert.h>
#include <stdbool.h>
#if USE_FIRMWARE == 0
#include "bip39.h"
#include <process.h>
#include <stdlib.h>
#include <string.h>

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
#endif

void raise_error(char *msg, int status) {
  printf("[%d] %s\n", status, msg);
  assert(false);
}