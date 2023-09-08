#ifndef MPC_UTILS_H
#define MPC_UTILS_H
#include <stdint.h>
#include "config.h"
#if USE_FIRMWARE == 0
#include <stdio.h>
#include "bip32.h"

#define print_array(arr, size, ...)              \
  {                                              \
    snprintf(title, sizeof(title), __VA_ARGS__); \
    print_hex_array(title, arr, size);           \
  }

extern char *progname;
extern char title[100];

void rand_bytes(uint8_t* bytes, size_t n);
void print_hex_array(const char *text,
                     const uint8_t *arr,
                     const uint8_t length);

void gen_hdnode(const char *curve, const uint8_t *entropy, HDNode *hdnode);
#endif

void raise_error(char *msg, int status);

#endif
