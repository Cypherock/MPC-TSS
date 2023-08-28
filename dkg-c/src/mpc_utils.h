#ifndef UTILS_H
#define UTILS_H
#include <stdint.h>
#include "config.h"
#if USE_FIRMWARE == 0
#include "bip32.h"

#define print_array(arr, size, ...)              \
  {                                              \
    snprintf(title, sizeof(title), __VA_ARGS__); \
    print_hex_array(title, arr, size);           \
  }

extern char *progname;
extern char title[100];

void print_hex_array(const char *text,
                     const uint8_t *arr,
                     const uint8_t length);

void printout_struct(void *invar, char *structname);

void derive_hdnode_from_path(const uint32_t *path,
                             const size_t path_length,
                             const char *curve,
                             const uint8_t *entropy,
                             HDNode *hdnode);
#endif

void raise_error(char *msg, int status);

#endif