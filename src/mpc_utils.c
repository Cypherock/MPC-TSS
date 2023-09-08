#include "mpc_utils.h"
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/time.h>
#include <stdlib.h>
#include <string.h>
#include "bip39.h"

inline static void seed_prng() {
    struct timeval time;
    gettimeofday(&time, NULL);

    srand(time.tv_sec + time.tv_usec * 1000000ul);
}

void rand_bytes(uint8_t* bytes, size_t n) {
    size_t i;

    seed_prng();

    for (i = 0; i < n; i++) {
        bytes[i] = rand();
    }
}

void print_hex_array(const char text[],
                     const uint8_t* arr,
                     const uint8_t length) {
    printf("%s %d\n", text, length);

    for (uint8_t i = 0U; i < length; i++) {
        printf("%02X ", arr[i]);
    }
    printf("\n");
}

void gen_hdnode(const char* curve, const uint8_t* entropy, HDNode* hdnode) {
    uint8_t seed[64]      = {0};
    const char* mnemonics = mnemonic_from_data(entropy, 24);
    mnemonic_to_seed(mnemonics, "", seed, NULL);
    hdnode_from_seed(seed, 512 / 8, curve, hdnode);
    hdnode_fill_public_key(hdnode);
}

void raise_error(char* msg, int status) {
    printf("[%d] %s\n", status, msg);
    exit(EXIT_FAILURE);
}
