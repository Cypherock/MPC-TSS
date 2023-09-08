#ifndef CONFIG_H
#define CONFIG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "curves.h"
#include "hasher.h"

#define MAX_N_PARTIES 100
#define MIN_N_PARTIES 3
#define N_PARTIES 5
#define THRESHOLD 2
#define ENTROPY_SIZE 32
#define OT_TERM_SIZE 256
#define ADDR "127.0.0.1"

#define TIMEOUT_SEC 2
#define TIMEOUT_TRIES 6

static const char* CURVE_NAME          = SECP256K1_NAME;
static const uint8_t MESSAGE[]         = {0x01, 0x04, 0x01, 0x00, 0x06};
static const uint32_t PORTS[N_PARTIES] = {8881, 8882, 8883, 8884, 8885};

// IDs of parties that will be used in threshold operations
static const uint8_t THRESHOLD_PARTIES[THRESHOLD + 1] = {2, 3, 4};

#endif
