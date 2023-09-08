#ifndef MPC_H
#define MPC_H
#include <arpa/inet.h>
#include <stdint.h>
#include "bip32.h"
#include "config.h"
#include "curves.h"
#include "ecdsa.h"

typedef struct Polynomial {
    bignum256* a0;
    uint8_t coeff_count;
    uint8_t member_count;
    bignum256 coeff[THRESHOLD + 1];
    bignum256 fx[N_PARTIES + 1];
} Polynomial;

typedef struct mpc_party {
    uint8_t id;
    char* name;
    uint8_t entropy[ENTROPY_SIZE];
    uint8_t private_key[32];

    // ot pre calculated
    bignum256 a[OT_TERM_SIZE];
    bignum256 b[OT_TERM_SIZE];
    curve_point A[OT_TERM_SIZE];

    bignum256 vi;
    bignum256 si;
    curve_point ri;

    // socket stuff
    uint32_t port;
    struct sockaddr_in address;
    int server_fd;
} mpc_party;

typedef enum MPC_STATUS {
    MPC_OP_SUCCESS                = 0,
    MPC_OP_NET_INVALID_CONNECTION = 1,
    MPC_OP_NET_FAILED_CONNECTION  = 2,
    MPC_OP_NET_CONNECTION_TIMEOUT = 3,
    MPC_OP_NET_SEND_FAIL          = 4,
    MPC_OP_NET_READ_FAIL          = 5,
    MPC_OP_NET_SOCKET_FAIL        = 6,
    MPC_OP_WRONG_PARAM            = 7,
    MPC_OP_MEM_FAIL               = 8,
    MPC_OP_INVALID_DATA           = 9,
    MPC_OP_CHECK_FAIL             = 10,
    MPC_OP_OVERFLOW               = 11,
} MPC_STATUS;

void init_polynomial(const uint8_t coeff_count,
                     const bignum256* coeff,
                     const bignum256* a0,
                     const uint8_t members,
                     Polynomial* p);

MPC_STATUS mpc_init_party(mpc_party* party, uint16_t id, char* name);

MPC_STATUS mpc_dkg_extension(mpc_party* party);

MPC_STATUS mpc_signature_phase(mpc_party* party);

#endif
