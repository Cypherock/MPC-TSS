#ifndef NETWORK_H
#define NETWORK_H

#include <arpa/inet.h>
#include <stddef.h>
#include <stdio.h>
#include "ecdsa.h"
#include "mpc.h"

#define BC_BYTES_SIZE 64

typedef union bc_data {
    curve_point* points;
    bignum256* nums;
    uint8_t (*bytes)[BC_BYTES_SIZE];
} bc_data;

typedef enum bc_data_type {
    BC_CURVE_POINTS,
    BC_BIGNUM,
    BC_BYTES,
} bc_data_type;

int open_socket(const unsigned int port,
                struct sockaddr_in* address,
                int* server_fd);

MPC_STATUS broadcast_shares(bc_data shares,
                            bc_data_type shares_type,
                            size_t n_shares,
                            size_t n_parties,
                            int server_fd,
                            uint8_t party_id);

MPC_STATUS dkg_private_share(uint8_t party_id,
                             size_t n_parties,
                             int server_fd,
                             Polynomial* S,
                             bignum256* Si);

MPC_STATUS dkg(uint8_t party_id,
               size_t n_parties,
               size_t threshold,
               int server_fd,
               Polynomial* S,
               curve_point* point,
               curve_point* Q);

MPC_STATUS ot(mpc_party* party,
              bignum256* x,
              bignum256* y,
              bignum256* U,
              size_t n_parties);

#endif
