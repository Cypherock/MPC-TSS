#include "network.h"
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include "config.h"
#include "memzero.h"
#include "mpc.h"
#include "mpc_helpers.h"
#include "mpc_utils.h"

int open_socket(const unsigned int port,
                struct sockaddr_in* address,
                int* server_fd) {
    int opt = 1;

    if ((*server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        fprintf(stderr, "Socket creation failed\n");
        return -1;
    }

    if (setsockopt(*server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        fprintf(stderr, "Setsockopt failed\n");
        return -1;
    }

    address->sin_family      = AF_INET;
    address->sin_addr.s_addr = INADDR_ANY;
    address->sin_port        = htons(port);

    if (bind(*server_fd, (struct sockaddr*)address, sizeof(*address)) < 0) {
        fprintf(stderr, "Bind failed\n");
        return -1;
    }

    if (listen(*server_fd, 3) < 0) {
        fprintf(stderr, "Listen failed\n");
        return -1;
    }

    return 0;
}

static MPC_STATUS sender(int server_fd, int* sock) {
    struct sockaddr_in client;
    socklen_t len = sizeof(struct sockaddr_in);

    if ((*sock = accept(server_fd, (struct sockaddr*)&client, &len)) < 0) {
        return MPC_OP_NET_FAILED_CONNECTION;
    }

    return MPC_OP_SUCCESS;
}

static MPC_STATUS receiver(int* sock, uint32_t port) {
    struct sockaddr_in server;
    int tries = 0;

    if ((*sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
        return MPC_OP_NET_SOCKET_FAIL;

    server.sin_family = AF_INET;
    server.sin_port   = htons(port);

    if (inet_pton(AF_INET, ADDR, &server.sin_addr) <= 0) {
        close(*sock);
        return MPC_OP_NET_INVALID_CONNECTION;
    }

    while (tries < TIMEOUT_TRIES) {
        if (connect(*sock, (struct sockaddr*)&server, sizeof(server)) < 0) {
            if (errno != ECONNREFUSED) {
                close(*sock);
                return MPC_OP_NET_INVALID_CONNECTION;
            }
        } else {
            break;
        }

        sleep(TIMEOUT_SEC);
        tries++;
    }

    if (tries == TIMEOUT_TRIES) {
        close(*sock);
        return MPC_OP_NET_CONNECTION_TIMEOUT;
    }

    return MPC_OP_SUCCESS;
}

MPC_STATUS broadcast_shares(bc_data shares,
                            bc_data_type shares_type,
                            size_t n_shares,
                            size_t n_parties,
                            int server_fd,
                            uint8_t party_id) {
    for (uint8_t i = 1; i <= n_shares; i++) {
        if (i == party_id) {
            bool connected[n_parties];
            memset(connected, 0, sizeof(connected));
            connected[party_id - 1] = 1;

            // n_parties - 1 connections in no order
            for (size_t j = 1; j < n_parties; j++) {
                MPC_STATUS status;
                int send_status;
                int sock;
                uint8_t id;

                if ((status = sender(server_fd, &sock)) != MPC_OP_SUCCESS) {
                    return status;
                }

                if (read(sock, &id, sizeof(id)) < 0) {
                    close(sock);
                    return MPC_OP_NET_READ_FAIL;
                }

                if (connected[id - 1]) {
                    close(sock);
                    return MPC_OP_NET_INVALID_CONNECTION;
                }

                connected[id - 1] = true;

                switch (shares_type) {
                    case BC_CURVE_POINTS:
                        send_status =
                            send(sock, &shares.points[party_id - 1],
                                 sizeof(shares.points[party_id - 1]), 0);
                        break;
                    case BC_BIGNUM:
                        send_status =
                            send(sock, &shares.nums[party_id - 1],
                                 sizeof(shares.nums[party_id - 1]), 0);
                        break;
                    case BC_BYTES:
                        send_status = send(sock, shares.bytes[party_id - 1],
                                           BC_BYTES_SIZE, 0);
                        break;
                        // unreachable
                    default: {
                    }
                }

                if (send_status < 0) {
                    close(sock);
                    return MPC_OP_NET_SEND_FAIL;
                }

                close(sock);
            }
        } else {
            MPC_STATUS status;
            int sock;

            if ((status = receiver(&sock, PORTS[i - 1])) != MPC_OP_SUCCESS)
                return status;

            if (send(sock, &party_id, sizeof(party_id), 0) < 0) {
                close(sock);
                return MPC_OP_NET_SEND_FAIL;
            }

            int read_status;

            switch (shares_type) {
                case BC_CURVE_POINTS:
                    read_status = read(sock, &shares.points[i - 1],
                                       sizeof(shares.points[i - 1]));
                    break;
                case BC_BIGNUM:
                    read_status = read(sock, &shares.nums[i - 1],
                                       sizeof(shares.nums[i - 1]));
                    break;
                case BC_BYTES:
                    read_status =
                        read(sock, shares.bytes[i - 1], BC_BYTES_SIZE);
                    break;
                    // unreachable
                default: {
                }
            }

            if (read_status < 0) {
                close(sock);
                return MPC_OP_NET_READ_FAIL;
            }

            close(sock);
        }
    }

    return MPC_OP_SUCCESS;
}

static MPC_STATUS dkg_verify_and_calculate(uint8_t party_id,
                                           size_t n_parties,
                                           size_t threshold,
                                           int server_fd,
                                           Polynomial* S,
                                           curve_point* Qi,
                                           curve_point* Q) {
    const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;
    curve_point Qj;

    curve_point shares[threshold + 1];
    const curve_point* points[threshold + 1];
    uint8_t xcords[threshold + 1];
    MPC_STATUS status;

    if (party_id <= threshold + 1)
        shares[party_id - 1] = *Qi;

    bc_data data;
    data.points = shares;

    if ((status = broadcast_shares(data, BC_CURVE_POINTS, threshold + 1,
                                   n_parties, server_fd, party_id)) !=
        MPC_OP_SUCCESS) {
        return status;
    };

    for (size_t i = 0; i < threshold + 1; i++) {
        points[i] = &shares[i];
        xcords[i] = i + 1;
    }

    lagarange_exp_interpolate(curve, points, xcords, party_id, threshold, &Qj);
    if (!point_is_equal(&Qj, Qi)) {
        return MPC_OP_CHECK_FAIL;
    }

    printf("(DKG) Verified share for party %u\n", party_id);

    if (Q != NULL) {
        lagarange_exp_interpolate(curve, points, xcords, 0, threshold, Q);
        printf("(DKG) Interpolated the public key\n");
    }

    return MPC_OP_SUCCESS;
}

MPC_STATUS dkg_private_share(uint8_t party_id,
                             size_t n_parties,
                             int server_fd,
                             Polynomial* S,
                             bignum256* Si) {
    const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;
    *Si                      = S->fx[party_id];

    for (size_t i = 1; i <= n_parties; i++) {
        if (i == party_id) {
            bool connected[n_parties];
            memset(connected, 0, sizeof(connected));
            connected[party_id - 1] = true;
            for (size_t j = 1; j < n_parties; j++) {
                int sock;
                uint8_t id;
                MPC_STATUS status;

                if ((status = sender(server_fd, &sock)) != MPC_OP_SUCCESS) {
                    return status;
                }

                if (read(sock, &id, sizeof(id)) < 0) {
                    close(sock);
                    return MPC_OP_INVALID_DATA;
                }

                if (connected[id - 1]) {
                    close(sock);
                    return MPC_OP_NET_INVALID_CONNECTION;
                }

                connected[id - 1] = true;

                if (send(sock, &S->fx[id], sizeof(S->fx[id]), 0) < 0) {
                    close(sock);
                    return MPC_OP_NET_SEND_FAIL;
                }

                close(sock);
            }
        } else {
            MPC_STATUS status;
            bignum256 eval;
            int sock;

            if ((status = receiver(&sock, PORTS[i - 1])) != MPC_OP_SUCCESS)
                return status;

            if (send(sock, &party_id, sizeof(party_id), 0) < 0) {
                close(sock);
                return MPC_OP_NET_SEND_FAIL;
            }

            if (read(sock, &eval, sizeof(eval)) < 0) {
                close(sock);
                return MPC_OP_NET_READ_FAIL;
            }

            bn_addmod(Si, &eval, &curve->order);

            close(sock);
        }
    }

    return MPC_OP_SUCCESS;
}

MPC_STATUS dkg(uint8_t party_id,
               size_t n_parties,
               size_t threshold,
               int server_fd,
               Polynomial* S,
               curve_point* point,
               curve_point* Q) {
    const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;
    MPC_STATUS status;
    curve_point Qi;
    bignum256 Si;

    if ((status = dkg_private_share(party_id, n_parties, server_fd, S, &Si)) !=
        MPC_OP_SUCCESS)
        return status;

    point_multiply(get_curve_by_name(CURVE_NAME)->params, &Si,
                   (point ? point : &curve->G), &Qi);
    printf("(DKG) Calculated public share\n");

    if ((status = dkg_verify_and_calculate(party_id, n_parties, threshold,
                                           server_fd, S, &Qi, Q)) !=
        MPC_OP_SUCCESS)
        return status;

    return MPC_OP_SUCCESS;
}

MPC_STATUS ot(mpc_party* party,
              bignum256* x,
              bignum256* y,
              bignum256* U,
              size_t n_parties) {
    const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;
    memzero(U, sizeof(*U));

    for (size_t i = 1; i <= n_parties; i++) {
        if (i == party->id) {
            bool connected[n_parties];
            memset(connected, 0, sizeof(connected));
            connected[party->id - 1] = true;
            for (size_t j = 1; j < n_parties; j++) {
                bignum256 Uij = {0};
                bignum256 m[OT_TERM_SIZE][2];
                curve_point B[OT_TERM_SIZE];
                int sock;
                uint8_t id;
                MPC_STATUS status;

                if ((status = sender(party->server_fd, &sock)) !=
                    MPC_OP_SUCCESS) {
                    return status;
                }

                if (read(sock, &id, sizeof(id)) < 0) {
                    close(sock);
                    return MPC_OP_NET_READ_FAIL;
                }

                if (connected[id - 1]) {
                    close(sock);
                    return MPC_OP_NET_INVALID_CONNECTION;
                }

                connected[id - 1] = true;

                if (send(sock, party->A, sizeof(party->A), 0) < 0) {
                    close(sock);
                    return MPC_OP_NET_SEND_FAIL;
                }

                if (read(sock, B, sizeof(B)) < 0) {
                    close(sock);
                    return MPC_OP_NET_READ_FAIL;
                }

                for (int i = OT_TERM_SIZE - 1; i >= 0; i--) {
                    bignum256 U_i;
                    uint8_t U_i_raw[32];
                    rand_bytes(U_i_raw, sizeof(U_i_raw));
                    bn_read_be(U_i_raw, &U_i);

                    bn_lshift(&Uij);                       // U <<= 1
                    bn_addmod(&Uij, &U_i, &curve->order);  // U += U_i

                    // m0
                    {
                        curve_point k0;
                        uint8_t k0_raw[32], k0_hash[32];

                        // Diffie Hellman
                        point_multiply(curve, &party->a[i], &B[i],
                                       &k0);  // k0 = a[i] . B[i] = (a * b) . B

                        bn_write_be(&k0.x, k0_raw);

                        sha256_Raw(k0_raw, 32, k0_hash);

                        bn_read_be(k0_hash, &k0.x);  // k0 = sha256(k0)

                        // simple otp encryption
                        bn_xor(&m[i][0], &k0.x, &U_i);  // m[0] = k0 ^ U_i
                    }

                    // m1
                    {
                        curve_point k1, tmp_A = party->A[i];
                        uint8_t k1_raw[32], k1_hash[32];

                        bn_cnegate(true, &tmp_A.y, &curve->prime);
                        point_add(curve, &tmp_A, &B[i]);  // B[i] = B[i] - A[i]

                        // Diffie Hellman
                        point_multiply(curve, &party->a[i], &B[i],
                                       &k1);  // k1 = a[i] . B[i]
                        bn_write_be(&k1.x, k1_raw);

                        sha256_Raw(k1_raw, 32, k1_hash);

                        bn_read_be(k1_hash, &k1.x);  // k1 = sha256(k1)
                        bn_addmod(&U_i, x, &curve->order);

                        // simple otp encryption
                        bn_xor(&m[i][1], &k1.x, &U_i);  // m[1] = k0 ^ U_i
                    }
                }

                if (send(sock, m, sizeof(m), 0) < 0) {
                    close(sock);
                    return MPC_OP_NET_SEND_FAIL;
                }

                bn_cnegate(true, &Uij, &curve->order);
                bn_addmod(U, &Uij, &curve->order);

                close(sock);
            }
        } else {
            const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;
            bignum256 Vij            = {0};
            bignum256 m[OT_TERM_SIZE][2];
            curve_point A[OT_TERM_SIZE];
            curve_point B[OT_TERM_SIZE];
            int sock;
            MPC_STATUS status;

            if ((status = receiver(&sock, PORTS[i - 1])) != MPC_OP_SUCCESS)
                return status;

            if (send(sock, &party->id, sizeof(party->id), 0) < 0) {
                close(sock);
                return MPC_OP_NET_SEND_FAIL;
            }

            if (read(sock, A, sizeof(A)) < 0) {
                close(sock);
                return MPC_OP_NET_READ_FAIL;
            }

            for (size_t i = 0; i < OT_TERM_SIZE; i++) {
                bool bit = bn_testbit(y, i);

                scalar_multiply(curve, &party->b[i], &B[i]);  // B[i] = b[i] . G

                if (bit) {
                    point_add(curve, &A[i], &B[i]);  // B[i] = B[i] + A[i]
                }
            }

            if (send(sock, B, sizeof(B), 0) < 0) {
                close(sock);
                return MPC_OP_NET_SEND_FAIL;
            }

            if (read(sock, m, sizeof(m)) < 0) {
                close(sock);
                return MPC_OP_NET_READ_FAIL;
            }

            for (int i = OT_TERM_SIZE - 1; i >= 0; i--) {
                bignum256 V_i;
                curve_point kr;
                uint8_t kr_raw[32], kr_hash[32];
                bool bit = bn_testbit(y, i);

                // Diffie Hellman

                point_multiply(curve, &party->b[i], &A[i],
                               &kr);  // kr = b[i] . A[i]
                bn_write_be(&kr.x, kr_raw);

                sha256_Raw(kr_raw, 32, kr_hash);

                bn_read_be(kr_hash, &kr.x);  // kr = sha256(kr)

                // simple otp encryption
                bn_xor(&V_i, &kr.x, &m[i][bit]);  // V_i = kr ^ m[bit]

                bn_lshift(&Vij);                       // V <<= 1
                bn_addmod(&Vij, &V_i, &curve->order);  // V += V_i
            }

            bn_addmod(U, &Vij, &curve->order);

            close(sock);
        }
    }
    return MPC_OP_SUCCESS;
}
