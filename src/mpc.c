#include "mpc.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include "bignum.h"
#include "bip32.h"
#include "config.h"
#include "ecdsa.h"
#include "hasher.h"
#include "memzero.h"
#include "mpc_helpers.h"
#include "mpc_utils.h"
#include "network.h"
#include "rand.h"
#include "sha2.h"
#if USE_FIRMWARE == 1
#include "coin_utils.h"
#include "utils.h"
#include "wallet.h"
#endif

#define HARDENED(i) (i | (1 << 31))

void init_polynomial(const uint8_t coeff_count,
                     const bignum256* coeff,
                     const bignum256* a0,
                     const uint8_t members,
                     Polynomial* p) {
    const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;

    p->coeff_count  = coeff_count;
    p->member_count = members;
#if USER_INPUT == 1
    p->coeff = malloc(sizeof(bignum256) * p->coeff_count);
    p->fx    = malloc(sizeof(bignum256) * (members + 1));
#endif
    p->a0 = p->coeff;
    memzero(p->coeff, sizeof(bignum256) * p->coeff_count);
    memzero(p->fx, sizeof(bignum256) * (members + 1));

    if (coeff != NULL) {
        for (size_t i = 0; i < p->coeff_count; i++)
            p->coeff[i] = coeff[i];
    } else {
        gen_polynomial_coeff(p->coeff_count, curve, p->coeff);
    }

    if (a0 != NULL)
        memcpy(p->a0, a0, sizeof(bignum256));

#if USE_FIRMWARE == 1
    uint32_t system_clock = uwTick;
#endif
    for (int i = 0; i <= members; i++) {
        bignum256 x;
        bn_read_uint32(i, &x);
        evaluate_polynomial(curve, p->coeff, coeff_count - 1, &x, &p->fx[i]);
    }
#if USE_FIRMWARE == 1
    LOG_CRITICAL("MPC Polynomial (%lu) evaluation in %lums\n", threshold,
                 uwTick - system_clock);
#endif
}

MPC_STATUS mpc_init_party(mpc_party* party, uint16_t id, char* name) {
    if (party == NULL || name == NULL)
        return MPC_OP_WRONG_PARAM;

#if USER_INPUT == 1
    size_t coeffient_storage_size = coeff_count * sizeof(bignum256);
    coeff_array                   = (bignum256*)malloc(coeffient_storage_size);
#endif
    party->id   = id;
    party->name = name;
    party->port = PORTS[party->id - 1];

    rand_bytes(party->entropy, sizeof(party->entropy));

    return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_dkg_extension(mpc_party* party) {
    Polynomial fp, fq;
    curve_point Q;

    // initialing the polynomials
    uint8_t coeff_count = THRESHOLD + 1;
    bignum256 coeff[coeff_count];
    HDNode account_nodes[coeff_count];
    HDNode master;
    MPC_STATUS status;

    gen_hdnode(CURVE_NAME, party->entropy, &master);

    for (size_t i = 0; i < coeff_count; i++) {
        // account node
        // m/i'/0'/0'/0'
        const uint32_t DERIVATION[] = {HARDENED(i), HARDENED(0), HARDENED(0),
                                       HARDENED(0)};
        account_nodes[i]            = master;

        for (size_t j = 0; j < sizeof(DERIVATION) / sizeof(uint32_t); j++)
            hdnode_private_ckd(&account_nodes[i], DERIVATION[j]);

        bn_read_be(account_nodes[i].private_key, &coeff[i]);
    }

    // account node
    init_polynomial(coeff_count, coeff, NULL, N_PARTIES, &fp);

    printf("Initialised polynomial for first group public key P\n");

    for (size_t i = 0; i < coeff_count; i++) {
        HDNode change_node = account_nodes[i];
        // m/i'/0'/0'/0'/0
        hdnode_private_ckd(&change_node, 0);
        hdnode_fill_public_key(&change_node);
        bn_read_be(change_node.private_key, &coeff[i]);
    }

    // change node
    init_polynomial(coeff_count, coeff, NULL, N_PARTIES, &fq);

    printf("Initialised polynomial for first second group public key Q\n");

    // exchange evaluations of these polynomials
    printf(
        "\n--------------\n"
        "DKG for account node level public key (m/i'/0'/0'/0')\n"
        "--------------\n");
    if ((status = dkg(party->id, N_PARTIES, THRESHOLD, party->server_fd, &fp,
                      NULL, NULL) != MPC_OP_SUCCESS))
        return status;

    printf(
        "\n--------------\n"
        "DKG for change node level public key (m/i'/0'/0'/0'/0)\n"
        "--------------\n");
    if ((status = dkg(party->id, N_PARTIES, THRESHOLD, party->server_fd, &fq,
                      NULL, &Q) != MPC_OP_SUCCESS))
        return status;

    printf(
        "\n--------------\n"
        "Change node level public key verification\n"
        "--------------\n");
    // verification
    {
        const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;
        curve_point Q_           = {0};
        uint8_t public_keys[N_PARTIES][BC_BYTES_SIZE];
        uint8_t chain_code[N_PARTIES][BC_BYTES_SIZE];

        hdnode_fill_public_key(&account_nodes[0]);
        memcpy(&public_keys[party->id - 1], account_nodes[0].public_key, 33);
        memcpy(&chain_code[party->id - 1], account_nodes[0].chain_code, 32);

        bc_data data;

        printf("\nBroadcasting account node level public keys\n");
        data.bytes = &public_keys[0];
        if ((status = broadcast_shares(data, BC_BYTES, N_PARTIES, N_PARTIES,
                                       party->server_fd, party->id)) !=
            MPC_OP_SUCCESS)
            return status;
        printf("Broadcasted public keys successfully\n");

        printf("\nBroadcasting account node level chain codes\n");
        data.bytes = &chain_code[0];
        if ((status = broadcast_shares(data, BC_BYTES, N_PARTIES, N_PARTIES,
                                       party->server_fd, party->id)) !=
            MPC_OP_SUCCESS)
            return status;
        printf("Broadcasted chain codes successfully\n");

        printf("\nPerforming EC addition on derived individual public keys\n");
        for (size_t i = 0; i < N_PARTIES; i++) {
            HDNode account_node;
            curve_point Qi_;
            hdnode_from_xpub(4, HARDENED(0), chain_code[i], public_keys[i],
                             CURVE_NAME, &account_node);
            hdnode_public_ckd(&account_node, 0);
            ecdsa_read_pubkey(curve, account_node.public_key, &Qi_);
            point_add(curve, &Qi_, &Q_);
        }

        if (!point_is_equal(&Q_, &Q))
            return MPC_OP_CHECK_FAIL;

        printf("Change node level public key Q verified successfully\n");
    }

    printf("Creating private key for party %u at m/0'/0'/0'/0'/0/0\n",
           party->id);
    hdnode_private_ckd(&account_nodes[0], 0);
    memcpy(party->private_key, account_nodes[0].private_key, 32);

    return MPC_OP_SUCCESS;
}

static void mpc_parties_ot_init(mpc_party* party) {
    uint8_t bn_raw[32] = {0};

    for (size_t i = 0; i < OT_TERM_SIZE; i++) {
        const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;

        // a generation
        rand_bytes(bn_raw, sizeof(bn_raw));
        bn_read_be(bn_raw, &party->a[i]);

        // A generation
        point_multiply(curve, &party->a[i], &curve->G, &party->A[i]);

        // b generation
        rand_bytes(bn_raw, sizeof(bn_raw));
        bn_read_be(bn_raw, &party->b[i]);
    }
}

MPC_STATUS mpc_signature_phase(mpc_party* party) {
    const ecdsa_curve* curve = get_curve_by_name(CURVE_NAME)->params;
    size_t threshold         = THRESHOLD;
    size_t coeff_count       = threshold + 1;
    size_t n_parties         = threshold + 1;
    bignum256 zero           = {0};
    Polynomial K, A, D, E;
    curve_point R, W;
    bignum256 s;
    bignum256 w, vi;
    bignum256 lagrange_si;
    MPC_STATUS status;

    init_polynomial(coeff_count, NULL, NULL, n_parties, &K);
    init_polynomial(coeff_count, NULL, NULL, n_parties, &A);
    init_polynomial(coeff_count, NULL, &zero, n_parties, &D);
    init_polynomial(coeff_count, NULL, &zero, n_parties, &E);
    printf("Initialised polynomials K, A, D and E for signature phase\n");

    printf(
        "\n--------------\n"
        "DKG for generating R from polynomial K\n"
        "--------------\n");
    if ((status = dkg(party->id, n_parties, threshold, party->server_fd, &K,
                      NULL, &R)) != MPC_OP_SUCCESS)
        return status;
    printf("R generated successfully\n");

    printf(
        "\n--------------\n"
        "DKG for generating authenticator W from polynomial A and point R\n"
        "--------------\n");
    if ((status = dkg(party->id, n_parties, threshold, party->server_fd, &A, &R,
                      &W)) != MPC_OP_SUCCESS)
        return status;
    printf("W generated successfully\n");

    mpc_parties_ot_init(party);
    printf("\nPre calculations done for upcoming OTs\n");

    {
        bignum256 Ui;
        bignum256 shares[n_parties];
        bignum256 tmp_a0;
        curve_point W_;
        bc_data data;

        memzero(&w, sizeof(w));

        printf(
            "\n--------------\n"
            "Correlated oblivious transfers between parties for "
            "multiplication between polynomials A and K\n"
            "--------------\n");
        if ((status = ot(party, A.a0, K.a0, &Ui, n_parties)) != MPC_OP_SUCCESS)
            return status;
        printf("Oblivious transfers successfully completed\n");

        tmp_a0 = *A.a0;
        bn_multiply(K.a0, &tmp_a0, &curve->order);

        bn_addmod(&Ui, &tmp_a0, &curve->order);

        shares[party->id - 1] = Ui;
        data.nums             = shares;

        printf("\nBroadcasting individual shares from previous OTs\n");
        if ((status = broadcast_shares(data, BC_BIGNUM, n_parties, n_parties,
                                       party->server_fd, party->id)) !=
            MPC_OP_SUCCESS)
            return status;
        printf("Shares broadcasted successfully\n");

        printf("Adding up all the shares\n");

        for (size_t i = 0; i < n_parties; i++)
            bn_addmod(&w, &shares[i], &curve->order);

        printf("Successfully calculated w\n");

        scalar_multiply(curve, &w, &W_);

        printf(
            "\n--------------\n"
            "Authenticator (W) verification\n"
            "--------------\n");
        if (!point_is_equal(&W, &W_))
            return MPC_OP_CHECK_FAIL;
        printf("Authenticator verified successfully\n");

        bn_inverse(&w, &curve->order);  // w = w^-1
    }

    {
        bignum256 k_share = *A.a0;
        bignum256 lagrange_term;
        bignum256 private_key;

        bn_multiply(&w, &k_share, &curve->order);

        bn_read_be(party->private_key, &private_key);

        evaluate_lagarange_term(curve, &private_key, party->id, 0, threshold,
                                &lagrange_term);

        printf(
            "\n--------------\n"
            "Correlated oblivious transfers between parties for "
            "multiplication between sharing of K^-1 and group private key\n"
            "--------------\n");
        if ((status = ot(party, &k_share, &lagrange_term, &vi, n_parties)) !=
            MPC_OP_SUCCESS)
            return status;
        printf("Oblivious transfers successfully completed\n");

        bn_multiply(&lagrange_term, &k_share, &curve->order);
        bn_addmod(&vi, &k_share, &curve->order);
        bn_multiply(&R.x, &vi, &curve->order);

        printf("v_i calculated successfully from the OT shares\n");
    }

    {
        bignum256 si;
        bignum256 hash;
        bignum256 Di, Ei;
        uint8_t hash_raw[SHA256_BLOCK_LENGTH];

        printf(
            "\n--------------\n"
            "Calculating D_i, E_i, A_i, Hash(M) and subsequently the lagrange "
            "term for s_i\n"
            "--------------\n");
        hasher_Raw(HASHER_SHA2D, MESSAGE, sizeof(MESSAGE), hash_raw);
        bn_read_be(hash_raw, &hash);

        if ((status = dkg_private_share(party->id, n_parties, party->server_fd,
                                        &A, &si)) != MPC_OP_SUCCESS)
            return status;

        bn_multiply(&w, &si, &curve->order);
        bn_multiply(&hash, &si, &curve->order);

        if ((status = dkg_private_share(party->id, n_parties, party->server_fd,
                                        &D, &Di)) != MPC_OP_SUCCESS)
            return status;

        bn_multiply(&hash, &Di, &curve->order);
        bn_addmod(&si, &Di, &curve->order);

        if ((status = dkg_private_share(party->id, n_parties, party->server_fd,
                                        &E, &Ei)) != MPC_OP_SUCCESS)
            return status;

        bn_addmod(&si, &Ei, &curve->order);

        evaluate_lagarange_term(curve, &si, party->id, 0, threshold,
                                &lagrange_si);
        printf("Lagrange term for s_i calculated successfully\n");
    }

    {
        bignum256 shares[n_parties];
        bc_data data;

        bn_addmod(&vi, &lagrange_si, &curve->order);

        shares[party->id - 1] = vi;

        data.nums = shares;

        printf("\nBroadcasting vi * r + lagrange_si\n");
        if ((status = broadcast_shares(data, BC_BIGNUM, n_parties, n_parties,
                                       party->server_fd, party->id)) !=
            MPC_OP_SUCCESS)
            return status;
        printf("Broadcasted successfully\n");

        memzero(&s, sizeof(s));
        for (size_t i = 0; i < n_parties; i++)
            bn_addmod(&s, &shares[i], &curve->order);
        printf("Calculated s successfully from the above shares\n");
    }

    printf("\n");
    printf("Signature (r): ");
    bn_print(&R.x);
    printf("\n");

    printf("Signature (s): ");
    bn_print(&s);
    printf("\n");

    return MPC_OP_SUCCESS;
}
