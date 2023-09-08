#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bip32.h"
#include "config.h"
#include "ecdsa.h"
#include "hasher.h"
#include "mpc.h"
#include "mpc_helpers.h"
#include "mpc_utils.h"
#include "names.h"
#include "network.h"

static void valid_parties() {
    fprintf(stderr, "Possible <id> values:\n");
    for (size_t i = 0; i < N_PARTIES; i++) {
        fprintf(stderr, "%lu\n", i + 1);
    }
};

int main(int argc, char** argv) {
    MPC_STATUS status = MPC_OP_SUCCESS;

    mpc_party party;

    if (argc != 2) {
        fprintf(stderr, "format: %s <id>\n", argv[0]);
        valid_parties();
        exit(EXIT_FAILURE);
    };

    uint8_t party_id = atoi(argv[1]);

    if (party_id == 0 || party_id > N_PARTIES) {
        valid_parties();
        exit(EXIT_FAILURE);
    }

    status = mpc_init_party(&party, party_id,
                            names[(party_id - 1) % NAME_LIST_SIZE]);

    if (status != MPC_OP_SUCCESS)
        raise_error("MPC party initialization failed", status);

    printf("Initialised party %u\n", party.id);

    if (open_socket(party.port, &party.address, &party.server_fd) < 0) {
        fprintf(stderr, "Failed to open socket at %u", party.port);
        exit(EXIT_FAILURE);
    }

    printf("Opened socket at %u\n", party.port);

    printf(
        "\n=============\n"
        "DKG EXTENSION\n"
        "=============\n\n");

    status = mpc_dkg_extension(&party);

    if (status != MPC_OP_SUCCESS)
        raise_error("MPC DKG Extension failed", status);

    if (party.id > THRESHOLD + 1) {
        printf(
            "\nParties from 1 to t + 1 inclusive will take part in the "
            "signature phase\n");
        return 0;
    }

    printf(
        "\n=============\n"
        "SIGNATURE PHASE\n"
        "=============\n\n");

    status = mpc_signature_phase(&party);

    if (status != MPC_OP_SUCCESS)
        raise_error("MPC Signature phase failed", status);

    return 0;
}
