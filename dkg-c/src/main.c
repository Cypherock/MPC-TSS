#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mpc.h"
#include "names.h"
#include "utils.h"

char *progname = NULL;

int main(int argc, char **argv) {
  progname        = argv[0];
  mpc_group group = {
    .params.member_count = MEMBERS,
    .params.threshold    = THRESHOLD,
#if USER_INPUT == 1
    .mpc_parties = NULL,
#endif
    .member_name = names
  };

#if USER_INPUT == 1
  printf("Input total members of MPC group\n");
  scanf("%hu", &group.params.member_count);

  if (group.params.member_count < MIN_MEMBERS) {
    printf("Minimum parties involved must  or more");
    return 1;
  }

  printf("Input threshold for the MPC group\n");
  scanf("%hu", &group.params.threshold);

  if (group.params.threshold == 0 ||
      group.params.threshold > group.params.member_count) {
    printf(
        "Invalid threshold. Should not be 0 and cannot be more than total "
        "members.");
    return 1;
  }
#endif

  uint8_t share[64] = {0};
  MPC_STATUS status = MPC_OP_SUCCESS;

  status = mpc_init_group(&group);

  if (status != MPC_OP_SUCCESS)
    raise_error("MPC Initialization failed", status);

  status =
      mpc_party_evaluate_poly(&group.params, &group.mpc_parties[0], 2, share);

  if (status != MPC_OP_SUCCESS)
    raise_error("MPC Polynomial evaluation failed", status);

  mpc_group_generate_shared_keypair(&group);
  status = mpc_party_verify_commitments(&group.params, &group.mpc_parties[1],
                                        group.mpc_parties->commitments, share);

  if (status != MPC_OP_VALID_COMMITS)
    raise_error("MPC Commitment verification failed", status);

#if USER_INPUT == 1
  free(group.mpc_parties);
#endif

  return 0;
}