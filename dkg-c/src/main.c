#include <stdlib.h>
#include "mpc.h"
#include "mpc_utils.h"
#include "names.h"
#if USE_FIRMWARE == 0
#include <stdio.h>
#include <string.h>
#else
#include "logger.h"
#include "stm32l4xx_hal.h"
#endif

char *progname = NULL;

#if USE_FIRMWARE == 0
int main(int argc, char **argv) {
  progname = argv[0];
#else
void mpc_main() {
  uint32_t system_clock;
#endif
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

#if USE_FIRMWARE == 1
  system_clock = uwTick;
#endif
  status = mpc_init_group(&group);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Initialization in %lums\n", uwTick - system_clock);
#endif

  if (status != MPC_OP_SUCCESS)
    raise_error("MPC Initialization failed", status);

#if USE_FIRMWARE == 1
  system_clock = uwTick;
#endif
  status =
      mpc_party_evaluate_poly(&group.params, &group.mpc_parties[0], 2, share);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Polynomial evaluation in %lums\n", uwTick - system_clock);
#endif

  if (status != MPC_OP_SUCCESS)
    raise_error("MPC Polynomial evaluation failed", status);

#if USE_FIRMWARE == 1
  system_clock = uwTick;
#endif
  mpc_group_generate_shared_keypair(&group);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Shared key generation in %lums\n", uwTick - system_clock);
  system_clock = uwTick;
#endif
  status = mpc_party_verify_commitments(&group.params, &group.mpc_parties[1],
                                        group.mpc_parties->commitments, share);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Commitment verification in %lums\n", uwTick - system_clock);
#endif

  if (status != MPC_OP_VALID_COMMITS)
    raise_error("MPC Commitment verification failed", status);

#if USER_INPUT == 1
  free(group.mpc_parties);
#endif

  return 0;
}