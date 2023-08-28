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
uint8_t msg[]  = {1, 2, 3, 4, 5};

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
    .member_name = names,
    .msg_size    = sizeof(msg),
    .msg         = msg
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

  bn_write_be(&group.mpc_parties[0].fx.fx[2], share);
  status = mpc_party_verify_commitments(&group.params, &group.mpc_parties[1],
                                        group.mpc_parties[0].fx.commit, share);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Commitment verification in %lums\n", uwTick - system_clock);
#endif

  if (status != MPC_OP_VALID_COMMITS)
    raise_error("MPC Commitment verification failed", status);

#if USE_FIRMWARE == 1
  system_clock = uwTick;
#endif
  status = mpc_group_presig(&group);
  verify_k_r(&group);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Presig evaluation in %lums\n", uwTick - system_clock);
#endif

  if (status != MPC_OP_SUCCESS)
    raise_error("MPC Presig evaluation failed", status);

#if USE_FIRMWARE == 1
  system_clock = uwTick;
#endif
  status = mpc_group_generate_sig(&group);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Signature generation in %lums\n", uwTick - system_clock);
#endif

  if (status != MPC_OP_SUCCESS)
    raise_error("MPC Signature generation failed", status);

#if USE_FIRMWARE == 1
  system_clock = uwTick;
#endif
  mpc_group_generate_shared_keypair(&group);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Shared key generation in %lums\n", uwTick - system_clock);
  system_clock = uwTick;
#endif
  uint8_t sig[64] = {0}, digest[32];
  bn_write_be(&group.r, sig);
  bn_write_be(&group.s, sig + 32);
  bn_write_be(&group.m, digest);
  if ((status = ecdsa_verify_digest(get_curve_by_name(CURVE_NAME)->params,
                                    group.public, sig, digest)) != 0)
    raise_error("MPC Signature did not match", status);

#if USER_INPUT == 1
  free(group.mpc_parties);
#endif

  return 0;
}