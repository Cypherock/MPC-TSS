#ifndef MPC_H
#define MPC_H
#include <stdint.h>
#include "bip32.h"
#include "config.h"
#include "curves.h"
#include "ecdsa.h"

typedef struct mpc_party {
  uint8_t id;
  char *name;
  uint8_t entropy[ENTROPY_SIZE];
  HDNode node;
#if USER_INPUT == 1
  uint8_t (*polynomial)[32];
  curve_point *commitments;
#else
  uint8_t polynomial[THRESHOLD][32];
  curve_point commitments[THRESHOLD + 1];
#endif
} mpc_party;

typedef struct mpc_config {
  uint8_t member_count;
  uint8_t threshold;
} mpc_config;

typedef struct mpc_group {
  char **member_name;
#if USER_INPUT == 1
  mpc_party *mpc_parties;
#else
  mpc_party mpc_parties[MEMBERS];
#endif
  mpc_config params;
} mpc_group;

typedef enum MPC_STATUS {
  MPC_OP_SUCCESS         = 0,
  MPC_OP_WRONG_PARAM     = 1,
  MPC_OP_MEM_FAIL        = 2,
  MPC_OP_INVALID_DATA    = 3,
  MPC_OP_VALID_COMMITS   = 4,
  MPC_OP_INVALID_COMMITS = 5,
  MPC_OP_OVERFLOW        = 6,
} MPC_STATUS;

#if USE_FIRMWARE == 1
void mpc_main();
#endif

MPC_STATUS mpc_init_group(mpc_group *group);

MPC_STATUS mpc_init_party(mpc_config *params,
                          mpc_party *party,
                          uint16_t id,
                          char *name);

MPC_STATUS mpc_party_gen_polynomial(mpc_config *params, mpc_party *party);

MPC_STATUS mpc_party_calculate_commitments(mpc_config *params,
                                           mpc_party *party);

MPC_STATUS mpc_party_evaluate_poly(mpc_config *params,
                                   mpc_party *party,
                                   uint16_t share_index,
                                   uint8_t *share);

MPC_STATUS mpc_party_verify_commitments(mpc_config *params,
                                        mpc_party *self,
                                        curve_point *coeff_commits,
                                        uint8_t *share);

void private_to_public_key(const uint8_t *private, uint8_t *public_65);

void mpc_group_generate_shared_keypair(mpc_group *group);

#endif