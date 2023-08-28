#ifndef MPC_H
#define MPC_H
#include <stdint.h>
#include "bip32.h"
#include "config.h"
#include "curves.h"
#include "ecdsa.h"

typedef struct Polynomial {
  bignum256 *a0;
  uint8_t coeff_count;
  uint8_t member_count;
#if USER_INPUT == 1
  bignum256 *coeff;   // = coeff_count
  curve_point *commit;  // = coeff_count
  bignum256 *fx;      // = members + 1
#else
  bignum256 coeff[THRESHOLD + 1];
  curve_point commit[THRESHOLD + 1];
  bignum256 fx[MEMBERS + 1];
#endif
} Polynomial;

typedef struct mpc_party {
  uint8_t id;
  char *name;
  uint8_t entropy[ENTROPY_SIZE];
  HDNode node;
  Polynomial fx;
  Polynomial fk;
  Polynomial fa;
  Polynomial fb;
  Polynomial fd;
  Polynomial fe;
  bignum256 xi;
  bignum256 ki;
  bignum256 ai;
  bignum256 bi;
  bignum256 ci;
  bignum256 di;
  bignum256 ei;
  bignum256 wi;
  bignum256 si;
  curve_point Wi;
  curve_point R;
  curve_point Yi;
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
  size_t msg_size;
  uint8_t *msg;
  bignum256 m;
  curve_point sum;
  bignum256 r;
  bignum256 s;
  bignum256 w;
  curve_point Y;
  curve_point R;
  curve_point W;
  uint8_t private[32];
  uint8_t public[65];
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

void init_polynomial(const uint8_t threshold,
                     const uint8_t members,
                     const bignum256 *a0,
                     const bool commit,
                     Polynomial *p);

MPC_STATUS mpc_init_group(mpc_group *group);

MPC_STATUS mpc_init_party(mpc_config *params,
                          mpc_party *party,
                          uint16_t id,
                          char *name);

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
MPC_STATUS mpc_group_presig(mpc_group *group);

MPC_STATUS mpc_group_generate_sig(mpc_group *group);

void private_to_public_key(const uint8_t *private, uint8_t *public_65);

void mpc_group_generate_shared_keypair(mpc_group *group);

void verify_k_r(mpc_group *group);

#endif