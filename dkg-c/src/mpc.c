#include "mpc.h"
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto_random.h"
#include "memzero.h"
#include "utils.h"

char title[100]             = "";
const uint32_t DERVN_PATH[] = {100, 100};

MPC_STATUS mpc_init_group(mpc_group *group) {
  if (group == NULL)
    return MPC_OP_WRONG_PARAM;

  MPC_STATUS status;

  srand(time(NULL));
#if USER_INPUT == 1
  group->mpc_parties =
      (mpc_party *)malloc(group->member_count * sizeof(mpc_party));

  if (group->mpc_parties == NULL)
    return MPC_OP_MEM_FAIL;
#endif

  memzero(group->mpc_parties, group->params.member_count * sizeof(mpc_party));

  for (int index = 0; index < group->params.member_count; index++) {
    mpc_party *party = &group->mpc_parties[index];
    if ((status = mpc_init_party(&group->params, party, index + 1,
                                 group->member_name[index])) != MPC_OP_SUCCESS)
      return status;
    if ((status = mpc_party_calculate_commitments(&group->params, party)) !=
        MPC_OP_SUCCESS)
      return status;

#if USER_INPUT == 1
#if VERBOSE == 1
    printout_struct(party, "mpc_party");
    printf("\n");
#endif
#endif
  }

#if VERBOSE == 1
  printout_struct(group, "mpc_group");
  printf("\n");
#endif

  return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_init_party(mpc_config *params,
                          mpc_party *party,
                          uint16_t id,
                          char *name) {
  if (party == NULL || name == NULL)
    return MPC_OP_WRONG_PARAM;

  party->id   = id;
  party->name = name;
  // TODO: use good source for randomness
  if (!crypto_random_generate(party->entropy, sizeof(party->entropy)))
    return MPC_OP_INVALID_DATA;
  derive_hdnode_from_path(DERVN_PATH, sizeof(DERVN_PATH) / sizeof(uint32_t),
                          CURVE_NAME, party->entropy, &party->node);
  return mpc_party_gen_polynomial(params, party);
}

MPC_STATUS mpc_party_gen_polynomial(mpc_config *params, mpc_party *party) {
  if (params == NULL || party == NULL)
    return MPC_OP_WRONG_PARAM;

  bignum256 coefficient = {0};
#if USER_INPUT == 1
  size_t coeffient_storage_size =
      params->threshold * sizeof(party->polynomial[0]);

  party->polynomial = (uint8_t(*)[32])malloc(coeffient_storage_size);
#endif

  for (int i = 0; i < params->threshold;) {
    memset(&coefficient, 0, sizeof(coefficient));

    /// create a valid coefficient in Fq of CURVE_NAME
    crypto_random_generate(party->polynomial[i], sizeof(party->polynomial[i]));
    bn_read_be(party->polynomial[i], &coefficient);
    // bn_read_uint32(i + 1, &coefficient);
    // bn_write_be(&coefficient, party->polynomial[i]);

    if (!bn_is_less(&coefficient,
                    &get_curve_by_name(CURVE_NAME)->params->order))
      continue;  // check failed; retry
    i++;
  }

  return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_party_calculate_commitments(mpc_config *params,
                                           mpc_party *party) {
  if (params == NULL || party == NULL)
    return MPC_OP_WRONG_PARAM;

  const ecdsa_curve *curve     = get_curve_by_name(CURVE_NAME)->params;
  uint8_t commitment[33] = {0};
  // uint8_t public[65]     = {0};
#if USER_INPUT == 1
  size_t commitments_storage_size =
      (params->threshold + 1) * sizeof(party->commitments[0]);

  party->commitments = (uint8_t(*)[32])malloc(commitments_storage_size);
#endif

  // calculate commitment for secret
  bignum256 k; bn_read_be(party->node.private_key, &k);
  point_multiply(curve, &k, &curve->G,
                 &party->commitments[0]);
  // ecdsa_get_public_key33(get_curve_by_name(CURVE_NAME)->params,
  //                        party->node.private_key, commitment);
  // if (commitment[0] == 0)
  //   return MPC_OP_INVALID_DATA;
  // else
  //   memcpy(&party->commitments[0], &commitment[1],
  //          sizeof(party->commitments[0]));

  for (int i = 1; i <= params->threshold; i++) {
    memset(commitment, 0, sizeof(commitment));

    // calculate commitment for all coefficients
    bn_read_be(party->polynomial[i - 1], &k);
    point_multiply(curve, &k, &curve->G,
                   &party->commitments[i]);
    // ecdsa_get_public_key33(get_curve_by_name(CURVE_NAME)->params,
    //                        party->polynomial[i - 1], commitment);
    // if (commitment[0] == 0)
    //   return MPC_OP_INVALID_DATA;
    // else
    //   memcpy(&party->commitments[i], &commitment[1],
    //          sizeof(party->commitments[i]));
  }

  return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_party_evaluate_poly(mpc_config *params,
                                   mpc_party *party,
                                   uint16_t share_index,
                                   uint8_t *share) {
  if (params == NULL || party == NULL || share == NULL || share_index == 0)
    return MPC_OP_WRONG_PARAM;

  bignum256 x = {0}, fx = {0}, term = {0}, index = {0};

  bn_read_be(party->node.private_key, &fx);
  bn_read_uint32(share_index, &x);
  bn_read_uint32(share_index, &index);
#if VERBOSE == 1
  print_array((uint8_t *)&fx, sizeof(fx), "[%s] %s-%d", "party", __func__,
              party->id);
  print_array((uint8_t *)&fx, sizeof(fx), "[%s] %s", __func__, "fx");
  // print_array((uint8_t *) params->mpc_parties[0].polynomial, 3 * 32, "[%s] %s", __func__, "party");
  // printf("fx = %llu", bn_write_uint64(&fx));
#endif

  for (int i = 0; i < params->threshold; i++) {
#if VERBOSE == 1
    print_array((uint8_t *)&fx, sizeof(fx), "\n[%s] %s", __func__, "fx");
#endif
    // y += ( ai * (x ^ (i+1)) )
    bn_read_be(party->polynomial[i], &term);
    // printf("term = %llu; x = %llu; ", bn_write_uint64(&term), bn_write_uint64(&x));
    bn_multiply(&x, &term, &get_curve_by_name(CURVE_NAME)->params->order);
    bn_addmod(&fx, &term, &get_curve_by_name(CURVE_NAME)->params->order);

#if VERBOSE == 1
    // printf("term = %llu; y = %llu; ", bn_write_uint64(&term), bn_write_uint64(&fx));
    print_array((uint8_t *)&x, sizeof(x), "[%s] %s", __func__, "x");
    print_array((uint8_t *)&term, sizeof(term), "[%s] %s", __func__, "term");
    print_array((uint8_t *)&fx, sizeof(fx), "[%s] %s", __func__, "fx");
#endif

    // calculate next power of index (i.e. x = index * x)
    bn_multiply(&index, &x, &get_curve_by_name(CURVE_NAME)->params->order);
  }
  // printf("fx = %llu\n", bn_write_uint64(&fx));
  bn_write_be(&fx, share);

#if VERBOSE == 1
  print_array(share, 32, "[%s] %s", __func__, "share");
#endif

  return MPC_OP_SUCCESS;
}

static bignum256 power(bignum256 x, uint64_t y) {
  bignum256 temp = {0};

  bn_one(&temp);

  if (y == 0)
    return temp;

  temp = power(x, y / 2);

  if (y % 2 == 0) {
    bn_multiply(&temp, &temp, &get_curve_by_name(CURVE_NAME)->params->prime);
    return temp;
  } else {
    bn_multiply(&temp, &temp, &get_curve_by_name(CURVE_NAME)->params->prime);
    bn_multiply(&x, &temp, &get_curve_by_name(CURVE_NAME)->params->prime);
    return temp;
  }
}

MPC_STATUS mpc_party_verify_commitments(mpc_config *params,
                                        mpc_party *self,
                                        curve_point *coeff_commits,
                                        uint8_t *share) {
  if (params == NULL || coeff_commits == NULL || share == NULL)
    return MPC_OP_WRONG_PARAM;

  const ecdsa_curve *curve = get_curve_by_name(CURVE_NAME)->params;
  curve_point commit_res, term = {0}, g_share = {0};
  bignum256 pow = {0}, index = {0};

  bn_read_uint32(self->id, &index);
  point_set_infinity(&commit_res);
  // calculate Commit(share) = g^share
  bn_read_be(share, &pow);
  point_multiply(curve, &pow, &curve->G, &g_share);

  for (int i = 0; i <= params->threshold; i++) {
    pow = power(index, i);
    point_multiply(curve, &pow, &coeff_commits[i], &term);
    point_add(curve, &term, &commit_res);
#if VERBOSE == 1
    printf("\npower = %d^%d = %llu", self->id, i, bn_write_uint64(&pow));
    print_array((uint8_t *)&term, sizeof(term), "\n[%s] term^(%llu)", __func__,
                bn_write_uint64(&pow));
    print_array((uint8_t *)&commit_res, sizeof(commit_res), "\n[%s] commit_res^(%llu)", __func__,
                bn_write_uint64(&pow));
#endif
  }

#if VERBOSE == 1
  print_array((uint8_t *) &g_share, sizeof(g_share), "\n[%s] g_share", __func__);
#endif

  if (memcmp(&commit_res, &g_share, sizeof(g_share)) == 0)
    return MPC_OP_VALID_COMMITS;
  else
    return MPC_OP_INVALID_COMMITS;
  return MPC_OP_SUCCESS;
}

void mpc_group_generate_shared_keypair(mpc_group *group) {
  uint8_t shared_private[32] = {0};
  uint8_t shared_public[65]  = {0};
  uint8_t public[65]         = {0};

  curve_point result = {0};
  bignum256 res = {0}, xi = {0};  //, yi = {0};
  for (int i = 0; i < group->params.member_count; i++) {
    bn_read_be(group->mpc_parties[i].node.private_key, &xi);
    bn_addmod(&res, &xi, &get_curve_by_name(CURVE_NAME)->params->order);
  }
  bn_write_be(&res, shared_private);
  private_to_public_key(shared_private, shared_public);
  bn_one(&res);
  point_set_infinity(&result);
  for (int i = 0; i < group->params.member_count; i++) {
    point_add(get_curve_by_name(CURVE_NAME)->params,
              &group->mpc_parties[i].commitments[0], &result);
  }
  bn_write_be(&result.x, public + 1);
  bn_write_be(&result.y, public + 33);
  print_hex_array("private", shared_private, 32);
  print_hex_array("public65", shared_public, 65);
  print_hex_array("public", public, 65);
}

// ECDSA multiply; g^k; private to public
void private_to_public_key(uint8_t *private, uint8_t *public_65) {
  curve_point R = {0}, temp = {0};

  const ecdsa_curve *curve = get_curve_by_name(CURVE_NAME)->params;
  point_set_infinity(&R);
  point_copy(&curve->G, &temp);

  for (int i = 255; i >= 0; i--) {
    int offset = i / 8;
    int bit    = 7 - (i % 8);
    if (private[offset] & (1 << bit)) {
      // bit is set; do add current doubled value to result
      point_add(curve, &temp, &R);
    }
    point_double(curve, &temp);
  }

  public_65[0] = 0x04;
  bn_write_be(&R.x, public_65 + 1);
  bn_write_be(&R.y, public_65 + 33);
}