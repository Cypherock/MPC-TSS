#include "mpc.h"
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "crypto_random.h"
#include "memzero.h"
#include "mpc_helpers.h"
#include "mpc_utils.h"
#if USE_FIRMWARE == 1
#include "coin_utils.h"
#include "utils.h"
#include "wallet.h"
#endif

char title[100]             = "";
const uint32_t DERVN_PATH[] = {100, 100};

void init_polynomial(const uint8_t threshold,
                     const uint8_t members,
                     const bignum256 *a0,
                     const bool commit,
                     Polynomial *p) {
  const ecdsa_curve *curve = get_curve_by_name(CURVE_NAME)->params;

  p->coeff_count  = threshold + 1;
  p->member_count = members;
#if USER_INPUT == 1
  p->coeff  = malloc(sizeof(bignum256) * p->coeff_count);
  p->commit = malloc(sizeof(curve_point) * p->coeff_count);
  p->fx     = malloc(sizeof(bignum256) * (members + 1));
#endif
  p->a0 = p->coeff;

  memzero(p->coeff, sizeof(bignum256) * p->coeff_count);
  memzero(p->commit, sizeof(curve_point) * p->coeff_count);
  memzero(p->fx, sizeof(bignum256) * (members + 1));
  gen_polynomial_coeff(p->coeff_count, curve, p->coeff);

  if (a0 != NULL)
    memcpy(p->a0, a0, sizeof(bignum256));

#if USE_FIRMWARE == 1
  uint32_t system_clock = uwTick;
#endif
  for (int i = 0; i <= members; i++) {
    bignum256 x;
    bn_read_uint32(i, &x);
    evaluate_polynomial(curve, p->coeff, threshold, &x, &p->fx[i]);
  }
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Polynomial (%lu) evaluation in %lums\n", threshold,
               uwTick - system_clock);
  system_clock = uwTick;
#endif

  if (!commit)
    return;

  for (int i = 0; i < p->coeff_count; i++) {
    point_multiply(curve, &p->coeff[i], &curve->G, &p->commit[i]);
  }
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Commitment calculation in %lums\n", uwTick - system_clock);
#endif
}

MPC_STATUS mpc_init_group(mpc_group *group) {
  if (group == NULL)
    return MPC_OP_WRONG_PARAM;

  MPC_STATUS status;

#if USE_FIRMWARE == 0
  srand(time(NULL));
#endif
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
  }

  return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_init_party(mpc_config *params,
                          mpc_party *party,
                          uint16_t id,
                          char *name) {
  if (party == NULL || name == NULL)
    return MPC_OP_WRONG_PARAM;
  bignum256 pk = {0};

#if USER_INPUT == 1
  size_t coeffient_storage_size = coeff_count * sizeof(bignum256);
  coeff_array                   = (bignum256 *)malloc(coeffient_storage_size);
#endif
  party->id   = id;
  party->name = name;

  if (!crypto_random_generate(party->entropy, sizeof(party->entropy)))
    return MPC_OP_INVALID_DATA;
  derive_hdnode_from_path(DERVN_PATH, sizeof(DERVN_PATH) / sizeof(uint32_t),
                          CURVE_NAME, party->entropy, &party->node);
  bn_read_be(party->node.private_key, &pk);
  init_polynomial(params->threshold, params->member_count, &pk, true,
                  &party->fx);
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
    print_array((uint8_t *)&commit_res, sizeof(commit_res),
                "\n[%s] commit_res^(%llu)", __func__, bn_write_uint64(&pow));
#endif
  }

#if VERBOSE == 1
  print_array((uint8_t *)&g_share, sizeof(g_share), "\n[%s] g_share", __func__);
#endif

  if (memcmp(&commit_res, &g_share, sizeof(g_share)) == 0)
    return MPC_OP_VALID_COMMITS;
  else
    return MPC_OP_INVALID_COMMITS;
  return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_party_presig_r1(mpc_config *params, mpc_party *party) {
  bignum256 zero_val = {0};

  bn_zero(&zero_val);
  // init fk, fa, fb, fd, fe
  init_polynomial(params->threshold, params->member_count, NULL, false,
                  &party->fk);
  init_polynomial(params->threshold, params->member_count, NULL, false,
                  &party->fa);
  init_polynomial(2 * params->threshold, params->member_count, &zero_val, false,
                  &party->fb);
  init_polynomial(2 * params->threshold, params->member_count, &zero_val, false,
                  &party->fd);
  init_polynomial(2 * params->threshold, params->member_count, &zero_val, false,
                  &party->fe);
  return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_party_consume_r1(mpc_group *group, mpc_party *party) {
  const ecdsa_curve *curve = get_curve_by_name(CURVE_NAME)->params;

  // populate ki, ai, bi, di, ei
  memzero(&party->xi, sizeof(party->xi));
  memzero(&party->ki, sizeof(party->ki));
  memzero(&party->ai, sizeof(party->ai));
  memzero(&party->bi, sizeof(party->bi));
  memzero(&party->di, sizeof(party->di));
  memzero(&party->ei, sizeof(party->ei));
  memzero(&party->wi, sizeof(party->wi));
  memzero(&party->R, sizeof(party->R));
  for (int i = 0; i < group->params.member_count; i++) {
    uint8_t party_id = party->id;
    bn_addmod(&party->xi, &group->mpc_parties[i].fx.fx[party_id],
              &curve->order);
    bn_addmod(&party->ki, &group->mpc_parties[i].fk.fx[party_id],
              &curve->order);
    bn_addmod(&party->ai, &group->mpc_parties[i].fa.fx[party_id],
              &curve->order);
    bn_addmod(&party->bi, &group->mpc_parties[i].fb.fx[party_id],
              &curve->order);
    bn_addmod(&party->di, &group->mpc_parties[i].fd.fx[party_id],
              &curve->order);
    bn_addmod(&party->ei, &group->mpc_parties[i].fe.fx[party_id],
              &curve->order);
  }

  // generate Ri
  point_multiply(curve, &party->xi, &curve->G, &party->Yi);
  point_multiply(curve, &party->ki, &curve->G, &party->R);

  // generate wi
  bn_copy(&party->ki, &party->wi);
  bn_multiply(&party->ai, &party->wi, &curve->order);
  bn_addmod(&party->wi, &party->bi, &curve->order);

  return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_group_presig(mpc_group *group) {
  const ecdsa_curve *curve = get_curve_by_name(CURVE_NAME)->params;

#if USE_FIRMWARE == 1
  uint32_t system_clock = uwTick;
#endif
  // initialize presig_r1 for all parties
  for (int index = 0; index < group->params.member_count; index++) {
    mpc_party *party = &group->mpc_parties[index];
    mpc_party_presig_r1(&group->params, party);
  }
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC PresigR1 in %lums\n", uwTick - system_clock);
  system_clock = uwTick;
#endif

  // compute Ri, wi
  for (int i = 0; i < group->params.member_count; i++) {
    mpc_party_consume_r1(group, &group->mpc_parties[i]);
  }
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC PresigR1 consumed in %lums\n", uwTick - system_clock);
  system_clock = uwTick;
#endif

  // evaluate w using Lagaranges interpolation
  const bignum256 *w_points[] = {
      &group->mpc_parties[0].wi, &group->mpc_parties[1].wi,
      &group->mpc_parties[2].wi, &group->mpc_parties[3].wi,
      &group->mpc_parties[4].wi};
  const uint8_t wx_cords[] = {
      group->mpc_parties[0].id, group->mpc_parties[1].id,
      group->mpc_parties[2].id, group->mpc_parties[3].id,
      group->mpc_parties[4].id};
  lagarange_interpolate(curve, w_points, wx_cords, 0,
                        2 * group->params.threshold, &group->w);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Lagaranges interpolation for 'w' in %lums\n",
               uwTick - system_clock);
  system_clock = uwTick;
#endif

  // evaluate R using Lagaranges interpolation
  const curve_point *points[] = {&group->mpc_parties[0].R,
                                 &group->mpc_parties[1].R,
                                 &group->mpc_parties[2].R};
  const uint8_t x_cords[] = {group->mpc_parties[0].id, group->mpc_parties[1].id,
                             group->mpc_parties[2].id};
  lagarange_exp_interpolate(curve, points, x_cords, 0, group->params.threshold,
                            &group->R);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Lagaranges Exp interpolation for 'R' in %lums\n",
               uwTick - system_clock);
  system_clock = uwTick;
#endif

  // compute Wi
  for (int i = 0; i < group->params.member_count; i++) {
    point_multiply(curve, &group->mpc_parties[i].ai, &group->R,
                   &group->mpc_parties[i].Wi);
  }

  // evaluate W using Lagaranges interpolation
  const curve_point *W_points[] = {&group->mpc_parties[0].Wi,
                                   &group->mpc_parties[1].Wi,
                                   &group->mpc_parties[2].Wi};
  const uint8_t Wx_cords[]      = {group->mpc_parties[0].id,
                                   group->mpc_parties[1].id,
                                   group->mpc_parties[2].id};
  lagarange_exp_interpolate(curve, W_points, Wx_cords, 0,
                            group->params.threshold, &group->W);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Lagaranges interpolation for 'W' in %lums\n",
               uwTick - system_clock);
  system_clock = uwTick;
#endif

  curve_point W = {0};
  point_multiply(curve, &group->w, &curve->G, &W);
  if (memcmp(&W, &group->W, sizeof(W)) != 0)
    raise_error("W comparison failed", 1);
  return MPC_OP_SUCCESS;
}

MPC_STATUS mpc_group_generate_sig(mpc_group *group) {
  const ecdsa_curve *curve = get_curve_by_name(CURVE_NAME)->params;
  uint8_t buffer[32]       = {0};
  bignum256 w_inv          = {0};

  // calculate m
  sha256_Raw(group->msg, group->msg_size, buffer);
  bn_read_be(buffer, &group->m);
  bn_mod(&group->m, &curve->order);

  // calculate w-1
  bn_copy(&group->w, &w_inv);
  bn_inverse(&w_inv, &curve->order);

#if USE_FIRMWARE == 1
  uint32_t system_clock = uwTick;
#endif

  // calculate si
  for (int i = 0; i < group->params.member_count; i++) {
    mpc_party *party = &group->mpc_parties[i];

    // ci = m*di + ei
    bn_copy(&group->m, &party->ci);
    bn_multiply(&party->di, &party->ci, &curve->order);
    bn_addmod(&party->ci, &party->ei, &curve->order);

    // si = hi*(m + r*xi) + ci
    bn_copy(&party->xi, &party->si);
    bn_multiply(&group->R.x, &party->si, &curve->order);
    bn_addmod(&party->si, &group->m, &curve->order);
    bn_multiply(&party->ai, &party->si, &curve->order);
    bn_multiply(&w_inv, &party->si, &curve->order);
    bn_addmod(&party->si, &party->ci, &curve->order);
  }
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC calculate 'si' in %lums\n", uwTick - system_clock);
  system_clock = uwTick;
#endif

  bn_copy(&group->R.x, &group->r);
  // evaluate s using Lagaranges interpolation
  const bignum256 *points[] = {
      &group->mpc_parties[0].si, &group->mpc_parties[1].si,
      &group->mpc_parties[2].si, &group->mpc_parties[3].si,
      &group->mpc_parties[4].si};
  const uint8_t x_cords[] = {group->mpc_parties[0].id, group->mpc_parties[1].id,
                             group->mpc_parties[2].id, group->mpc_parties[3].id,
                             group->mpc_parties[4].id};
  lagarange_interpolate(curve, points, x_cords, 0, 2 * group->params.threshold,
                        &group->s);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Lagaranges interpolation for 's' in %lums\n",
               uwTick - system_clock);
  system_clock = uwTick;
#endif

  // evaluate s using Lagaranges interpolation
  const bignum256 *points1[] = {
      &group->mpc_parties[0].ci, &group->mpc_parties[1].ci,
      &group->mpc_parties[2].ci, &group->mpc_parties[3].ci,
      &group->mpc_parties[4].ci};
  bignum256 temp;
  const uint8_t x_cords1[] = {
      group->mpc_parties[0].id, group->mpc_parties[1].id,
      group->mpc_parties[2].id, group->mpc_parties[3].id,
      group->mpc_parties[4].id};
  lagarange_interpolate(curve, points1, x_cords1, 0,
                        2 * group->params.threshold, &temp);
  bn_mod(&temp, &curve->order);
  if (bn_is_zero(&temp))
    return MPC_OP_SUCCESS;
  else
    return MPC_OP_INVALID_DATA;
}

void mpc_group_generate_shared_keypair(mpc_group *group) {
  uint8_t shared_private[32] = {0};
  uint8_t shared_public[65]  = {0};
  uint8_t public[65]         = {0};
  uint8_t public_int[65]     = {0};

  curve_point result = {0};
  bignum256 res = {0}, xi = {0};  //, yi = {0};
  const curve_point *points[] = {&group->mpc_parties[0].Yi,
                                 &group->mpc_parties[1].Yi,
                                 &group->mpc_parties[2].Yi};
  const uint8_t x_cords[] = {group->mpc_parties[0].id, group->mpc_parties[1].id,
                             group->mpc_parties[2].id};

#if USE_FIRMWARE == 1
  uint32_t system_clock = uwTick;
#endif
  // calculate public key by Lagrange Interpolation in the Exponent
  lagarange_exp_interpolate(get_curve_by_name(CURVE_NAME)->params, points,
                            x_cords, 0, group->params.threshold, &group->Y);
  bn_write_be(&group->Y.x, public_int + 1);
  bn_write_be(&group->Y.y, public_int + 33);
#if USE_FIRMWARE == 1
  LOG_CRITICAL("MPC Lagrange Interpolation in the Exponent in %lums\n",
               uwTick - system_clock);
#endif

  // calculate public key EC multiplication
  for (int i = 0; i < group->params.member_count; i++) {
    bn_read_be(group->mpc_parties[i].node.private_key, &xi);
    bn_addmod(&res, &xi, &get_curve_by_name(CURVE_NAME)->params->order);
  }
  bn_write_be(&res, shared_private);
  private_to_public_key(shared_private, shared_public);

  // calculate public key by using PedCommit of xi
  bn_one(&res);
  point_set_infinity(&result);
  for (int i = 0; i < group->params.member_count; i++) {
    point_add(get_curve_by_name(CURVE_NAME)->params,
              &group->mpc_parties[i].fx.commit[0], &result);
  }
  bn_write_be(&result.x, public + 1);
  bn_write_be(&result.y, public + 33);

  memcpy(group->private, shared_private, sizeof(shared_private));
  memcpy(group->public, shared_public, sizeof(shared_public));
#if USE_FIRMWARE == 0
  print_hex_array("private", shared_private, 32);
  print_hex_array("public65 (EC op)", shared_public, 65);
  print_hex_array("public (PedCommit)", public, 65);
  print_hex_array("public (ExpInt)", public, 65);
#endif
}

void verify_k_r(mpc_group *group) {
  const ecdsa_curve *curve = get_curve_by_name(CURVE_NAME)->params;
  bignum256 nonce_sum      = {0};
  curve_point R            = {0};

  bn_zero(&nonce_sum);

  for (int i = 0; i < group->params.member_count; i++) {
    bn_addmod(&nonce_sum, group->mpc_parties[i].fk.a0, &curve->order);
  }
  point_multiply(get_curve_by_name(CURVE_NAME)->params, &nonce_sum, &curve->G,
                 &R);
  print_hex_array("R", (uint8_t *)&R, sizeof(R));
  print_hex_array("sum", (uint8_t *)&group->R, sizeof(R));
  if (memcmp(&R, &group->R, sizeof(R)) != 0)
    raise_error("r value mismatch", 99);
}

// ECDSA multiply; g^k; private to public
void private_to_public_key(const uint8_t *private, uint8_t *public_65) {
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