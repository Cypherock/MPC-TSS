#ifndef MPC_HELPERS
#define MPC_HELPERS

#include <stdint.h>
#include "bignum.h"
#include "ecdsa.h"
#if USE_FIRMWARE == 1
#include "utils.h"
#include "wallet.h"
#endif

void gen_polynomial_coeff(uint8_t coeff_count,
                          const ecdsa_curve *curve,
                          bignum256 *coeff_array);

void evaluate_polynomial(const ecdsa_curve *curve,
                         const bignum256 *coeff,
                         uint8_t coeff_count,
                         const bignum256 *x,
                         bignum256 *fx);

void evaluate_lagarange_term(const ecdsa_curve *curve,
                                    const bignum256 *point,
                                    const uint64_t x_cord,
                                    const uint64_t interpolate_point,
                                    const uint64_t threshold,
                                    bignum256 *result);

void lagarange_exp_interpolate(const ecdsa_curve *curve,
                               const curve_point **points,
                               const uint8_t *x_cords,
                               uint8_t interpolate_point,
                               uint8_t threshold,
                               curve_point *result);

void lagarange_interpolate(const ecdsa_curve *curve,
                           const bignum256 **points,
                           const uint8_t *x_cords,
                           uint8_t interpolate_point,
                           uint8_t threshold,
                           bignum256 *result);

#endif
