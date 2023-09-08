#include "mpc_helpers.h"
#include <assert.h>
#include <string.h>
#include "config.h"
#include "ecdsa.h"
#include "mpc_utils.h"
#include "rand.h"

void gen_polynomial_coeff(const uint8_t coeff_count,
                          const ecdsa_curve* curve,
                          bignum256* coeff_array) {
    assert(curve != NULL && coeff_array != NULL && coeff_count > 0);
    uint8_t coefficient[32] = {0};

    for (int i = 0; i < coeff_count;) {
        memset(&coefficient, 0, sizeof(coefficient));

        /// create a valid coefficient in Fq of given curve
        rand_bytes(coefficient, sizeof(coefficient));
        bn_read_be(coefficient, &coeff_array[i]);

        if (!bn_is_less(&coeff_array[i], &curve->order))
            continue;  // check failed; retry
        i++;
    }
}

void evaluate_polynomial(const ecdsa_curve* curve,
                         const bignum256* coeff,
                         const uint8_t coeff_count,
                         const bignum256* x,
                         bignum256* fx) {
    assert(curve != NULL && coeff != NULL && x != NULL && fx != NULL);
    bignum256 term = {0}, x_pow_i = {0};

    bn_one(&x_pow_i);
    bn_zero(fx);

    for (int i = 0; i <= coeff_count; i++) {
        // fx += ( ai * (x ^ (i+1)) )
        bn_copy(&coeff[i], &term);
        bn_multiply(&x_pow_i, &term, &curve->order);
        bn_addmod(fx, &term, &curve->order);

#if VERBOSE == 1
        // printf("term = %llu; y = %llu; ", bn_write_uint64(&term),
        // bn_write_uint64(&fx));
        print_array((uint8_t*)&x_pow_i, sizeof(bignum256), "[%s] %s", __func__,
                    "x^i");
        print_array((uint8_t*)&term, sizeof(term), "[%s] %s", __func__, "term");
        print_array((uint8_t*)fx, sizeof(bignum256), "[%s] %s", __func__, "fx");
#endif

        // calculate next power of x (i.e. x_pow_i = x_pow_i * x)
        bn_multiply(x, &x_pow_i, &curve->order);
    }

#if VERBOSE == 1
    print_array((uint8_t*)fx, sizeof(bignum256), "[%s] %s", __func__, "fx");
#endif
}

static void evaluate_exp_lagarange_term(const ecdsa_curve* curve,
                                        const curve_point* point,
                                        const uint64_t x_cord,
                                        const uint64_t interpolate_point,
                                        const uint64_t threshold,
                                        curve_point* result) {
    bignum256 lambda = {0}, zero_val = {0}, temp = {0};
    int64_t num = 1, den = 1;

    for (uint64_t m = 0; m <= threshold; m++) {
        if (m + 1 == x_cord)
            continue;

        num *= (int64_t)(m + 1 - interpolate_point);
        den *= (int64_t)(m + 1 - x_cord);
    }

    assert(num % den == 0);
    num /= den;

    bn_zero(&zero_val);
    bn_read_uint32(num < 0 ? num * -1 : num, &lambda);
    bn_copy(&lambda, &temp);
    if (num < 0)
        bn_subtractmod(&zero_val, &temp, &lambda, &curve->order);
    bn_mod(&lambda, &curve->order);
    point_multiply(curve, &lambda, point, result);
}

void evaluate_lagarange_term(const ecdsa_curve* curve,
                             const bignum256* point,
                             const uint64_t x_cord,
                             const uint64_t interpolate_point,
                             const uint64_t threshold,
                             bignum256* result) {
    bignum256 lambda = {0}, zero_val = {0};
    int64_t num = 1, den = 1;

    for (uint64_t m = 0; m <= threshold; m++) {
        if (m + 1 == x_cord)
            continue;

        num *= (int64_t)(m + 1 - interpolate_point);
        den *= (int64_t)(m + 1 - x_cord);
    }

    assert(num % den == 0);
    num /= den;

    bn_zero(&zero_val);
    bn_read_uint32(num < 0 ? num * -1 : num, &lambda);
    bn_multiply(point, &lambda, &curve->order);
    bn_copy(&lambda, result);
    if (num < 0)
        bn_subtractmod(&zero_val, &lambda, result, &curve->order);
    bn_mod(result, &curve->order);
}

// interplate threshold+1 points on polynomial to evaluate polynomial at
// interpolate_point
void lagarange_interpolate(const ecdsa_curve* curve,
                           const bignum256** points,
                           const uint8_t* x_cords,
                           const uint8_t interpolate_point,
                           const uint8_t threshold,
                           bignum256* result) {
    bignum256 term = {0};

    bn_zero(result);
    for (int i = 0; i <= threshold; i++) {
        evaluate_lagarange_term(curve, points[i], x_cords[i], interpolate_point,
                                threshold, &term);
        bn_addmod(result, &term, &curve->order);
    }
}

void lagarange_exp_interpolate(const ecdsa_curve* curve,
                               const curve_point** points,
                               const uint8_t* x_cords,
                               const uint8_t interpolate_point,
                               const uint8_t threshold,
                               curve_point* result) {
    curve_point term = {0};

    point_set_infinity(result);
    for (int i = 0; i <= threshold; i++) {
        evaluate_exp_lagarange_term(curve, points[i], x_cords[i],
                                    interpolate_point, threshold, &term);
        point_add(curve, &term, result);
    }
}
