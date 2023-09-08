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

void ot_calculate_shares(const ecdsa_curve* curve,
                         bignum256* x,
                         bignum256* y,
                         bignum256* U,
                         bignum256* V,
                         bignum256* a,
                         bignum256* b,
                         curve_point* A) {
    assert(x != NULL && y != NULL && a != NULL && b != NULL && A != NULL);
    curve_point B[OT_TERM_SIZE];
    int i;

    bn_zero(U);
    bn_zero(V);

    for (i = 0; i < OT_TERM_SIZE; i++) {
        bool bit = bn_testbit(y, i);

        point_multiply(curve, &b[i], &curve->G, &B[i]);  // B[i] = b[i] . G

        if (bit) {
            point_add(curve, &A[i], &B[i]);  // B[i] = B[i] + A[i]
        }
    }

    for (i = OT_TERM_SIZE - 1; i >= 0; i--) {
        bignum256 m[2];

        bignum256 U_i;
        uint8_t U_i_raw[32];
        random_buffer(U_i_raw, sizeof(U_i_raw));
        bn_read_be(U_i_raw, &U_i);

        bn_lshift(U);                       // U <<= 1
        bn_addmod(U, &U_i, &curve->order);  // U += U_i

        // m0
        {
            curve_point k0;
            uint8_t k0_raw[32], k0_hash[32];

            // Diffie Hellman
            point_multiply(curve, &a[i], &B[i],
                           &k0);  // k0 = a[i] . B[i] = (a * b) . B

            bn_write_be(&k0.x, k0_raw);

            sha256_Raw(k0_raw, 32, k0_hash);

            bn_read_be(k0_hash, &k0.x);  // k0 = sha256(k0)

            // simple otp encryption
            bn_xor(&m[0], &k0.x, &U_i);  // m[0] = k0 ^ U_i
        }

        // m1
        {
            curve_point k1, tmp_A = A[i];
            uint8_t k1_raw[32], k1_hash[32];

            bn_cnegate(true, &tmp_A.y, &curve->prime);
            point_add(curve, &tmp_A, &B[i]);  // B[i] = B[i] - A[i]

            // Diffie Hellman
            point_multiply(curve, &a[i], &B[i], &k1);  // k1 = a[i] . B[i]
            bn_write_be(&k1.x, k1_raw);

            sha256_Raw(k1_raw, 32, k1_hash);

            bn_read_be(k1_hash, &k1.x);         // k1 = sha256(k1)
            bn_addmod(&U_i, x, &curve->order);  // ???

            // simple otp encryption
            bn_xor(&m[1], &k1.x, &U_i);  // m[1] = k0 ^ U_i
        }

        // decryption of m
        {
            bignum256 V_i;
            curve_point kr;
            uint8_t kr_raw[32], kr_hash[32];
            bool bit = bn_testbit(y, i);

            // Diffie Hellman

            point_multiply(curve, &b[i], &A[i], &kr);  // kr = b[i] . A[i]
            bn_write_be(&kr.x, kr_raw);

            sha256_Raw(kr_raw, 32, kr_hash);

            bn_read_be(kr_hash, &kr.x);  // kr = sha256(kr)

            // simple otp encryption
            bn_xor(&V_i, &kr.x, &m[bit]);  // V_i = kr ^ m[bit]

            bn_lshift(V);                       // V <<= 1
            bn_addmod(V, &V_i, &curve->order);  // V += V_i
        }
    }

    // U = -U
    bn_cnegate(true, U, &curve->order);
}
