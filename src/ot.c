#include "ot.h"
#include "bignum.h"
#include "sha2.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void xorr(uint8_t *m, uint8_t *k, uint8_t *r, uint32_t sz) {
  for (int i = 0; i < sz; i++)
    r[i] = m[i] ^ k[i];
}

void random256bits(uint8_t *a) {
  FILE *random = fopen("/dev/urandom", "rb");

  if (random == NULL) {
    fprintf(stderr, "Error opening /dev/urandom\n");
    exit(1);
  }

  size_t bytesRead = fread(a, sizeof(unsigned char), 32, random);

  if (bytesRead != 32) {
    fprintf(stderr, "Error reading random bytes\n");
    exit(1);
  }

  fclose(random);
}

void ot_poc(uint32_t c) {
  uint8_t m0[32], m1[32];
  uint8_t a_[32], b_[32], g_[32];

  random256bits(m0);
  random256bits(m1);

  printf("m0 = ");
  for (int i = 0; i < 32; i++)
    printf("%02x", m0[i]);
  printf("\nm1 = ");
  for (int i = 0; i < 32; i++)
    printf("%02x", m1[i]);

  random256bits(a_);
  random256bits(b_);
  random256bits(g_);

  bignum256 a, b, g,
      p = {{0x1ffffc2f, 0x1ffffff7, 0x1fffffff, 0x1fffffff, 0x1fffffff,
            0x1fffffff, 0x1fffffff, 0x1fffffff, 0xffffff}};

  bn_read_be(a_, &a);
  bn_read_be(b_, &b);
  bn_read_be(g_, &g);

  printf("\n\na = ");
  bn_print(&a);
  printf("\nb = ");
  bn_print(&b);
  printf("\np = ");
  bn_print(&p);
  printf("\ng = ");
  bn_print(&g);

  bignum256 A, B;

  // A generation
  bn_power_mod(&g, &a, &p, &A); // A = g^a

  // B generation
  bn_power_mod(&g, &b, &p, &B); // B = g^b
  if (c == 1)
    bn_multiply(&A, &B, &p); // B = A*B = A*g^b1

  // kr generation
  bignum256 kr_arg;
  bn_power_mod(&A, &b, &p, &kr_arg); // kr_arg = A^b (diffie hellman)
  uint8_t kr_[32], kr[32];
  bn_write_be(&kr_arg, kr_);
  sha256_Raw(kr_, 32, kr); // kr = hash(kr_arg)

  // k0 generation
  bignum256 k0_arg;
  bn_power_mod(&B, &a, &p, &k0_arg); // k0_arg = B^a
  uint8_t k0_[32], k0[32];
  bn_write_be(&k0_arg, k0_);
  sha256_Raw(k0_, 32, k0);

  // k1 generation
  bignum256 k1_arg;
  bn_inverse(&A, &p);                // A = A^-1
  bn_multiply(&A, &B, &p);           // B = B/A
  bn_power_mod(&B, &a, &p, &k1_arg); // k1_arg = (B/A)^a
  uint8_t k1_[32], k1[32];
  bn_write_be(&k1_arg, k1_);
  sha256_Raw(k1_, 32, k1);

  uint8_t e0[32], e1[32];
  xorr(m0, k0, e0, 32); // encrypt m0 with k0
  xorr(m1, k1, e1, 32); // encrypt m1 with k1

  uint8_t d0[32], d1[32];
  xorr(e0, kr, d0, 32); // decrypt e0 with kr
  xorr(e1, kr, d1, 32); // decrypt e1 with kr

  printf("\nd0 = ");
  for (int i = 0; i < 32; i++)
    printf("%02x", d0[i]);
  printf("\nd1 = ");
  for (int i = 0; i < 32; i++)
    printf("%02x", d1[i]);

  if (!memcmp(d0, m0, 32))
    printf("\nParty A encrypted m0 with k0\n");
  else if (!memcmp(d1, m1, 32))
    printf("\nParty A encrypted m1 with k1\n");
  else // unreachable
    printf("\nUnknown message intercepted\n");
}
