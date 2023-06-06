#include <stdint.h>

void xorr (uint8_t *, uint8_t *, uint8_t *, uint32_t);

// requires urandom
void random256bits(uint8_t *a);

// c = 0 | 1
void ot_poc(uint32_t c);
