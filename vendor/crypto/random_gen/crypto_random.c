#include "crypto_random.h"
#include <stdlib.h>

uint32_t crypto_random_begin()
{
	return 0;
}

void crypto_random_end()
{
	
}

bool crypto_random_generate(uint8_t* buf, uint16_t bufsize)
{
	uint16_t i=0;
	do{
		buf[i++]=rand();
	}while(i<bufsize);
	return true;
}

/**
 * [in/out] buf The address where the saved random number should be saved.
 * [in] lower_range Random number should not be less than this number but can be equal to it.
 * [in] upper_range Random number should not be greater than this number but can be equal to it.
 */

bool crypto_random_generate_one_byte(uint8_t* buf, uint16_t lower_range, uint16_t upper_range)
{


    return true;
}

