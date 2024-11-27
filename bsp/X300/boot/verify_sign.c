#include <stdint.h>
#include <string.h>
#include <openssl/sha.h>

int verify_sign(const uint8_t* data, size_t data_len, 
				const uint8_t* stored_sign) 
{
	uint8_t calc_hash[SHA256_DIGEST_LENGTH];
	//Calc hash of input data
	SHA256(data, data_len, calc_hash);
	return memcmp(calc_hash, stored_sign, SHA256_DIGEST_LENGTH);
}

