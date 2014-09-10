#pragma once

#include <inttypes.h>
#include <sys/types.h>

void siphash24(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
void siphash24_Kamil(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
void siphash24_Kamil2(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
void siphash24_Kamil3(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
void siphash24_Kamil4(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
void siphash24_Kamil5(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
void siphash24_Kamil6(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
void siphash24_Kamil7(uint8_t out[8], const void *in, size_t inlen, const uint8_t k[16]);
