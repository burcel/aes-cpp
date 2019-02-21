#pragma once
#include "stdafx.h"
#include <iostream>
#include <stdint.h>
#include <ctime>
#include <wmmintrin.h>
#include <emmintrin.h>
#include <smmintrin.h>
#include <tmmintrin.h>

typedef uint8_t  u8;
typedef uint32_t u32;
typedef uint64_t u64;

// 128 Mains
void mainAesNi128ExhaustiveSearch();
void mainAesNi128Ctr();
// 128 Internal Functions
void aesNi128ExhaustiveSearch(u8 *pt, u8 *rk, u8 *ct, u32 range);
void aesNi128Ctr(u8 *pt, u8 *rk, u32 range);
void aesNi128BlockEncryption(__m128i *rk, uint8_t *pt, uint8_t *ct);
void aesNi128LoadKey(uint8_t *encryptionKey, __m128i *rk);
__m128i aesNi128KeyExpansion(__m128i key, __m128i keyGenerated);
u8* aesNi128EncryptOneBlock(u8 *pt, u8 *rk);

// Utils
void printM128i(__m128i var);
void printHex(u8* key, int length);
void incrementByteArray(u8 *rk);
void incrementM128i(__m128i var);
__m128i reverseBytesM128i(__m128i x);