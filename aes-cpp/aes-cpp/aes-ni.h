#ifndef AES_NI_H
#define AES_NI_H
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

#define AES_128_KEY_LEN 16
#define AES_192_KEY_LEN 24
#define AES_256_KEY_LEN 32

#define AES_128_KEY_SIZE 11
#define AES_192_KEY_SIZE 13
#define AES_256_KEY_SIZE 15

void aesNiBlockEncryption(__m128i *rk, u8 *pt, u8 *ct, int keySize);
void aesNiExhaustiveSearch(u8 *pt, u8 *rk, u8 *ct, u32 range, int keySize, int keyLen);
void aesNiCtr(u8 *pt, u8 *rk, u32 range, int keySize, int keyLen);
void aesNiCtrMemAlocation(u8 *pt, u8 *rk, u8 *ct, u32 range, int keySize, int keyLen);

// 128
void mainAesNi128ExhaustiveSearch();
void mainAesNi128Ctr();

// 192
void mainAesNi192ExhaustiveSearch();
void mainAesNi192Ctr();

// 256
void mainAesNi256ExhaustiveSearch();
void mainAesNi256Ctr();

// File Encryption
void mainAesNiFileEncryption();


// Utils
void printM128i(__m128i var);
void printHex(u8* key, int length);
void incrementByteArray(u8 *rk);
void incrementM128i(__m128i var);
__m128i reverseBytesM128i(__m128i x);

// Key Expansion
__m128i aes128KeyExpand(__m128i key);
__m128i aes192KeyExpand2(__m128i key, __m128i key2);
void aesNiKeyExpansion(u8 *cipherKey, __m128i *rk, int keyLen);

#endif