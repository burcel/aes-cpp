#include "stdafx.h"
#include "aes-ni.h"
#include <fstream>

using namespace std;

#define KEYEXP128_H(K1, K2, I, S) _mm_xor_si128(aes128KeyExpand(K1), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(K2, I), S))
#define KEYEXP128(K, I) KEYEXP128_H(K, K, I, 0xff)
#define KEYEXP192(K1, K2, I) KEYEXP128_H(K1, K2, I, 0x55)
#define KEYEXP192_2(K1, K2) aes192KeyExpand2(K1, K2)
#define KEYEXP256(K1, K2, I)  KEYEXP128_H(K1, K2, I, 0xff)
#define KEYEXP256_2(K1, K2) KEYEXP128_H(K1, K2, 0x00, 0xaa)

__m128i aes128KeyExpand(__m128i key) {
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, _mm_slli_si128(key, 4));
}

__m128i aes192KeyExpand2(__m128i key, __m128i key2) {
	key = _mm_shuffle_epi32(key, 0xff);
	key2 = _mm_xor_si128(key2, _mm_slli_si128(key2, 4));
	return _mm_xor_si128(key, key2);
}

void aesNiKeyExpansion(u8 *cipherKey, __m128i *rk, int keyLen) {
	switch (keyLen) {
		case AES_128_KEY_LEN: {
			/* 128 bit key setup */
			rk[0] = _mm_loadu_si128((const __m128i*) cipherKey);
			rk[1] = KEYEXP128(rk[0], 0x01);
			rk[2] = KEYEXP128(rk[1], 0x02);
			rk[3] = KEYEXP128(rk[2], 0x04);
			rk[4] = KEYEXP128(rk[3], 0x08);
			rk[5] = KEYEXP128(rk[4], 0x10);
			rk[6] = KEYEXP128(rk[5], 0x20);
			rk[7] = KEYEXP128(rk[6], 0x40);
			rk[8] = KEYEXP128(rk[7], 0x80);
			rk[9] = KEYEXP128(rk[8], 0x1B);
			rk[10] = KEYEXP128(rk[9], 0x36);
			break;
		}
		case AES_192_KEY_LEN: {
			/* 192 bit key setup */
			__m128i temp[2];
			rk[0] = _mm_loadu_si128((const __m128i*) cipherKey);
			rk[1] = _mm_loadu_si128((const __m128i*) (cipherKey + 16));
			rk[1] = _mm_and_si128(rk[1], _mm_set_epi32(0, 0, 0xFFFFFFFF, 0xFFFFFFFF));
			temp[0] = KEYEXP192(rk[0], rk[1], 0x01);
			temp[1] = KEYEXP192_2(temp[0], rk[1]);
			rk[1] = _mm_xor_si128(rk[1], _mm_slli_si128(temp[0], 8));
			rk[2] = _mm_xor_si128(_mm_srli_si128(temp[0], 8), _mm_slli_si128(temp[1], 8));
			rk[3] = KEYEXP192(temp[0], temp[1], 0x02);
			rk[4] = KEYEXP192_2(rk[3], temp[1]);
			temp[0] = KEYEXP192(rk[3], rk[4], 0x04);
			temp[1] = KEYEXP192_2(temp[0], rk[4]);
			rk[4] = _mm_and_si128(rk[4], _mm_set_epi32(0, 0, 0xFFFFFFFF, 0xFFFFFFFF));
			rk[4] = _mm_xor_si128(rk[4], _mm_slli_si128(temp[0], 8));
			rk[5] = _mm_xor_si128(_mm_srli_si128(temp[0], 8), _mm_slli_si128(temp[1], 8));
			rk[6] = KEYEXP192(temp[0], temp[1], 0x08);
			rk[7] = KEYEXP192_2(rk[6], temp[1]);
			temp[0] = KEYEXP192(rk[6], rk[7], 0x10);
			temp[1] = KEYEXP192_2(temp[0], rk[7]);
			rk[7] = _mm_and_si128(rk[7], _mm_set_epi32(0, 0, 0xFFFFFFFF, 0xFFFFFFFF));
			rk[7] = _mm_xor_si128(rk[7], _mm_slli_si128(temp[0], 8));
			rk[8] = _mm_xor_si128(_mm_srli_si128(temp[0], 8), _mm_slli_si128(temp[1], 8));
			rk[9] = KEYEXP192(temp[0], temp[1], 0x20);
			rk[10] = KEYEXP192_2(rk[9], temp[1]);
			temp[0] = KEYEXP192(rk[9], rk[10], 0x40);
			temp[1] = KEYEXP192_2(temp[0], rk[10]);
			rk[10] = _mm_and_si128(rk[10], _mm_set_epi32(0, 0, 0xFFFFFFFF, 0xFFFFFFFF));
			rk[10] = _mm_xor_si128(rk[10], _mm_slli_si128(temp[0], 8));
			rk[11] = _mm_xor_si128(_mm_srli_si128(temp[0], 8), _mm_slli_si128(temp[1], 8));
			rk[12] = KEYEXP192(temp[0], temp[1], 0x80);
			break;
		}
		case AES_256_KEY_LEN: {
			/* 256 bit key setup */
			rk[0] = _mm_loadu_si128((const __m128i*) cipherKey);
			rk[1] = _mm_loadu_si128((const __m128i*) (cipherKey + 16));
			rk[2] = KEYEXP256(rk[0], rk[1], 0x01);
			rk[3] = KEYEXP256_2(rk[1], rk[2]);
			rk[4] = KEYEXP256(rk[2], rk[3], 0x02);
			rk[5] = KEYEXP256_2(rk[3], rk[4]);
			rk[6] = KEYEXP256(rk[4], rk[5], 0x04);
			rk[7] = KEYEXP256_2(rk[5], rk[6]);
			rk[8] = KEYEXP256(rk[6], rk[7], 0x08);
			rk[9] = KEYEXP256_2(rk[7], rk[8]);
			rk[10] = KEYEXP256(rk[8], rk[9], 0x10);
			rk[11] = KEYEXP256_2(rk[9], rk[10]);
			rk[12] = KEYEXP256(rk[10], rk[11], 0x20);
			rk[13] = KEYEXP256_2(rk[11], rk[12]);
			rk[14] = KEYEXP256(rk[12], rk[13], 0x40);
			break;
		}
	}
}

void aesNiBlockEncryption(__m128i *rk, u8 *pt, u8 *ct, int keySize) {
	__m128i m = _mm_loadu_si128((__m128i *) pt);
	m = _mm_xor_si128(m, rk[0]);
	m = _mm_aesenc_si128(m, rk[1]);
	m = _mm_aesenc_si128(m, rk[2]);
	m = _mm_aesenc_si128(m, rk[3]);
	m = _mm_aesenc_si128(m, rk[4]);
	m = _mm_aesenc_si128(m, rk[5]);
	m = _mm_aesenc_si128(m, rk[6]);
	m = _mm_aesenc_si128(m, rk[7]);
	m = _mm_aesenc_si128(m, rk[8]);
	m = _mm_aesenc_si128(m, rk[9]);
	if (keySize == AES_192_KEY_SIZE || keySize == AES_256_KEY_SIZE) {
		m = _mm_aesenc_si128(m, rk[10]);
		m = _mm_aesenc_si128(m, rk[11]);
		if (keySize == AES_256_KEY_SIZE) {
			m = _mm_aesenc_si128(m, rk[12]);
			m = _mm_aesenc_si128(m, rk[13]);
		}
	}

	m = _mm_aesenclast_si128(m, rk[keySize-1]);

	_mm_storeu_si128((__m128i *) ct, m);
}

void aesNiExhaustiveSearch(u8 *pt, u8 *rk, u8 *ct, u32 range, int keySize, int keyLen) {
	u8 createdCiphertext[AES_128_KEY_LEN];
	__m128i *roundKeys = new __m128i[keySize];
	
	for (int rangeCount = 0; rangeCount < range; rangeCount++) {

		aesNiKeyExpansion(rk, roundKeys, keyLen);
		aesNiBlockEncryption(roundKeys, pt, createdCiphertext, keySize);

		if (memcmp(ct, createdCiphertext, sizeof(ct)) == 0) {
			cout << "! Key is found: " << endl;
			printHex(rk, keyLen);
		}

		incrementByteArray(rk);
	}

	delete roundKeys;
}

void aesNiCtr(u8 *pt, u8 *rk, u32 range, int keySize, int keyLen) {

	u8 createdCiphertext[AES_128_KEY_LEN];
	__m128i *roundKeys = new __m128i[keySize];
	aesNiKeyExpansion(rk, roundKeys, keyLen);
	for (int rangeCount = 0; rangeCount < range; rangeCount++) {

		aesNiBlockEncryption(roundKeys, pt, createdCiphertext, keySize);

		incrementByteArray(pt);

		if (rangeCount == 0) {
			printf("Ciphertext    :"); printHex(createdCiphertext, AES_128_KEY_LEN);
		}
	}

	delete roundKeys;
}

void aesNiCtrMemAlocation(u8 *pt, u8 *rk, u8 *ct, u32 range, int keySize, int keyLen) {

	u32 ctIndex = 0;
	u8 createdCiphertext[AES_128_KEY_LEN];
	__m128i *roundKeys = new __m128i[keySize];
	aesNiKeyExpansion(rk, roundKeys, keyLen);
	for (int rangeCount = 0; rangeCount < range; rangeCount++) {

		aesNiBlockEncryption(roundKeys, pt, createdCiphertext, keySize);

		incrementByteArray(pt);

		// Allocate ciphertext
		for (int createdCtIndex = 0; createdCtIndex < AES_128_KEY_LEN; createdCtIndex++, ctIndex++) {
			ct[ctIndex] = createdCiphertext[createdCtIndex];
		}
	}

	delete roundKeys;
}

void printHex(u8* key, int length) {
	for (int i = 0; i < length; i++) {
		unsigned int keyByteValue = key[i];
		printf("%02x", key[i]);
		if (i % 4 == 3) {
			printf(" ");
		}
	}
	printf("\n");
}

void incrementByteArray(u8 *rk) {
	rk[15]++;
	for (int keySize = 0; keySize < 16; keySize++) {
		if (rk[15 - keySize] == 0x00) {
			if (keySize != 15) {
				rk[14 - keySize]++;
			}
		} else {
			break;
		}
	}
}

void incrementM128i(__m128i var) {
	var = reverseBytesM128i(var);
	//var++;
	var = reverseBytesM128i(var);
}

__m128i reverseBytesM128i(__m128i x) {
	// Swap bytes in each 16-bit word:
	__m128i a = _mm_or_si128(_mm_slli_epi16(x, 8), _mm_srli_epi16(x, 8));
	// Reverse all 16-bit words in 64-bit halves:
	a = _mm_shufflelo_epi16(a, _MM_SHUFFLE(0, 1, 2, 3));
	a = _mm_shufflehi_epi16(a, _MM_SHUFFLE(0, 1, 2, 3));
	// Reverse 64-bit halves:
	return _mm_shuffle_epi32(a, _MM_SHUFFLE(1, 0, 3, 2));
}

void printM128i(__m128i var) {
	uint8_t *val = (uint8_t*)&var;
	for (int i = 0; i < 16; i++) {
		printf("%02x", val[i]);
		if (i % 4 == 3) {
			printf(" ");
		}
	}
	printf("\n");
}

void mainAesNi128ExhaustiveSearch() {
	cout << endl << "########## AES-128 NI Exhaustive Search Implementation ##########" << endl << endl;

	u8 pt[AES_128_KEY_LEN] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
	u8 ct[AES_128_KEY_LEN] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
	u8 rk[AES_128_KEY_LEN] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Initial Key   :"); printHex(rk, AES_128_KEY_LEN);
	printf("Plaintext     :"); printHex(pt, AES_128_KEY_LEN);
	printf("Ciphertext    :"); printHex(ct, AES_128_KEY_LEN);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aesNiExhaustiveSearch(pt, rk, ct, range, AES_128_KEY_SIZE, AES_128_KEY_LEN);

	cout << "------------------------------------" << endl;
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	cout << "------------------------------------" << endl;

}

void mainAesNi192ExhaustiveSearch() {
	cout << endl << "########## AES-192 NI Exhaustive Search Implementation ##########" << endl << endl;

	u8 pt[AES_128_KEY_LEN] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };
	u8 ct[AES_128_KEY_LEN] = { 0xBD, 0x33, 0x4F, 0x1D, 0x6E, 0x45, 0xF2, 0x5F, 0xF7, 0x12, 0xA2, 0x14, 0x57, 0x1F, 0xA5, 0xCC };
	u8 rk[AES_192_KEY_LEN] = { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5, 
		0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B };

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Initial Key   :"); printHex(rk, AES_192_KEY_LEN);
	printf("Plaintext     :"); printHex(pt, AES_128_KEY_LEN);
	printf("Ciphertext    :"); printHex(ct, AES_128_KEY_LEN);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aesNiExhaustiveSearch(pt, rk, ct, range, AES_192_KEY_SIZE, AES_192_KEY_LEN);

	cout << "------------------------------------" << endl;
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	cout << "------------------------------------" << endl;

}

void mainAesNi256ExhaustiveSearch() {
	cout << endl << "########## AES-256 NI Exhaustive Search Implementation ##########" << endl << endl;

	u8 pt[AES_128_KEY_LEN] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };
	u8 ct[AES_128_KEY_LEN] = { 0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1, 0x81, 0xF8 };
	u8 rk[AES_256_KEY_LEN] = { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81, 
		0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 };

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Initial Key   :"); printHex(rk, AES_256_KEY_LEN);
	printf("Plaintext     :"); printHex(pt, AES_128_KEY_LEN);
	printf("Ciphertext    :"); printHex(ct, AES_128_KEY_LEN);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aesNiExhaustiveSearch(pt, rk, ct, range, AES_256_KEY_SIZE, AES_256_KEY_LEN);

	cout << "------------------------------------" << endl;
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	cout << "------------------------------------" << endl;

}

void mainAesNi128Ctr() {
	cout << endl << "########## AES-128 NI Counter Mode Implementation ##########" << endl << endl;

	u8 pt[AES_128_KEY_LEN] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
	u8 ct[AES_128_KEY_LEN] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
	u8 rk[AES_128_KEY_LEN] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Initial Key   :"); printHex(rk, AES_128_KEY_LEN);
	printf("Plaintext     :"); printHex(pt, AES_128_KEY_LEN);
	printf("Ciphertext    :"); printHex(ct, AES_128_KEY_LEN);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aesNiCtr(pt, rk, range, AES_128_KEY_SIZE, AES_128_KEY_LEN);

	cout << "------------------------------------" << endl;
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	cout << "------------------------------------" << endl;
}

void mainAesNi192Ctr() {
	cout << endl << "########## AES-192 NI Counter Mode Implementation ##########" << endl << endl;

	u8 pt[AES_128_KEY_LEN] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };
	u8 ct[AES_128_KEY_LEN] = { 0xBD, 0x33, 0x4F, 0x1D, 0x6E, 0x45, 0xF2, 0x5F, 0xF7, 0x12, 0xA2, 0x14, 0x57, 0x1F, 0xA5, 0xCC };
	u8 rk[AES_192_KEY_LEN] = { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
		0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B };

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Initial Key   :"); printHex(rk, AES_192_KEY_LEN);
	printf("Plaintext     :"); printHex(pt, AES_128_KEY_LEN);
	printf("Ciphertext    :"); printHex(ct, AES_128_KEY_LEN);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aesNiCtr(pt, rk, range, AES_192_KEY_SIZE, AES_192_KEY_LEN);

	cout << "------------------------------------" << endl;
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	cout << "------------------------------------" << endl;
}

void mainAesNi256Ctr() {
	cout << endl << "########## AES-256 NI Counter Mode Implementation ##########" << endl << endl;

	u8 pt[AES_128_KEY_LEN] = { 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A };
	u8 ct[AES_128_KEY_LEN] = { 0xF3, 0xEE, 0xD1, 0xBD, 0xB5, 0xD2, 0xA0, 0x3C, 0x06, 0x4B, 0x5A, 0x7E, 0x3D, 0xB1, 0x81, 0xF8 };
	u8 rk[AES_256_KEY_LEN] = { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
		0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 };

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Initial Key   :"); printHex(rk, AES_256_KEY_LEN);
	printf("Plaintext     :"); printHex(pt, AES_128_KEY_LEN);
	printf("Ciphertext    :"); printHex(ct, AES_128_KEY_LEN);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aesNiCtr(pt, rk, range, AES_256_KEY_SIZE, AES_256_KEY_LEN);

	cout << "------------------------------------" << endl;
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	cout << "------------------------------------" << endl;
}

void mainAesNiFileEncryption() {
	cout << endl << "########## AES-128 NI File Encryption Implementation ##########" << endl << endl;

	u8 pt[AES_128_KEY_LEN] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
	u8 ct[AES_128_KEY_LEN] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
	u8 rk128[AES_128_KEY_LEN] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };
	u8 rk192[AES_192_KEY_LEN] = { 0x8E, 0x73, 0xB0, 0xF7, 0xDA, 0x0E, 0x64, 0x52, 0xC8, 0x10, 0xF3, 0x2B, 0x80, 0x90, 0x79, 0xE5,
	0x62, 0xF8, 0xEA, 0xD2, 0x52, 0x2C, 0x6B, 0x7B };
	u8 rk256[AES_256_KEY_LEN] = { 0x60, 0x3D, 0xEB, 0x10, 0x15, 0xCA, 0x71, 0xBE, 0x2B, 0x73, 0xAE, 0xF0, 0x85, 0x7D, 0x77, 0x81,
	0x1F, 0x35, 0x2C, 0x07, 0x3B, 0x61, 0x08, 0xD7, 0x2D, 0x98, 0x10, 0xA3, 0x09, 0x14, 0xDF, 0xF4 };

	int chunkSize = 1024;
	const string filePath = "C://file-encryption-test//william3.mp4_ENC";
	fstream fileIn(filePath, fstream::in | fstream::binary);
	if (fileIn) {
		// Get file size
		fileIn.seekg(0, fileIn.end);
		int fileSize = fileIn.tellg();
		fileIn.seekg(0, fileIn.beg);
		printf("File: %s\n", filePath.c_str());
		printf("Size in bytes: %d\n", fileSize);
		printf("-------------------------------\n");

		double totalBlockSize = (double)fileSize / AES_128_KEY_LEN;
		u32 encryptionCount = ceil(totalBlockSize);
		u32 ciphertextSize = encryptionCount * AES_128_KEY_LEN * sizeof(u8);
		u8 *ct = new u8[ciphertextSize];

		printf("Total encryptions             : %d\n", encryptionCount);
		printf("Total encryptions in byte     : %d\n", ciphertextSize);
		printf("-------------------------------\n");
		printf("Initial Key      :"); printHex(rk128, AES_128_KEY_LEN);
		//printf("Initial Key      :"); printHex(rk192, AES_192_KEY_LEN);
		//printf("Initial Key      :"); printHex(rk256, AES_256_KEY_LEN);
		printf("Initial Counter  :"); printHex(pt, AES_128_KEY_LEN);
		printf("-------------------------------\n");

		clock_t beginTime = clock();

		aesNiCtrMemAlocation(pt, rk128, ct, encryptionCount, AES_128_KEY_SIZE, AES_128_KEY_LEN);

		printf("-------------------------------\n");
		printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
		printf("-------------------------------\n");


		beginTime = clock();
		// Open output file
		const std::string outFilePath = filePath + "_ENC";
		printf("Encrypted File: %s\n", outFilePath.c_str());
		printf("-------------------------------\n");
		fstream fileOut(outFilePath, fstream::out | fstream::binary);
		// Allocate file buffer
		char * buffer = new char[chunkSize];
		while (1) {
			// Read data as a block into buffer:
			fileIn.read(buffer, chunkSize);
			// Decide whether buffer is at the last part
			long readByte = 0;
			if (fileIn) {
				// All characters read successfully
				readByte = chunkSize;
			} else {
				// Only readByte characters could be read
				readByte = fileIn.gcount();
			}
			// Process current buffer
			u32 readInt = 0;
			u32 ctIndex = 0;
			for (u32 bufferIndex = 0; bufferIndex < readByte; bufferIndex++, ctIndex++) {
				buffer[bufferIndex] ^= ct[ctIndex];
			}
			// Write buffer to output file
			fileOut.write(buffer, readByte);
			// stop
			if (readByte < chunkSize) {
				break;
			}
		}

		printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
		printf("-------------------------------\n");

		delete[] buffer;
		fileOut.close();


		delete ct;
	} else {
		printf("File could not be opened: %s\n", filePath.c_str());
	}

}
