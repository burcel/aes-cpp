#include "stdafx.h"
#include "aes-ni.h"

using namespace std;

#define KEYEXP128_H(K1, K2, I, S) _mm_xor_si128(aes128_keyexpand(K1), _mm_shuffle_epi32(_mm_aeskeygenassist_si128(K2, I), S))
#define KEYEXP128(K, I) KEYEXP128_H(K, K, I, 0xff)
#define KEYEXP192(K1, K2, I) KEYEXP128_H(K1, K2, I, 0x55)
#define KEYEXP192_2(K1, K2) aes192_keyexpand_2(K1, K2)
#define KEYEXP256(K1, K2, I)  KEYEXP128_H(K1, K2, I, 0xff)
#define KEYEXP256_2(K1, K2) KEYEXP128_H(K1, K2, 0x00, 0xaa)

__m128i aesNi128KeyExpansion(__m128i key, __m128i keyGenerated) {
	keyGenerated = _mm_shuffle_epi32(keyGenerated, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, keyGenerated);
}

void aesNi128LoadKey(uint8_t *encryptionKey, __m128i *rk) {
	rk[0]  = _mm_loadu_si128((const __m128i*) encryptionKey);
	rk[1]  = aesNi128KeyExpansion(rk[0], _mm_aeskeygenassist_si128(rk[0], 0x01));
	rk[2]  = aesNi128KeyExpansion(rk[1], _mm_aeskeygenassist_si128(rk[1], 0x02));
	rk[3]  = aesNi128KeyExpansion(rk[2], _mm_aeskeygenassist_si128(rk[2], 0x04));
	rk[4]  = aesNi128KeyExpansion(rk[3], _mm_aeskeygenassist_si128(rk[3], 0x08));
	rk[5]  = aesNi128KeyExpansion(rk[4], _mm_aeskeygenassist_si128(rk[4], 0x10));
	rk[6]  = aesNi128KeyExpansion(rk[5], _mm_aeskeygenassist_si128(rk[5], 0x20));
	rk[7]  = aesNi128KeyExpansion(rk[6], _mm_aeskeygenassist_si128(rk[6], 0x40));
	rk[8]  = aesNi128KeyExpansion(rk[7], _mm_aeskeygenassist_si128(rk[7], 0x80));
	rk[9]  = aesNi128KeyExpansion(rk[8], _mm_aeskeygenassist_si128(rk[8], 0x1B));
	rk[10] = aesNi128KeyExpansion(rk[9], _mm_aeskeygenassist_si128(rk[9], 0x36));
}

void aesNi128BlockEncryption(__m128i *rk, uint8_t *pt, uint8_t *ct) {
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
	m = _mm_aesenclast_si128(m, rk[10]);

	_mm_storeu_si128((__m128i *) ct, m);
}

u8* aesNi128EncryptOneBlock(u8 *pt, u8 *rk) {
	u8 computed_cipher[16];
	__m128i key_schedule[20];
	aesNi128LoadKey(rk, key_schedule);
	aesNi128BlockEncryption(key_schedule, pt, computed_cipher);
	return computed_cipher;
}

void aesNi128ExhaustiveSearch(u8 *pt, u8 *rk, u8 *ct, u32 range) {
	u8 computed_cipher[16];
	__m128i key_schedule[20];
	for (int rangeCount = 0; rangeCount < range; rangeCount++) {
		//printHex(rk, 16);

		aesNi128LoadKey(rk, key_schedule);
		aesNi128BlockEncryption(key_schedule, pt, computed_cipher);

		if (memcmp(ct, computed_cipher, sizeof(ct)) == 0) {
			cout << "! Key is found: " << endl;
			printHex(rk, 16);
		}

		incrementByteArray(rk);
	}
}


void aesNi128Ctr(u8 *pt, u8 *rk, u32 range) {

	u8 ct[16] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };

	uint8_t computed_cipher[16];
	__m128i key_schedule[20];
	aesNi128LoadKey(rk, key_schedule);
	for (int rangeCount = 0; rangeCount < range; rangeCount++) {
		//cout << "Plaintext: " << endl;
		//printHex(pt, 16);

		aesNi128BlockEncryption(key_schedule, pt, computed_cipher);

		//cout << "Ciphertext: " << endl;
		//printHex(computed_cipher, 16);

		//if (memcmp(ct, computed_cipher, sizeof(ct)) == 0) {
		//	cout << "! Key is found: " << endl;
		//}

		incrementByteArray(pt);
	}

	cout << "Plaintext: " << endl;
	printHex(pt, 16);

	cout << "Ciphertext: " << endl;
	printHex(computed_cipher, 16);
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
		printf("%02x ", val[i]);
	}
	printf("\n");
}

void mainAesNi128ExhaustiveSearch() {
	cout << endl << "########## AES-128 NI Exhaustive Search Implementation ##########" << endl << endl;

	u8 pt[16] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
	u8 ct[16] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
	u8 rk[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x30 };

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	cout << "POWER: " << p << " Range: " << range << endl;
	cout << "------------------------------------" << endl;

	clock_t beginTime = clock();

	aesNi128ExhaustiveSearch(pt, rk, ct, range);
	cout << "------------------------------------" << endl;
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	cout << "------------------------------------" << endl;

}

void mainAesNi128Ctr() {
	cout << endl << "########## AES-128 NI Counter Mode Implementation ##########" << endl << endl;

	u8 pt[16] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
	u8 ct[16] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
	u8 rk[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	cout << "POWER: " << p << " Range: " << range << endl;
	cout << "------------------------------------" << endl;

	clock_t beginTime = clock();

	aesNi128Ctr(pt, rk, range);
	cout << "------------------------------------" << endl;
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	cout << "------------------------------------" << endl;
}