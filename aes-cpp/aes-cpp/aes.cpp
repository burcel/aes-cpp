#pragma once
#include "stdafx.h"
#include "aes.h"
#include <fstream>

using namespace std;

u32 arithmeticRightShift(u32 x, int n) {
	return (x >> n) | (x << (-n & 31));
}

void aesKeyExpansion(u32 *cipherKey, u32 *rk, int keyLen) {
	switch (keyLen) {
		case AES_128_KEY_LEN_INT: {
			/* 128 bit key setup */
			u32 rk0, rk1, rk2, rk3;
			rk0 = cipherKey[0];
			rk1 = cipherKey[1];
			rk2 = cipherKey[2];
			rk3 = cipherKey[3];

			rk[0] = rk0;
			rk[1] = rk1;
			rk[2] = rk2;
			rk[3] = rk3;

			for (u8 roundCount = 0; roundCount < ROUND_COUNT_128; roundCount++) {
				u32 temp = rk3;
				rk0 = rk0 ^
					(T4[(temp >> 16) & 0xff] & 0xff000000) ^
					(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
					(T4[(temp      ) & 0xff] & 0x0000ff00) ^
					(T4[(temp >> 24)       ] & 0x000000ff) ^
					RCON32[roundCount];
				rk1 = rk1 ^ rk0;
				rk2 = rk2 ^ rk1;
				rk3 = rk2 ^ rk3;

				rk[roundCount * 4 + 4] = rk0;
				rk[roundCount * 4 + 5] = rk1;
				rk[roundCount * 4 + 6] = rk2;
				rk[roundCount * 4 + 7] = rk3;
			}

			// Print keys
			//for (int i = 0; i < AES_128_KEY_SIZE_INT; i++) {
			//	printf("%08x ", rk[i]);
			//	if ((i+1) % 4 == 0) {
			//		printf("Round: %d\n", i / 4);
			//	}
			//}
			break;
		}
		case AES_192_KEY_LEN_INT: {
			/* 192 bit key setup */
			u32 rk0, rk1, rk2, rk3, rk4, rk5;
			rk0 = cipherKey[0];
			rk1 = cipherKey[1];
			rk2 = cipherKey[2];
			rk3 = cipherKey[3];
			rk4 = cipherKey[4];
			rk5 = cipherKey[5];

			rk[0] = rk0;
			rk[1] = rk1;
			rk[2] = rk2;
			rk[3] = rk3;
			rk[4] = rk4;
			rk[5] = rk5;

			for (u8 roundCount = 0; roundCount < ROUND_COUNT_192; roundCount++) {
				u32 temp = rk5;
				rk0 = rk0 ^
					(T4[(temp >> 16) & 0xff] & 0xff000000) ^
					(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
					(T4[(temp      ) & 0xff] & 0x0000ff00) ^
					(T4[(temp >> 24)       ] & 0x000000ff) ^
					RCON32[roundCount];
				rk1 = rk1 ^ rk0;
				rk2 = rk2 ^ rk1;
				rk3 = rk3 ^ rk2;
				rk4 = rk4 ^ rk3;
				rk5 = rk5 ^ rk4;

				rk[roundCount * 6 + 6] = rk0;
				rk[roundCount * 6 + 7] = rk1;
				rk[roundCount * 6 + 8] = rk2;
				rk[roundCount * 6 + 9] = rk3;
				if (roundCount == 7) {
					break;
				}
				rk[roundCount * 6 + 10] = rk4;
				rk[roundCount * 6 + 11] = rk5;
			}

			// Print keys
			//for (int i = 0; i < AES_192_KEY_SIZE_INT; i++) {
			//	printf("%08x ", rk[i]);
			//	if ((i + 1) % 4 == 0) {
			//		printf("Round: %d\n", i / 4);
			//	}
			//}
			break;
		}
		case AES_256_KEY_LEN_INT: {
			/* 256 bit key setup */
			u32 rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7;
			rk0 = cipherKey[0];
			rk1 = cipherKey[1];
			rk2 = cipherKey[2];
			rk3 = cipherKey[3];
			rk4 = cipherKey[4];
			rk5 = cipherKey[5];
			rk6 = cipherKey[6];
			rk7 = cipherKey[7];

			rk[0] = rk0;
			rk[1] = rk1;
			rk[2] = rk2;
			rk[3] = rk3;
			rk[4] = rk4;
			rk[5] = rk5;
			rk[6] = rk6;
			rk[7] = rk7;

			for (u8 roundCount = 0; roundCount < ROUND_COUNT_256; roundCount++) {
				u32 temp = rk7;
				rk0 = rk0 ^ 
					(T4[(temp >> 16) & 0xff] & 0xff000000) ^ 
					(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
					(T4[(temp      ) & 0xff] & 0x0000ff00) ^
					(T4[(temp >> 24)       ] & 0x000000ff) ^
					RCON32[roundCount];
				rk1 = rk1 ^ rk0;
				rk2 = rk2 ^ rk1;
				rk3 = rk3 ^ rk2;
				rk4 = rk4 ^ 
					(T4[(rk3 >> 24) & 0xff] & 0xff000000) ^
					(T4[(rk3 >> 16) & 0xff] & 0x00ff0000) ^
					(T4[(rk3 >>  8) & 0xff] & 0x0000ff00) ^
					(T4[(rk3      ) & 0xff] & 0x000000ff);
				rk5 = rk5 ^ rk4;
				rk6 = rk6 ^ rk5;
				rk7 = rk7 ^ rk6;

				rk[roundCount * 8 + 8] = rk0;
				rk[roundCount * 8 + 9] = rk1;
				rk[roundCount * 8 + 10] = rk2;
				rk[roundCount * 8 + 11] = rk3;
				if (roundCount == 6) {
					break;
				}
				rk[roundCount * 8 + 12] = rk4;
				rk[roundCount * 8 + 13] = rk5;
				rk[roundCount * 8 + 14] = rk6;
				rk[roundCount * 8 + 15] = rk7;

			}

			// Print keys
			//for (int i = 0; i < AES_256_KEY_SIZE_INT; i++) {
			//	printf("%08x ", rk[i]);
			//	if ((i + 1) % 4 == 0) {
			//		printf("Round: %d\n", i / 4);
			//	}
			//}
			break;
		}
	}
}

void aes128ExhaustiveSearch(u32 *pt, u32 *rk, u32 *ct, u32 range) {

	u32 rk0Init, rk1Init, rk2Init, rk3Init;
	rk0Init = rk[0];
	rk1Init = rk[1];
	rk2Init = rk[2];
	rk3Init = rk[3];

	u32 pt0Init, pt1Init, pt2Init, pt3Init;
	pt0Init = pt[0];
	pt1Init = pt[1];
	pt2Init = pt[2];
	pt3Init = pt[3];

	for (int rangeCount = 0; rangeCount < range; rangeCount++) {

		u32 rk0, rk1, rk2, rk3;
		rk0 = rk0Init;
		rk1 = rk1Init;
		rk2 = rk2Init;
		rk3 = rk3Init;

		// Create plaintext as 32 bit unsigned integers
		u32 s0, s1, s2, s3;
		s0 = pt0Init;
		s1 = pt1Init;
		s2 = pt2Init;
		s3 = pt3Init;

		// First round just XORs input with key.
		s0 = s0 ^ rk0;
		s1 = s1 ^ rk1;
		s2 = s2 ^ rk2;
		s3 = s3 ^ rk3;

		u32 t0, t1, t2, t3;
		for (u8 roundCount = 0; roundCount < ROUND_COUNT_128_MIN_1; roundCount++) {

			// Calculate round key
			u32 temp = rk3;
			rk0 = rk0 ^
				(T4[(temp >> 16) & 0xff] & 0xff000000) ^
				(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
				(T4[(temp      ) & 0xff] & 0x0000ff00) ^
				(T4[(temp >> 24)       ] & 0x000000ff) ^
				RCON32[roundCount];
			rk1 = rk1 ^ rk0;
			rk2 = rk2 ^ rk1;
			rk3 = rk2 ^ rk3;

			// Table based round function
			t0 = T0[s0 >> 24] ^ arithmeticRightShift(T0[(s1 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s2 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s3 & 0xFF], SHIFT_3_RIGHT) ^ rk0;
			t1 = T0[s1 >> 24] ^ arithmeticRightShift(T0[(s2 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s3 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s0 & 0xFF], SHIFT_3_RIGHT) ^ rk1;
			t2 = T0[s2 >> 24] ^ arithmeticRightShift(T0[(s3 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s0 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s1 & 0xFF], SHIFT_3_RIGHT) ^ rk2;
			t3 = T0[s3 >> 24] ^ arithmeticRightShift(T0[(s0 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s1 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s2 & 0xFF], SHIFT_3_RIGHT) ^ rk3;

			s0 = t0;
			s1 = t1;
			s2 = t2;
			s3 = t3;

		}

		// Calculate the last round key
		u32 temp = rk3;
		rk0 = rk0 ^
			(T4[(temp >> 16) & 0xff] & 0xff000000) ^
			(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
			(T4[(temp      ) & 0xff] & 0x0000ff00) ^
			(T4[(temp >> 24)       ] & 0x000000ff) ^
			RCON32[ROUND_COUNT_128_MIN_1];
		// Last round uses s-box directly and XORs to produce output.
		s0 = (T4[t0 >> 24] & 0xFF000000) ^ (T4[(t1 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t2 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t3) & 0xFF] & 0x000000FF) ^ rk0;
		if (s0 == ct[0]) {
			rk1 = rk1 ^ rk0;
			s1 = (T4[t1 >> 24] & 0xFF000000) ^ (T4[(t2 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t3 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t0) & 0xFF] & 0x000000FF) ^ rk1;
			if (s1 == ct[1]) {
				rk2 = rk2 ^ rk1;
				s2 = (T4[t2 >> 24] & 0xFF000000) ^ (T4[(t3 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t0 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t1) & 0xFF] & 0x000000FF) ^ rk2;
				if (s2 == ct[2]) {
					rk3 = rk2 ^ rk3;
					s3 = (T4[t3 >> 24] & 0xFF000000) ^ (T4[(t0 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t1 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t2) & 0xFF] & 0x000000FF) ^ rk3;
					if (s3 == ct[3]) {
						printf("! Found key : %08x %08x %08x %08x\n", rk0Init, rk1Init, rk2Init, rk3Init);
						printf("-------------------------------\n");
					}
				}
			}
		}

		// Overflow
		if (rk3Init == MAX_U32) {
			rk2Init++;
		}

		// Create key as 32 bit unsigned integers
		rk3Init++;
	}
}

void aes192ExhaustiveSearch(u32 *pt, u32 *rk, u32 *ct, u32 range) {

	u32 rk0Init, rk1Init, rk2Init, rk3Init, rk4Init, rk5Init;
	rk0Init = rk[0];
	rk1Init = rk[1];
	rk2Init = rk[2];
	rk3Init = rk[3];
	rk4Init = rk[4];
	rk5Init = rk[5];

	u32 pt0Init, pt1Init, pt2Init, pt3Init;
	pt0Init = pt[0];
	pt1Init = pt[1];
	pt2Init = pt[2];
	pt3Init = pt[3];

	for (int rangeCount = 0; rangeCount < range; rangeCount++) {

		// Calculate round keys
		u32 rk0, rk1, rk2, rk3, rk4, rk5;
		rk0 = rk0Init;
		rk1 = rk1Init;
		rk2 = rk2Init;
		rk3 = rk3Init;
		rk4 = rk4Init;
		rk5 = rk5Init;

		// Create plaintext as 32 bit unsigned integers
		u32 s0, s1, s2, s3;
		s0 = pt0Init;
		s1 = pt1Init;
		s2 = pt2Init;
		s3 = pt3Init;

		// First round just XORs input with key.
		s0 = s0 ^ rk0;
		s1 = s1 ^ rk1;
		s2 = s2 ^ rk2;
		s3 = s3 ^ rk3;

		u32 t0, t1, t2, t3;
		u8 rconIndex = 0;
		for (u8 roundCount = 0; roundCount < ROUND_COUNT_192_MIN_1; roundCount++) {
			// Table based round function
			t0 = T0[s0 >> 24] ^ arithmeticRightShift(T0[(s1 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s2 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s3 & 0xFF], SHIFT_3_RIGHT);
			t1 = T0[s1 >> 24] ^ arithmeticRightShift(T0[(s2 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s3 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s0 & 0xFF], SHIFT_3_RIGHT);
			t2 = T0[s2 >> 24] ^ arithmeticRightShift(T0[(s3 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s0 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s1 & 0xFF], SHIFT_3_RIGHT);
			t3 = T0[s3 >> 24] ^ arithmeticRightShift(T0[(s0 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s1 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s2 & 0xFF], SHIFT_3_RIGHT);

			// Add round key
			if (roundCount % 3 == 0) {
				t0 = t0 ^ rk4;
				t1 = t1 ^ rk5;
				// Calculate round key
				u32 temp = rk5;
				rk0 = rk0 ^
					(T4[(temp >> 16) & 0xff] & 0xff000000) ^
					(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
					(T4[(temp      ) & 0xff] & 0x0000ff00) ^
					(T4[(temp >> 24)       ] & 0x000000ff) ^
					RCON32[rconIndex++];
				rk1 = rk1 ^ rk0;
				rk2 = rk2 ^ rk1;
				rk3 = rk3 ^ rk2;
				rk4 = rk4 ^ rk3;
				rk5 = rk5 ^ rk4;

				t2 = t2 ^ rk0;
				t3 = t3 ^ rk1;
			} else if (roundCount % 3 == 1) {
				t0 = t0 ^ rk2;
				t1 = t1 ^ rk3;
				t2 = t2 ^ rk4;
				t3 = t3 ^ rk5;
			} else {
				// Calculate round key
				u32 temp = rk5;
				rk0 = rk0 ^
					(T4[(temp >> 16) & 0xff] & 0xff000000) ^
					(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
					(T4[(temp      ) & 0xff] & 0x0000ff00) ^
					(T4[(temp >> 24)       ] & 0x000000ff) ^
					RCON32[rconIndex++];
				rk1 = rk1 ^ rk0;
				rk2 = rk2 ^ rk1;
				rk3 = rk3 ^ rk2;
				rk4 = rk4 ^ rk3;
				rk5 = rk5 ^ rk4;

				t0 = t0 ^ rk0;
				t1 = t1 ^ rk1;
				t2 = t2 ^ rk2;
				t3 = t3 ^ rk3;
			}

			s0 = t0;
			s1 = t1;
			s2 = t2;
			s3 = t3;
		}

		// Calculate the last round key
		u32 temp = rk5;
		rk0 = rk0 ^
			(T4[(temp >> 16) & 0xff] & 0xff000000) ^
			(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
			(T4[(temp      ) & 0xff] & 0x0000ff00) ^
			(T4[(temp >> 24)       ] & 0x000000ff) ^
			RCON32[rconIndex];

		// Last round uses s-box directly and XORs to produce output.
		s0 = (T4[t0 >> 24] & 0xFF000000) ^ (T4[(t1 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t2 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t3) & 0xFF] & 0x000000FF) ^ rk0;
		if (s0 == ct[0]) {
			rk1 = rk1 ^ rk0;
			s1 = (T4[t1 >> 24] & 0xFF000000) ^ (T4[(t2 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t3 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t0) & 0xFF] & 0x000000FF) ^ rk1;
			if (s1 == ct[1]) {
				rk2 = rk2 ^ rk1;
				s2 = (T4[t2 >> 24] & 0xFF000000) ^ (T4[(t3 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t0 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t1) & 0xFF] & 0x000000FF) ^ rk2;
				if (s2 == ct[2]) {
					rk3 = rk2 ^ rk3;
					s3 = (T4[t3 >> 24] & 0xFF000000) ^ (T4[(t0 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t1 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t2) & 0xFF] & 0x000000FF) ^ rk3;
					if (s3 == ct[3]) {
						printf("! Found key : %08x %08x %08x %08x %08x %08x\n", rk0Init, rk1Init, rk2Init, rk3Init, rk4Init, rk5Init);
						printf("-------------------------------\n");
					}
				}
			}
		}

		// Overflow
		if (rk5Init == MAX_U32) {
			rk4Init++;
		}

		// Create key as 32 bit unsigned integers
		rk5Init++;
	}
}

void aes256ExhaustiveSearch(u32 *pt, u32 *rk, u32 *ct, u32 range) {

	u32 rk0Init, rk1Init, rk2Init, rk3Init, rk4Init, rk5Init, rk6Init, rk7Init;
	rk0Init = rk[0];
	rk1Init = rk[1];
	rk2Init = rk[2];
	rk3Init = rk[3];
	rk4Init = rk[4];
	rk5Init = rk[5];
	rk6Init = rk[6];
	rk7Init = rk[7];

	u32 pt0Init, pt1Init, pt2Init, pt3Init;
	pt0Init = pt[0];
	pt1Init = pt[1];
	pt2Init = pt[2];
	pt3Init = pt[3];

	for (u32 rangeCount = 0; rangeCount < range; rangeCount++) {

		// Calculate round keys
		u32 rk0, rk1, rk2, rk3, rk4, rk5, rk6, rk7;
		rk0 = rk0Init;
		rk1 = rk1Init;
		rk2 = rk2Init;
		rk3 = rk3Init;
		rk4 = rk4Init;
		rk5 = rk5Init;
		rk6 = rk6Init;
		rk7 = rk7Init;

		// Create plaintext as 32 bit unsigned integers
		u32 s0, s1, s2, s3;
		s0 = pt0Init;
		s1 = pt1Init;
		s2 = pt2Init;
		s3 = pt3Init;

		// First round just XORs input with key.
		s0 = s0 ^ rk0;
		s1 = s1 ^ rk1;
		s2 = s2 ^ rk2;
		s3 = s3 ^ rk3;

		u32 t0, t1, t2, t3;
		u8 rconIndex = 0;
		for (u8 roundCount = 0; roundCount < ROUND_COUNT_256_MIN_1; roundCount++) {
			// Table based round function
			t0 = T0[s0 >> 24] ^ arithmeticRightShift(T0[(s1 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s2 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s3 & 0xFF], SHIFT_3_RIGHT);
			t1 = T0[s1 >> 24] ^ arithmeticRightShift(T0[(s2 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s3 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s0 & 0xFF], SHIFT_3_RIGHT);
			t2 = T0[s2 >> 24] ^ arithmeticRightShift(T0[(s3 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s0 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s1 & 0xFF], SHIFT_3_RIGHT);
			t3 = T0[s3 >> 24] ^ arithmeticRightShift(T0[(s0 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s1 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s2 & 0xFF], SHIFT_3_RIGHT);

			// Add round key
			if (roundCount % 2 == 0) {
				t0 = t0 ^ rk4;
				t1 = t1 ^ rk5;
				t2 = t2 ^ rk6;
				t3 = t3 ^ rk7;
			} else {
				// Calculate round key
				u32 temp = rk7;
				rk0 = rk0 ^
					(T4[(temp >> 16) & 0xff] & 0xff000000) ^
					(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
					(T4[(temp      ) & 0xff] & 0x0000ff00) ^
					(T4[(temp >> 24)       ] & 0x000000ff) ^
					RCON32[rconIndex++];
				rk1 = rk1 ^ rk0;
				rk2 = rk2 ^ rk1;
				rk3 = rk3 ^ rk2;
				rk4 = rk4 ^
					(T4[(rk3 >> 24) & 0xff] & 0xff000000) ^
					(T4[(rk3 >> 16) & 0xff] & 0x00ff0000) ^
					(T4[(rk3 >>  8) & 0xff] & 0x0000ff00) ^
					(T4[(rk3      ) & 0xff] & 0x000000ff);
				rk5 = rk5 ^ rk4;
				rk6 = rk6 ^ rk5;
				rk7 = rk7 ^ rk6;

				t0 = t0 ^ rk0;
				t1 = t1 ^ rk1;
				t2 = t2 ^ rk2;
				t3 = t3 ^ rk3;
			}

			s0 = t0;
			s1 = t1;
			s2 = t2;
			s3 = t3;
		}

		// Calculate the last round key
		u32 temp = rk7;
		rk0 = rk0 ^
			(T4[(temp >> 16) & 0xff] & 0xff000000) ^
			(T4[(temp >>  8) & 0xff] & 0x00ff0000) ^
			(T4[(temp      ) & 0xff] & 0x0000ff00) ^
			(T4[(temp >> 24)       ] & 0x000000ff) ^
			RCON32[rconIndex++];

		// Last round uses s-box directly and XORs to produce output.
		s0 = (T4[t0 >> 24] & 0xFF000000) ^ (T4[(t1 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t2 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t3) & 0xFF] & 0x000000FF) ^ rk0;
		if (s0 == ct[0]) {
			rk1 = rk1 ^ rk0;
			s1 = (T4[t1 >> 24] & 0xFF000000) ^ (T4[(t2 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t3 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t0) & 0xFF] & 0x000000FF) ^ rk1;
			if (s1 == ct[1]) {
				rk2 = rk2 ^ rk1;
				s2 = (T4[t2 >> 24] & 0xFF000000) ^ (T4[(t3 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t0 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t1) & 0xFF] & 0x000000FF) ^ rk2;
				if (s2 == ct[2]) {
					rk3 = rk2 ^ rk3;
					s3 = (T4[t3 >> 24] & 0xFF000000) ^ (T4[(t0 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t1 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t2) & 0xFF] & 0x000000FF) ^ rk3;
					if (s3 == ct[3]) {
						printf("! Found key : %08x %08x %08x %08x %08x %08x %08x %08x\n", rk0Init, rk1Init, rk2Init, rk3Init, rk4Init, rk5Init, rk6Init, rk7Init);
						printf("-------------------------------\n");
					}
				}
			}
		}

		// Overflow
		if (rk7Init == MAX_U32) {
			rk6Init++;
		}

		// Create key as 32 bit unsigned integers
		rk7Init++;
	}
}

void aes128Ctr(u32 *pt, u32 *rk, u32 *ct, u32 range) {

	u32 ctIndex = 0;
	u32 pt0Init, pt1Init, pt2Init, pt3Init;
	u32 s0, s1, s2, s3;
	pt0Init = pt[0];
	pt1Init = pt[1];
	pt2Init = pt[2];
	pt3Init = pt[3];

	for (u32 rangeCount = 0; rangeCount < range; rangeCount++) {

		// Create plaintext as 32 bit unsigned integers
		s0 = pt0Init;
		s1 = pt1Init;
		s2 = pt2Init;
		s3 = pt3Init;

		// First round just XORs input with key.
		s0 = s0 ^ rk[0];
		s1 = s1 ^ rk[1];
		s2 = s2 ^ rk[2];
		s3 = s3 ^ rk[3];

		u32 t0, t1, t2, t3;
		for (u8 roundCount = 0; roundCount < ROUND_COUNT_128_MIN_1; roundCount++) {

			// Table based round function
			u32 rkStart = roundCount * 4 + 4;
			t0 = T0[s0 >> 24] ^ arithmeticRightShift(T0[(s1 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s2 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s3 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart];
			t1 = T0[s1 >> 24] ^ arithmeticRightShift(T0[(s2 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s3 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s0 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 1];
			t2 = T0[s2 >> 24] ^ arithmeticRightShift(T0[(s3 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s0 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s1 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 2];
			t3 = T0[s3 >> 24] ^ arithmeticRightShift(T0[(s0 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s1 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s2 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 3];

			s0 = t0;
			s1 = t1;
			s2 = t2;
			s3 = t3;

		}

		// Calculate the last round key
		// Last round uses s-box directly and XORs to produce output.
		s0 = (T4[t0 >> 24] & 0xFF000000) ^ (T4[(t1 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t2 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t3) & 0xFF] & 0x000000FF) ^ rk[40];
		s1 = (T4[t1 >> 24] & 0xFF000000) ^ (T4[(t2 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t3 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t0) & 0xFF] & 0x000000FF) ^ rk[41];
		s2 = (T4[t2 >> 24] & 0xFF000000) ^ (T4[(t3 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t0 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t1) & 0xFF] & 0x000000FF) ^ rk[42];
		s3 = (T4[t3 >> 24] & 0xFF000000) ^ (T4[(t0 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t1 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t2) & 0xFF] & 0x000000FF) ^ rk[43];

		// Overflow
		if (pt3Init == MAX_U32) {
			pt2Init++;
		}

		pt3Init++;

		if (rangeCount == 0) {
			printf("First Ciphertext : %08x %08x %08x %08x\n", s0, s1, s2, s3);
		}

		// Allocate ciphertext
		if (ct != NULL) {
			ct[ctIndex++] = s0;
			ct[ctIndex++] = s1;
			ct[ctIndex++] = s2;
			ct[ctIndex++] = s3;
		}
	}
}

void aes192Ctr(u32 *pt, u32 *rk, u32 *ct, u32 range) {

	u32 ctIndex = 0;
	u32 pt0Init, pt1Init, pt2Init, pt3Init;
	u32 s0, s1, s2, s3;
	pt0Init = pt[0];
	pt1Init = pt[1];
	pt2Init = pt[2];
	pt3Init = pt[3];

	for (u32 rangeCount = 0; rangeCount < range; rangeCount++) {

		// Create plaintext as 32 bit unsigned integers
		s0 = pt0Init;
		s1 = pt1Init;
		s2 = pt2Init;
		s3 = pt3Init;

		// First round just XORs input with key.
		s0 = s0 ^ rk[0];
		s1 = s1 ^ rk[1];
		s2 = s2 ^ rk[2];
		s3 = s3 ^ rk[3];

		u32 t0, t1, t2, t3;
		for (u8 roundCount = 0; roundCount < ROUND_COUNT_192_MIN_1; roundCount++) {

			// Table based round function
			u32 rkStart = roundCount * 4 + 4;
			t0 = T0[s0 >> 24] ^ arithmeticRightShift(T0[(s1 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s2 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s3 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart];
			t1 = T0[s1 >> 24] ^ arithmeticRightShift(T0[(s2 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s3 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s0 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 1];
			t2 = T0[s2 >> 24] ^ arithmeticRightShift(T0[(s3 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s0 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s1 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 2];
			t3 = T0[s3 >> 24] ^ arithmeticRightShift(T0[(s0 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s1 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s2 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 3];

			s0 = t0;
			s1 = t1;
			s2 = t2;
			s3 = t3;

		}

		// Calculate the last round key
		// Last round uses s-box directly and XORs to produce output.
		s0 = (T4[t0 >> 24] & 0xFF000000) ^ (T4[(t1 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t2 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t3) & 0xFF] & 0x000000FF) ^ rk[48];
		s1 = (T4[t1 >> 24] & 0xFF000000) ^ (T4[(t2 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t3 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t0) & 0xFF] & 0x000000FF) ^ rk[49];
		s2 = (T4[t2 >> 24] & 0xFF000000) ^ (T4[(t3 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t0 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t1) & 0xFF] & 0x000000FF) ^ rk[50];
		s3 = (T4[t3 >> 24] & 0xFF000000) ^ (T4[(t0 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t1 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t2) & 0xFF] & 0x000000FF) ^ rk[51];

		// Overflow
		if (pt3Init == MAX_U32) {
			pt2Init++;
		}

		// Create key as 32 bit unsigned integers
		pt3Init++;

		if (rangeCount == 0) {
			printf("First Ciphertext : %08x %08x %08x %08x\n", s0, s1, s2, s3);
		}

		// Allocate ciphertext
		if (ct != NULL) {
			ct[ctIndex++] = s0;
			ct[ctIndex++] = s1;
			ct[ctIndex++] = s2;
			ct[ctIndex++] = s3;
		}
	}
}

void aes256Ctr(u32 *pt, u32 *rk, u32 *ct, u32 range) {

	u32 ctIndex = 0;
	u32 pt0Init, pt1Init, pt2Init, pt3Init;
	u32 s0, s1, s2, s3;
	pt0Init = pt[0];
	pt1Init = pt[1];
	pt2Init = pt[2];
	pt3Init = pt[3];

	for (u32 rangeCount = 0; rangeCount < range; rangeCount++) {

		// Create plaintext as 32 bit unsigned integers
		s0 = pt0Init;
		s1 = pt1Init;
		s2 = pt2Init;
		s3 = pt3Init;

		// First round just XORs input with key.
		s0 = s0 ^ rk[0];
		s1 = s1 ^ rk[1];
		s2 = s2 ^ rk[2];
		s3 = s3 ^ rk[3];

		u32 t0, t1, t2, t3;
		for (u8 roundCount = 0; roundCount < ROUND_COUNT_256_MIN_1; roundCount++) {

			// Table based round function
			u32 rkStart = roundCount * 4 + 4;
			t0 = T0[s0 >> 24] ^ arithmeticRightShift(T0[(s1 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s2 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s3 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart];
			t1 = T0[s1 >> 24] ^ arithmeticRightShift(T0[(s2 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s3 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s0 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 1];
			t2 = T0[s2 >> 24] ^ arithmeticRightShift(T0[(s3 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s0 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s1 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 2];
			t3 = T0[s3 >> 24] ^ arithmeticRightShift(T0[(s0 >> 16) & 0xFF], SHIFT_1_RIGHT) ^ arithmeticRightShift(T0[(s1 >> 8) & 0xFF], SHIFT_2_RIGHT) ^ arithmeticRightShift(T0[s2 & 0xFF], SHIFT_3_RIGHT) ^ rk[rkStart + 3];

			s0 = t0;
			s1 = t1;
			s2 = t2;
			s3 = t3;

		}

		// Calculate the last round key
		// Last round uses s-box directly and XORs to produce output.
		s0 = (T4[t0 >> 24] & 0xFF000000) ^ (T4[(t1 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t2 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t3) & 0xFF] & 0x000000FF) ^ rk[56];
		s1 = (T4[t1 >> 24] & 0xFF000000) ^ (T4[(t2 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t3 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t0) & 0xFF] & 0x000000FF) ^ rk[57];
		s2 = (T4[t2 >> 24] & 0xFF000000) ^ (T4[(t3 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t0 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t1) & 0xFF] & 0x000000FF) ^ rk[58];
		s3 = (T4[t3 >> 24] & 0xFF000000) ^ (T4[(t0 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t1 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t2) & 0xFF] & 0x000000FF) ^ rk[59];

		// Overflow
		if (pt3Init == MAX_U32) {
			pt2Init++;
		}

		// Create key as 32 bit unsigned integers
		pt3Init++;

		if (rangeCount == 0) {
			printf("First Ciphertext : %08x %08x %08x %08x\n", s0, s1, s2, s3);
		}

		// Allocate ciphertext
		if (ct != NULL) {
			ct[ctIndex++] = s0;
			ct[ctIndex++] = s1;
			ct[ctIndex++] = s2;
			ct[ctIndex++] = s3;
		}
	}
}

void mainAes128ExhaustiveSearch() {
	printf("---------------------------------------------------------------------------\n");
	printf("      ########## AES - 128 Exhaustive Search Implementation ##########     \n");
	printf("---------------------------------------------------------------------------\n\n");

	u32 pt[AES_128_KEY_LEN_INT], ct[AES_128_KEY_LEN_INT], rk[AES_128_KEY_LEN_INT];
	pt[0] = 0x3243F6A8U;
	pt[1] = 0x885A308DU;
	pt[2] = 0x313198A2U;
	pt[3] = 0xE0370734U;

	ct[0] = 0x3925841DU;
	ct[1] = 0x02DC09FBU;
	ct[2] = 0xDC118597U;
	ct[3] = 0x196A0B32U;

	rk[0] = 0x2B7E1516U;
	rk[1] = 0x28AED2A6U;
	rk[2] = 0xABF71588U;
	rk[3] = 0x09CF4F3CU;

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Plaintext     : %08x %08x %08x %08x\n", pt[0], pt[1], pt[2], pt[3]);
	printf("Ciphertext    : %08x %08x %08x %08x\n", ct[0], ct[1], ct[2], ct[3]);
	printf("Initial Key   : %08x %08x %08x %08x\n", rk[0], rk[1], rk[2], rk[3]);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aes128ExhaustiveSearch(pt, rk, ct, range);

	printf("-------------------------------\n");
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	printf("-------------------------------\n");
}

void mainAes192ExhaustiveSearch() {
	printf("---------------------------------------------------------------------------\n");
	printf("      ########## AES - 192 Exhaustive Search Implementation ##########     \n");
	printf("---------------------------------------------------------------------------\n\n");

	u32 pt[AES_128_KEY_LEN_INT], ct[AES_128_KEY_LEN_INT], rk[AES_192_KEY_LEN_INT];
	pt[0] = 0x6BC1BEE2U;
	pt[1] = 0x2E409F96U;
	pt[2] = 0xE93D7E11U;
	pt[3] = 0x7393172AU;

	ct[0] = 0xBD334F1DU;
	ct[1] = 0x6E45F25FU;
	ct[2] = 0xF712A214U;
	ct[3] = 0x571FA5CCU;

	rk[0] = 0x8e73b0f7U;
	rk[1] = 0xda0e6452U;
	rk[2] = 0xc810f32bU;
	rk[3] = 0x809079e5U;
	rk[4] = 0x62f8ead2U;
	rk[5] = 0x522c6b7bU;

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Plaintext     : %08x %08x %08x %08x\n", pt[0], pt[1], pt[2], pt[3]);
	printf("Ciphertext    : %08x %08x %08x %08x\n", ct[0], ct[1], ct[2], ct[3]);
	printf("Initial Key   : %08x %08x %08x %08x %08x %08x\n", rk[0], rk[1], rk[2], rk[3], rk[4], rk[5]);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aes192ExhaustiveSearch(pt, rk, ct, range);

	printf("-------------------------------\n");
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	printf("-------------------------------\n");
}

void mainAes256ExhaustiveSearch() {
	printf("---------------------------------------------------------------------------\n");
	printf("      ########## AES - 256 Exhaustive Search Implementation ##########     \n");
	printf("---------------------------------------------------------------------------\n\n");

	u32 pt[AES_128_KEY_LEN_INT], ct[AES_128_KEY_LEN_INT], rk[AES_256_KEY_LEN_INT];
	pt[0] = 0x6BC1BEE2U;
	pt[1] = 0x2E409F96U;
	pt[2] = 0xE93D7E11U;
	pt[3] = 0x7393172AU;
	
	ct[0] = 0xF3EED1BDU;
	ct[1] = 0xB5D2A03CU;
	ct[2] = 0x064B5A7EU;
	ct[3] = 0x3DB181F8U;

	rk[0] = 0x603deb10U;
	rk[1] = 0x15ca71beU;
	rk[2] = 0x2b73aef0U;
	rk[3] = 0x857d7781U;
	rk[4] = 0x1f352c07U;
	rk[5] = 0x3b6108d7U;
	rk[6] = 0x2d9810a3U;
	rk[7] = 0x0914dff4U;

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Plaintext     : %08x %08x %08x %08x\n", pt[0], pt[1], pt[2], pt[3]);
	printf("Ciphertext    : %08x %08x %08x %08x\n", ct[0], ct[1], ct[2], ct[3]);
	printf("Initial Key   : %08x %08x %08x %08x %08x %08x\n", rk[0], rk[1], rk[2], rk[3], rk[4], rk[5], rk[6], rk[7]);
	printf("-------------------------------\n");

	clock_t beginTime = clock();

	aes256ExhaustiveSearch(pt, rk, ct, range);

	printf("-------------------------------\n");
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	printf("-------------------------------\n");
}

void mainAes128Ctr() {
	printf("---------------------------------------------------------------------------\n");
	printf("         ########## AES - 128 Counter Mode Implementation ##########       \n");
	printf("---------------------------------------------------------------------------\n\n");

	u32 pt[AES_128_KEY_LEN_INT], ct[AES_128_KEY_LEN_INT], rk[AES_128_KEY_LEN_INT];
	pt[0] = 0x3243F6A8U;
	pt[1] = 0x885A308DU;
	pt[2] = 0x313198A2U;
	pt[3] = 0xE0370734U;

	rk[0] = 0x2B7E1516U;
	rk[1] = 0x28AED2A6U;
	rk[2] = 0xABF71588U;
	rk[3] = 0x09CF4F3CU;

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Plaintext     : %08x %08x %08x %08x\n", pt[0], pt[1], pt[2], pt[3]);
	printf("Initial Key   : %08x %08x %08x %08x\n", rk[0], rk[1], rk[2], rk[3]);
	printf("-------------------------------\n");

	// Prepare round keys
	u32 *roundKeys = new u32[AES_128_KEY_SIZE_INT];
	aesKeyExpansion(rk, roundKeys, AES_128_KEY_LEN_INT);

	clock_t beginTime = clock();
	
	aes128Ctr(pt, roundKeys, NULL, range);

	printf("-------------------------------\n");
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	printf("-------------------------------\n");
}

void mainAes192Ctr() {
	printf("---------------------------------------------------------------------------\n");
	printf("         ########## AES - 192 Counter Mode Implementation ##########       \n");
	printf("---------------------------------------------------------------------------\n\n");

	u32 pt[AES_128_KEY_LEN_INT], rk[AES_192_KEY_LEN_INT];
	pt[0] = 0x6BC1BEE2U;
	pt[1] = 0x2E409F96U;
	pt[2] = 0xE93D7E11U;
	pt[3] = 0x7393172AU;

	rk[0] = 0x8e73b0f7U;
	rk[1] = 0xda0e6452U;
	rk[2] = 0xc810f32bU;
	rk[3] = 0x809079e5U;
	rk[4] = 0x62f8ead2U;
	rk[5] = 0x522c6b7bU;

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Plaintext     : %08x %08x %08x %08x\n", pt[0], pt[1], pt[2], pt[3]);
	printf("Initial Key   : %08x %08x %08x %08x %08x %08x\n", rk[0], rk[1], rk[2], rk[3], rk[4], rk[5]);
	printf("-------------------------------\n");

	// Prepare round keys
	u32 *roundKeys = new u32[AES_192_KEY_SIZE_INT];
	aesKeyExpansion(rk, roundKeys, AES_192_KEY_LEN_INT);

	clock_t beginTime = clock();

	aes192Ctr(pt, roundKeys, NULL, range);

	printf("-------------------------------\n");
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	printf("-------------------------------\n");
}

void mainAes256Ctr() {
	printf("---------------------------------------------------------------------------\n");
	printf("         ########## AES - 256 Counter Mode Implementation ##########       \n");
	printf("---------------------------------------------------------------------------\n\n");

	u32 pt[AES_128_KEY_LEN_INT], rk[AES_256_KEY_LEN_INT];
	pt[0] = 0x6BC1BEE2U;
	pt[1] = 0x2E409F96U;
	pt[2] = 0xE93D7E11U;
	pt[3] = 0x7393172AU;

	rk[0] = 0x603deb10U;
	rk[1] = 0x15ca71beU;
	rk[2] = 0x2b73aef0U;
	rk[3] = 0x857d7781U;
	rk[4] = 0x1f352c07U;
	rk[5] = 0x3b6108d7U;
	rk[6] = 0x2d9810a3U;
	rk[7] = 0x0914dff4U;

	u32 p = 25;
	double keyRange = pow(2, p);
	u32 range = ceil(keyRange);
	printf("-------------------------------\n");
	printf("Key Range (power)  : %d\n", p);
	printf("Total encryptions  : %d\n", range);
	printf("-------------------------------\n");
	printf("Plaintext     : %08x %08x %08x %08x\n", pt[0], pt[1], pt[2], pt[3]);
	printf("Initial Key   : %08x %08x %08x %08x %08x %08x\n", rk[0], rk[1], rk[2], rk[3], rk[4], rk[5], rk[6], rk[7]);
	printf("-------------------------------\n");

	// Prepare round keys
	u32 *roundKeys = new u32[AES_256_KEY_SIZE_INT];
	aesKeyExpansion(rk, roundKeys, AES_256_KEY_LEN_INT);

	clock_t beginTime = clock();

	aes256Ctr(pt, roundKeys, NULL, range);

	printf("-------------------------------\n");
	printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
	printf("-------------------------------\n");
}

void mainAesFileEncryption() {
	printf("---------------------------------------------------------------------------\n");
	printf("           ########## AES File Encryption Implementation ##########        \n");
	printf("---------------------------------------------------------------------------\n\n");

	// Options
	int chunkSize = 1024;
	const string filePath = "C://file-encryption-test//william3.mp4";
	int keyLen = AES_128_KEY_LEN_INT;

	u32 pt[AES_128_KEY_LEN_INT], rk128[AES_128_KEY_LEN_INT], rk192[AES_192_KEY_LEN_INT], rk256[AES_256_KEY_LEN_INT];

	pt[0] = 0x3243F6A8U;
	pt[1] = 0x885A308DU;
	pt[2] = 0x313198A2U;
	pt[3] = 0x00000000U;

	rk128[0] = 0x2B7E1516U;
	rk128[1] = 0x28AED2A6U;
	rk128[2] = 0xABF71588U;
	rk128[3] = 0x09CF4F3CU;

	rk192[0] = 0x8e73b0f7U;
	rk192[1] = 0xda0e6452U;
	rk192[2] = 0xc810f32bU;
	rk192[3] = 0x809079e5U;
	rk192[4] = 0x62f8ead2U;
	rk192[5] = 0x522c6b7bU;

	rk256[0] = 0x603deb10U;
	rk256[1] = 0x15ca71beU;
	rk256[2] = 0x2b73aef0U;
	rk256[3] = 0x857d7781U;
	rk256[4] = 0x1f352c07U;
	rk256[5] = 0x3b6108d7U;
	rk256[6] = 0x2d9810a3U;
	rk256[7] = 0x0914dff4U;

	fstream fileIn(filePath, fstream::in | fstream::binary);
	if (fileIn) {
		// Get file size
		fileIn.seekg(0, fileIn.end);
		int fileSize = fileIn.tellg();
		fileIn.seekg(0, fileIn.beg);
		printf("File: %s\n", filePath.c_str());
		printf("Size in bytes: %d\n", fileSize);
		printf("-------------------------------\n");

		// Calculate encryption boundary
		double totalBlockSize = (double)fileSize / (AES_128_KEY_LEN_INT * U32_SIZE);
		u32 encryptionCount = ceil(totalBlockSize);
		u32 ciphertextSize = encryptionCount * U32_SIZE;

		printf("Total encryptions             : %d\n", encryptionCount);
		printf("Total encryptions in byte     : %d\n", ciphertextSize);
		printf("-------------------------------\n");
		u32 *rk;
		int keySize;
		if (keyLen == AES_128_KEY_LEN_INT) {
			rk = rk128;
			keySize = AES_128_KEY_SIZE_INT;
			printf("Initial Key (%d byte)  : %08x %08x %08x %08x\n", AES_128_KEY_LEN_INT * U32_SIZE, rk[0], rk[1], rk[2], rk[3]);
		} else if (keyLen == AES_192_KEY_LEN_INT) {
			rk = rk192;
			keySize = AES_192_KEY_SIZE_INT;
			printf("Initial Key (%d byte)  : %08x %08x %08x %08x %08x %08x\n", AES_192_KEY_LEN_INT * U32_SIZE, rk[0], rk[1], rk[2], rk[3], rk[4], rk[5]);
		} else if (keyLen == AES_256_KEY_LEN_INT) {
			rk = rk256;
			keySize = AES_256_KEY_SIZE_INT;
			printf("Initial Key (%d byte)  : %08x %08x %08x %08x %08x %08x %08x %08x\n", AES_256_KEY_LEN_INT * U32_SIZE, rk[0], rk[1], rk[2], rk[3], rk[4], rk[5], rk[6], rk[7]);
		} else {
			return;
		}
		printf("Initial Counter        : %08x %08x %08x %08x\n", pt[0], pt[1], pt[2], pt[3]);
		printf("-------------------------------\n");

		// Prepare round keys
		u32 *roundKeys = new u32[keySize];
		aesKeyExpansion(rk, roundKeys, keyLen);
		// Allocate ciphertext
		u32 *ct = new u32[ciphertextSize];

		clock_t beginTime = clock();

		if (keyLen == AES_128_KEY_LEN_INT) {
			aes128Ctr(pt, roundKeys, ct, encryptionCount);
		} else if (keyLen == AES_192_KEY_LEN_INT) {
			aes192Ctr(pt, roundKeys, ct, encryptionCount);
		} else if (keyLen == AES_256_KEY_LEN_INT) {
			aes256Ctr(pt, roundKeys, ct, encryptionCount);
		}

		printf("-------------------------------\n");
		printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);
		printf("-------------------------------\n");

		beginTime = clock();
		// Open output file
		const std::string outFilePath = filePath + "_ENC";
		printf("Encrypted File: %s\n", outFilePath.c_str());
		printf("-------------------------------\n");
		std::fstream fileOut(outFilePath, std::fstream::out | std::fstream::binary);
		u32 cipherTextIndex = 0;
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
			for (int bufferIndex = 0; bufferIndex < readByte; bufferIndex++) {
				// Process 4 byte as integers
				int bufferIntIndex = (bufferIndex + 1) % U32_SIZE;
				if (bufferIntIndex == 0) {
					// Change 4 byte to int
					readInt = 0;
					readInt |= (0x000000FF & buffer[bufferIndex - 3]) << 24;
					readInt |= (0x000000FF & buffer[bufferIndex - 2]) << 16;
					readInt |= (0x000000FF & buffer[bufferIndex - 1]) << 8;
					readInt |= (0x000000FF & buffer[bufferIndex]);
					// XOR with ciphertext
					readInt ^= ct[cipherTextIndex++];
					// TODO: bug-fix -> create ctIndex and increment here 
					// Change 4 byte back to char
					buffer[bufferIndex - 3] = readInt >> 24;
					buffer[bufferIndex - 2] = readInt >> 16;
					buffer[bufferIndex - 1] = readInt >> 8;
					buffer[bufferIndex] = readInt;
				} else if (bufferIndex == readByte - 1) {
					// Change bufferIntIndex byte to int
					readInt = 0;
					for (int extraByteIndex = 0; extraByteIndex < bufferIntIndex; extraByteIndex++) {
						readInt |= (0x000000FF & buffer[bufferIndex - bufferIntIndex + extraByteIndex + 1]) << ((U32_SIZE - 1 - extraByteIndex) * 8);
					}
					// XOR with ciphertext
					readInt ^= ct[cipherTextIndex++];
					// Change bufferIntIndex byte back to char
					for (int extraByteIndex = 0; extraByteIndex < bufferIntIndex; extraByteIndex++) {
						buffer[bufferIndex - bufferIntIndex + extraByteIndex + 1] = readInt >> (U32_SIZE - 1 - extraByteIndex) * 8;
					}
				}
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
		delete[] ct;
		fileOut.close();
	} else {
		printf("File could not be opened: %s\n", filePath.c_str());
	}

}