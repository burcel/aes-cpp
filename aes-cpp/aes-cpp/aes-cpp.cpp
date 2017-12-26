#include "stdafx.h"
#include <iostream>
#include <string>
//#include "aes-s-box.h"

using namespace std;

typedef uint8_t u8;
int ROUND_COUNT = 10;
bool VERBOSE = false;

// Function declarations 
void free2dArray(u8** arr, int row);
void printHex(u8 ent);
void printHex(u8* key, int length);
void printMatrix(u8** key);
void oneRoundKeySchedule(u8** key, int roundCount);
u8** oneRoundKeyScheduleInv(u8** key);
void xorBytes(u8 ent1[4], u8 ent2[4]);
void xorBytes(u8* ent1, u8* ent2, int length);
void xorBytes(u8** ent1, u8** ent2);
void subBytes(u8** inp);
void subBytesInv(u8** inp);
u8** matrixFromInput(u8 ent[16]);
u8* inputFromMatrix(u8** ent);
void mirror(u8** ent);
void shiftBytes(u8** inp);
void shiftBytesInv(u8** inp);
void mixColumns(u8** inp);
void mixColumnsInv(u8** inp);
u8 galoisMultiplication(u8 left, u8 multiplier);
u8 galoisCalculation(u8 left);
u8* encrypt(u8 plainTextInput[16], u8 keyInput[16]);
u8* decrypt(u8 plainTextInput[16], u8 keyInput[16]);
void incrementCounter(u8 counter[16], int index);
void encryptWithCtr(u8 key[16], u8 plainTextList[4][16], u8 counter[16]);
void decryptWithCtr(u8 key[16], u8 cipherTextList[4][16], u8 counter[16]);

u8 S_BOX[256] = {
	0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
	0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
	0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
	0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
	0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
	0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
	0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
	0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
	0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
	0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
	0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
	0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
	0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
	0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
};

u8 S_BOX_INV[256] = {
	0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
	0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
	0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
	0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
	0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
	0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
	0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
	0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
	0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
	0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
	0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
	0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
	0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
	0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
	0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
	0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
};

u8 RCON[256] = {
	0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
	0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
	0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
	0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
	0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
	0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
	0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b,
	0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
	0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
	0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20,
	0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35,
	0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
	0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
	0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63,
	0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
	0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d
};

u8 M[4][4] = {
	{0x02, 0x03, 0x01, 0x01},
	{0x01, 0x02, 0x03, 0x01},
	{0x01, 0x01, 0x02, 0x03},
	{0x03, 0x01, 0x01, 0x02}
};

u8 M_INV[4][4] = {
	{ 0x0E, 0x0B, 0x0D, 0x09 },
	{ 0x09, 0x0E, 0x0B, 0x0D },
	{ 0x0D, 0x09, 0x0E, 0x0B },
	{ 0x0B, 0x0D, 0x09, 0x0E }
};

int main() {
	cout << "-- AES 128 bits --" << endl;

	//u8 plainTextInput[16] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };  // 128bits
	//u8 cipherTextInput[16] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };  // 128bits
	//u8 keyInput[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };  // 128bits

	//u8 plainTextInput[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };  // 128bits
	//u8 cipherTextInput[16] = { 0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A };  // 128bits
	//u8 keyInput[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };  // 128bits

	//encrypt(plainTextInput, keyInput);
	//decrypt(cipherTextInput, keyInput);

	u8 keyInput[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };  // 128bits
	u8 counter[16] = { 0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7, 0xF8, 0xF9, 0xFA, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF };  // 128bits
	u8 plainTextInputList[4][16] = {
		{ 0x6B, 0xC1, 0xBE, 0xE2, 0x2E, 0x40, 0x9F, 0x96, 0xE9, 0x3D, 0x7E, 0x11, 0x73, 0x93, 0x17, 0x2A },
		{ 0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51 },
		{ 0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef },
		{ 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 }
	};

	u8 cipherTextInputList[4][16] = {
		{ 0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26, 0x1b, 0xef, 0x68, 0x64, 0x99, 0x0d, 0xb6, 0xce },
		{ 0x98, 0x06, 0xf6, 0x6b, 0x79, 0x70, 0xfd, 0xff, 0x86, 0x17, 0x18, 0x7b, 0xb9, 0xff, 0xfd, 0xff },
		{ 0x5a, 0xe4, 0xdf, 0x3e, 0xdb, 0xd5, 0xd3, 0x5e, 0x5b, 0x4f, 0x09, 0x02, 0x0d, 0xb0, 0x3e, 0xab },
		{ 0x1e, 0x03, 0x1d, 0xda, 0x2f, 0xbe, 0x03, 0xd1, 0x79, 0x21, 0x70, 0xa0, 0xf3, 0x00, 0x9c, 0xee }
	};

	//encryptWithCtr(keyInput, plainTextInputList, counter);
	decryptWithCtr(keyInput, cipherTextInputList, counter);

	return 0;
}

void encryptWithCtr(u8 key[16], u8 plainTextList[4][16], u8 counter[16]) {
	cout << "-- CTR mode encryption --" << endl;
	cout << "Key: " << endl;
	printHex(key, 16);

	cout << "Initial Counter: " << endl;
	printHex(counter, 16);

	u8* output = NULL;

	for (int i = 0; i < 4; i++) {
		cout << "Block #" << i + 1 << endl;
		cout << "Input Block: " << endl;
		printHex(counter, 16);

		output = encrypt(counter, key);
		cout << "Output Block: " << endl;
		printHex(output, 16);

		cout << "Plaintext: " << endl;
		printHex(plainTextList[i], 16);

		xorBytes(output, plainTextList[i], 16);

		cout << "Ciphertext: " << endl;
		printHex(output, 16);

		incrementCounter(counter, 15);
	}

	delete[] output;
}

void decryptWithCtr(u8 key[16], u8 cipherTextList[4][16], u8 counter[16]) {
	cout << "-- CTR mode decryption --" << endl;
	cout << "Key: " << endl;
	printHex(key, 16);

	cout << "Initial Counter: " << endl;
	printHex(counter, 16);

	u8* output = NULL;

	for (int i = 0; i < 4; i++) {
		cout << "Block #" << i + 1 << endl;
		cout << "Input Block: " << endl;
		printHex(counter, 16);

		output = encrypt(counter, key);
		cout << "Output Block: " << endl;
		printHex(output, 16);

		cout << "Ciphertext: " << endl;
		printHex(cipherTextList[i], 16);

		xorBytes(output, cipherTextList[i], 16);

		cout << "Plaintext: " << endl;
		printHex(output, 16);

		incrementCounter(counter, 15);
	}

	delete[] output;
}

void incrementCounter(u8 counter[16], int index) {
	if (index == 0) {
		return;
	}
	if (counter[index] == 0xFF) {
		counter[index] = 0x00;
		index--;
		if (counter[index] == 0xFF) {
			incrementCounter(counter, index);
		} else {
			counter[index]++;
		}
	} else {
		counter[index]++;
	}
}

u8* encrypt(u8 plainTextInput[16], u8 keyInput[16]) {
	//cout << "-- Encryption --" << endl;
	//cout << "Initial input: " << endl;
	//printHex(plainTextInput, 16);

	//cout << "Initial key: " << endl;
	//printHex(keyInput, 16);

	u8** plainText = matrixFromInput(plainTextInput);
	u8** key = matrixFromInput(keyInput);

	//cout << "## Round: " << 0 << endl;
	//cout << "   0. Add Round Key" << endl;
	xorBytes(plainText, key);
	//printMatrix(plainText);

	for (int roundCount = 1; roundCount <= ROUND_COUNT; roundCount++) {
		//cout << "## Round: " << roundCount << endl;

		//cout << "   1. SubBytes" << endl;
		subBytes(plainText);
		//printMatrix(plainText);

		//cout << "   2. Shift Row" << endl;
		shiftBytes(plainText);
		//printMatrix(plainText);

		if (roundCount != ROUND_COUNT) {
			//cout << "   3. Mix Columns" << endl;
			mixColumns(plainText);
			//printMatrix(plainText);
		}

		//cout << "   4. Add Round Key" << endl;
		oneRoundKeySchedule(key, roundCount);
		xorBytes(plainText, key);
		//printMatrix(plainText);
		//cout << "   4. Round Key" << endl;
		//printMatrix(key);

	}

	//cout << "Ciphertext: " << endl;
	u8* cipherText = inputFromMatrix(plainText);
	//printHex(cipherText, 16);

	delete[] plainText;
	delete[] key;

	return cipherText;
}

u8* decrypt(u8 cipherTextInput[16], u8 keyInput[16]) {

	//cout << "-- Decryption --" << endl;
	//cout << "Initial input: " << endl;
	//printHex(cipherTextInput, 16);

	//cout << "Initial key: " << endl;
	//printHex(keyInput, 16);

	u8** cipherText = matrixFromInput(cipherTextInput);
	u8** key = matrixFromInput(keyInput);

	//cout << "###############" << endl;
	u8** inverseKeyList = oneRoundKeyScheduleInv(key);
	//for (int ii = 0; ii <= ROUND_COUNT; ii++) {
	//	cout << "Round: " << ii << endl;
	//	printHex(inverseKeyList[ii], 16);
	//}

	//cout << "## Round: " << 0 << endl;
	u8** roundKey = matrixFromInput((inverseKeyList[0]));
	//cout << 0 << "  Round Key" << endl;
	//printMatrix(roundKey);
	//printHex(inputFromMatrix(roundKey), 16);
	//cout << 0 << " Add Round Key" << endl;
	xorBytes(cipherText, roundKey);
	//printMatrix(cipherText);
	//printHex(inputFromMatrix(cipherText), 16);

	for (int roundCount = 1; roundCount <= ROUND_COUNT; roundCount++) {
		//cout << "## Round: " << roundCount << endl;

		//cout << roundCount << " SubBytes" << endl;
		subBytesInv(cipherText);
		//printMatrix(cipherText);
		//printHex(inputFromMatrix(cipherText), 16);

		//cout << roundCount << " Shift Row" << endl;
		shiftBytesInv(cipherText);
		//printMatrix(cipherText);
		//printHex(inputFromMatrix(cipherText), 16);

		//cout << roundCount << " Round Key" << endl;
		u8** roundKey = matrixFromInput(inverseKeyList[roundCount]);
		//printMatrix(roundKey);
		//printHex(inverseKeyList[roundCount], 16);

		//cout << roundCount << " Add Round Key" << endl;
		xorBytes(cipherText, roundKey);
		//printMatrix(cipherText);
		//printHex(inputFromMatrix(cipherText), 16);

		if (roundCount != ROUND_COUNT) {
			//cout << roundCount << " Mix Columns" << endl;
			mixColumnsInv(cipherText);
			//printMatrix(cipherText);
			//printHex(inputFromMatrix(cipherText), 16);
		}
	}

	//cout << "Plaintext: " << endl;
	u8* plainText = inputFromMatrix(cipherText);
	//printHex(plainText, 16);

	free2dArray(roundKey, 4);
	free2dArray(cipherText, 4);
	free2dArray(key, 4);
	free2dArray(inverseKeyList, ROUND_COUNT + 1);

	return plainText;
}

// Return 4x4 matrix from 16 byte array
u8** matrixFromInput(u8 ent[16]) {
	u8** matrix = new u8*[4];
	for (int i = 0; i < 4; i++) {
		matrix[i] = new u8[4];
		for (int j = 0; j < 4; j++) {
			matrix[i][j] = ent[j * 4 + i];
		}
	}

	return matrix;
}

// Return 16 byte array from 4x4 matrix
u8* inputFromMatrix(u8** ent) {
	u8* input = new u8[16];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			input[j * 4 + i] = ent[i][j];
		}
	}
	return input;
}

// Print given key
void printMatrix(u8** key) {
	for (int k = 0; k < 11; k++) {
		cout << "-";
	} 
	cout << endl;
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			unsigned int keyByteValue = key[i][j];
			string hexFront = "";
			if (keyByteValue < 16) {
				hexFront = "0";
			}
			cout << hexFront << hex << keyByteValue << dec << " ";
		}
		cout << endl;
	}
	for (int k = 0; k < 11; k++) {
		cout << "-";
	}
	cout << endl;
}

// Print given byte
void printHex(u8 ent) {
	unsigned int keyByteValue = ent;
	string hexFront = "";
	if (keyByteValue < 16) {
		hexFront = "0";
	}
	cout << hexFront << hex << keyByteValue << dec << endl;
}

// Print given 4 bytes
void printHex(u8* key, int length) {

	for (int i = 0; i < length; i++) {
		unsigned int keyByteValue = key[i];
		string hexFront = "";
		if (keyByteValue < 16) {
			hexFront = "0";
		}
		cout << hexFront << hex << keyByteValue << dec << " ";
	}
	cout << endl;
}

void free2dArray(u8** arr, int row) {
	for (int i = 0; i < row; i++) {
		delete[] arr[i];
	}
	delete[] arr;
}

// Generate one key for each round
void oneRoundKeySchedule(u8** key, int roundCount) {

	// Mirror key matrix for direct 4 byte partitions
	mirror(key);

	// Fetch key bytes
	u8* first4Bytes = key[0];
	u8* second4Bytes = key[1];
	u8* third4Bytes = key[2];
	u8* fourth4Bytes = key[3];

	u8* processedFourth4Bytes = new u8[4];

	// Rotate the last 4 bytes and then substitute
	processedFourth4Bytes[0] = S_BOX[(int)fourth4Bytes[1]];
	processedFourth4Bytes[1] = S_BOX[(int)fourth4Bytes[2]];
	processedFourth4Bytes[2] = S_BOX[(int)fourth4Bytes[3]];
	processedFourth4Bytes[3] = S_BOX[(int)fourth4Bytes[0]];

	// RCON
	processedFourth4Bytes[0] = processedFourth4Bytes[0] ^ RCON[roundCount];

	// XOR operations
	xorBytes(first4Bytes, processedFourth4Bytes);
	xorBytes(second4Bytes, first4Bytes);
	xorBytes(third4Bytes, second4Bytes);
	xorBytes(fourth4Bytes, third4Bytes);

	// Mirror key matrix for direct 4 byte partitions
	mirror(key);

}

// Generate round keys for each round
u8** oneRoundKeyScheduleInv(u8** key) {

	u8** inverseKeyList = new u8*[ROUND_COUNT + 1];
	for (int i = 0; i < ROUND_COUNT + 1; i++) {
		inverseKeyList[i] = new u8[16];
	}

	inverseKeyList[ROUND_COUNT] = inputFromMatrix(key);

 	for (int roundCount = 1; roundCount <= ROUND_COUNT; roundCount++) {
		// Mirror key matrix for direct 4 byte partitions
		mirror(key);

		// Fetch key bytes
		u8* first4Bytes = key[0];
		u8* second4Bytes = key[1];
		u8* third4Bytes = key[2];
		u8* fourth4Bytes = key[3];

		u8* processedFourth4Bytes = new u8[4];

		// Rotate the last 4 bytes and then substitute
		processedFourth4Bytes[0] = S_BOX[(int)fourth4Bytes[1]];
		processedFourth4Bytes[1] = S_BOX[(int)fourth4Bytes[2]];
		processedFourth4Bytes[2] = S_BOX[(int)fourth4Bytes[3]];
		processedFourth4Bytes[3] = S_BOX[(int)fourth4Bytes[0]];

		// RCON
		processedFourth4Bytes[0] = processedFourth4Bytes[0] ^ RCON[roundCount];

		// XOR operations
		xorBytes(first4Bytes, processedFourth4Bytes);
		xorBytes(second4Bytes, first4Bytes);
		xorBytes(third4Bytes, second4Bytes);
		xorBytes(fourth4Bytes, third4Bytes);

		// Mirror key matrix for direct 4 byte partitions
		mirror(key);

		delete[] processedFourth4Bytes;

		inverseKeyList[ROUND_COUNT - roundCount] = inputFromMatrix(key);
	}

	return inverseKeyList;
}

// return S-boxed version of given input
void subBytes(u8** inp) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			inp[i][j] = S_BOX[(int)inp[i][j]];
		}

	}
}

// return inverse S-boxed version of given input
void subBytesInv(u8** inp) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			inp[i][j] = S_BOX_INV[(int)inp[i][j]];
		}

	}
}

// Shifting operation on plaintext
void shiftBytes(u8** inp) {
	// Shift 1 left
	u8 temp = inp[1][0];
	inp[1][0] = inp[1][1];
	inp[1][1] = inp[1][2];
	inp[1][2] = inp[1][3];
	inp[1][3] = temp;

	// Shift 2 left
	temp = inp[2][0];
	inp[2][0] = inp[2][2];
	inp[2][2] = temp;
	temp = inp[2][1];
	inp[2][1] = inp[2][3];
	inp[2][3] = temp;

	// Shift 3 left aka 1 right
	temp = inp[3][3];
	inp[3][3] = inp[3][2];
	inp[3][2] = inp[3][1];
	inp[3][1] = inp[3][0];
	inp[3][0] = temp;
	
}

// Shifting operation on ciphertext
void shiftBytesInv(u8** inp) {
	// Shift 1 right
	u8 temp = inp[1][3];
	inp[1][3] = inp[1][2];
	inp[1][2] = inp[1][1];
	inp[1][1] = inp[1][0];
	inp[1][0] = temp;

	// Shift 2 right
	temp = inp[2][0];
	inp[2][0] = inp[2][2];
	inp[2][2] = temp;
	temp = inp[2][1];
	inp[2][1] = inp[2][3];
	inp[2][3] = temp;

	// Shift 3 right aka 1 left
	temp = inp[3][0];
	inp[3][0] = inp[3][1];
	inp[3][1] = inp[3][2];
	inp[3][2] = inp[3][3];
	inp[3][3] = temp;

}

// Mixing columns operation on plaintext
void mixColumns(u8** inp) {
	mirror(inp);

	for (int i = 0; i < 4; i++) {
		u8* row4Bytes = inp[i];
		u8* processedRow4Bytes = new u8[4];
		for (int j = 0; j < 4; j++) {
			processedRow4Bytes[j] = galoisMultiplication(row4Bytes[0], M[j][0]) ^ galoisMultiplication(row4Bytes[1], M[j][1]) ^
				galoisMultiplication(row4Bytes[2], M[j][2]) ^ galoisMultiplication(row4Bytes[3], M[j][3]);
		}
		inp[i] = processedRow4Bytes;
		delete[] row4Bytes;
	}

	mirror(inp);
}

// Mixing columns operation on ciphertext
void mixColumnsInv(u8** inp) {
	mirror(inp);

	for (int i = 0; i < 4; i++) {
		u8* row4Bytes = inp[i];
		u8* processedRow4Bytes = new u8[4];
		for (int j = 0; j < 4; j++) {
			processedRow4Bytes[j] = galoisMultiplication(row4Bytes[0], M_INV[j][0]) ^ galoisMultiplication(row4Bytes[1], M_INV[j][1]) ^
				galoisMultiplication(row4Bytes[2], M_INV[j][2]) ^ galoisMultiplication(row4Bytes[3], M_INV[j][3]);
		}
		inp[i] = processedRow4Bytes;
		delete[] row4Bytes;
	}

	mirror(inp);
}

u8 galoisMultiplication(u8 left, u8 multiplier) {
	if (multiplier == 0x02) {
		left = galoisCalculation(left);
	} else if (multiplier == 0x03) {
		u8 leftx2 = galoisCalculation(left);
		left = leftx2 ^ left;
	} else if (multiplier == 0x09) {
		// (((x2)x2)x2)+
		u8 leftx2 = galoisCalculation(left);
		leftx2 = galoisCalculation(leftx2);
		leftx2 = galoisCalculation(leftx2);
		left = leftx2 ^ left;
	} else if (multiplier == 0xB) {
		// ((((x2)x2)+)x2)+
		u8 leftx2 = galoisCalculation(left);
		leftx2 = galoisCalculation(leftx2);
		leftx2 = leftx2 ^ left;
		leftx2 = galoisCalculation(leftx2);
		left = leftx2 ^ left;
	} else if (multiplier == 0x0D) {
		// ((((x2)+)x2)x2)+
		u8 leftx2 = galoisCalculation(left);
		leftx2 = leftx2 ^ left;
		leftx2 = galoisCalculation(leftx2);
		leftx2 = galoisCalculation(leftx2);
		left = leftx2 ^ left;
	} else if (multiplier == 0x0E) {
		// ((((x2)+)x2)+)x2
		u8 leftx2 = galoisCalculation(left);
		leftx2 = leftx2 ^ left;
		leftx2 = galoisCalculation(leftx2);
		leftx2 = leftx2 ^ left;
		left = galoisCalculation(leftx2);
	}
	return left;
}

u8 galoisCalculation(u8 left) {
	int input = left;
	input = input << 1;
	if (left >= 128) {
		input ^= 0x1B;
	}
	return input;
}

// XOR ent1 and ent2, store the result in ent1
void xorBytes(u8 ent1[4], u8 ent2[4]) {
	for (int i = 0; i < 4; i++) {
		ent1[i] = ent1[i] ^ ent2[i];
	}
}

void xorBytes(u8* ent1, u8* ent2, int length) {
	for (int i = 0; i < length; i++) {
		ent1[i] = ent1[i] ^ ent2[i];
	}
}

// XOR ent1 and ent2, store the result in ent1
void xorBytes(u8** ent1, u8** ent2) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			ent1[i][j] = ent1[i][j] ^ ent2[i][j];
		}
		
	}
}

// Mirrors given matrix
void mirror(u8** ent) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			if (i == j || i > j) {
				continue;
			} else {
				u8 temp = ent[i][j];
				temp = ent[i][j];
				ent[i][j] = ent[j][i];
				ent[j][i] = temp;
			}
		}
	}
}
