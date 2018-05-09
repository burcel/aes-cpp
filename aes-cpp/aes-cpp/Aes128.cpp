#include "stdafx.h"
#include "Aes128.h"
#include <fstream>
#include <iostream>
#include <string>
#include  <iomanip>

using namespace std;
typedef uint8_t u8;


Aes128::Aes128(u8* keyInput) {
	key = keyInput;
	
	// TODO: initialize IV -> Counter
}


Aes128::~Aes128() {
	// Deallocate key list
	free2dArray(keyList, ROUND_COUNT + 1);
	free2dArray(inverseKeyList, ROUND_COUNT + 1);
	if (tableBasedKeyList != NULL) {
		delete[] tableBasedKeyList;
	}
	// Deallocate table based implementation
	if (T0 != NULL) {
		delete[] T0;
	}
	if (T1 != NULL) {
		delete[] T1;
	}
	if (T2 != NULL) {
		delete[] T2;
	}
	if (T3 != NULL) {
		delete[] T3;
	}
}

u8* Aes128::encrypt(u8 plainTextInput[16]) {

	//cout << "-- Encryption --" << endl;
	//cout << "Initial input: " << endl;
	//printHex(plainTextInput, 16);
	//cout << "Initial key: " << endl;
	//printHex(key, 16);

	if (keyList == NULL) {
		keySchedule();
	}

	u8** plainText = matrixFromInput(plainTextInput);

	u8** roundKey = matrixFromInput((keyList[0]));
	xorByteMatrix(plainText, roundKey);
	//cout << "## Round: " << 0 << endl;
	//cout << "   0. Add Round Key" << endl;
	//printMatrix(plainText);
	//cout << "   0. Round Key" << endl;
	//printMatrix(roundKey);
	free2dArray(roundKey, 4);

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
		roundKey = matrixFromInput(keyList[roundCount]);
		xorByteMatrix(plainText, roundKey);
		//printMatrix(plainText);
		//cout << "   4. Round Key" << endl;
		//printMatrix(roundKey);

		free2dArray(roundKey, 4);
	}

	u8* cipherText = inputFromMatrix(plainText);
	//cout << "Ciphertext: " << endl;
	//printHex(cipherText, 16);

	free2dArray(plainText, 4);

	return cipherText;
}

// Inverse cipher
u8* Aes128::decrypt(u8 cipherTextInput[16]) {
	
	//cout << "-- Decryption --" << endl;
	//cout << "Initial input: " << endl;
	//printHex(cipherTextInput, 16);
	//cout << "Initial key: " << endl;
	//printHex(key, 16);

	if (inverseKeyList == NULL) {
		keyScheduleInv();
	}
	
	u8** cipherText = matrixFromInput(cipherTextInput);
	u8** roundKey = matrixFromInput((inverseKeyList[0]));
	xorByteMatrix(cipherText, roundKey);

	//cout << "## Round: " << 0 << endl;
	//cout << 0 << "  Round Key" << endl;
	//printMatrix(roundKey);
	//printHex(inputFromMatrix(roundKey), 16);
	//cout << 0 << " Add Round Key" << endl;
	//printMatrix(cipherText);
	//printHex(inputFromMatrix(cipherText), 16);

	free2dArray(roundKey, 4);
	
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
		roundKey = matrixFromInput(inverseKeyList[roundCount]);
		//printMatrix(roundKey);
		//printHex(inverseKeyList[roundCount], 16);
	
		//cout << roundCount << " Add Round Key" << endl;
		xorByteMatrix(cipherText, roundKey);
		free2dArray(roundKey, 4);
		//printMatrix(cipherText);
		//printHex(inputFromMatrix(cipherText), 16);
	
		if (roundCount != ROUND_COUNT) {
			//cout << roundCount << " Mix Columns" << endl;
			mixColumnsInv(cipherText);
			//printMatrix(cipherText);
			//printHex(inputFromMatrix(cipherText), 16);
		}
	}
	
	u8* plainText = inputFromMatrix(cipherText);
	//cout << "Plaintext: " << endl;
	//printHex(plainText, 16);
	
	free2dArray(cipherText, 4);
	
	return plainText;
}

u8* Aes128::encryptWithTable(u8 plainTextInput[16]) {
	/*cout << "-- Encryption --" << endl;
	cout << "Initial input: " << endl;
	printHex(plainTextInput, 16);
	cout << "Initial key: " << endl;
	printHex(key, 16);*/

	if (keyList == NULL) {
		keySchedule();
		keyScheduleTableBased();
	}

	// Create plaintext as 32 bit unsigned integers
	u32 s0, s1, s2, s3;
	s0 = ((u32)plainTextInput[0] << 24) |
		((u32)plainTextInput[1] << 16) |
		((u32)plainTextInput[2] << 8) |
		((u32)plainTextInput[3]);

	s1 = ((u32)plainTextInput[4] << 24) |
		((u32)plainTextInput[5] << 16) |
		((u32)plainTextInput[6] << 8) |
		((u32)plainTextInput[7]);

	s2 = ((u32)plainTextInput[8] << 24) |
		((u32)plainTextInput[9] << 16) |
		((u32)plainTextInput[10] << 8) |
		((u32)plainTextInput[11]);

	s3 = ((u32)plainTextInput[12] << 24) |
		((u32)plainTextInput[13] << 16) |
		((u32)plainTextInput[14] << 8) |
		((u32)plainTextInput[15]);

	// First round just XORs input with key.
	s0 = s0 ^ tableBasedKeyList[0];
	s1 = s1 ^ tableBasedKeyList[1];
	s2 = s2 ^ tableBasedKeyList[2];
	s3 = s3 ^ tableBasedKeyList[3];

	/*cout << "-- Round: " << 0 << endl;
	printHex(s0);
	printHex(s1);
	printHex(s2);
	printHex(s3);
	cout << "-- Round Key" << endl;
	printHex(tableBasedKeyList[0]);
	printHex(tableBasedKeyList[1]);
	printHex(tableBasedKeyList[2]);
	printHex(tableBasedKeyList[3]);*/

	u32 t0, t1, t2, t3;

	for (int roundCount = 1; roundCount < ROUND_COUNT; roundCount++) {
		t0 = T0[s0 >> 24] ^ T1[(s1 >> 16) & 0xFF] ^ T2[(s2 >> 8) & 0xFF] ^ T3[s3 & 0xFF] ^ tableBasedKeyList[roundCount * 4 + 0];
		t1 = T0[s1 >> 24] ^ T1[(s2 >> 16) & 0xFF] ^ T2[(s3 >> 8) & 0xFF] ^ T3[s0 & 0xFF] ^ tableBasedKeyList[roundCount * 4 + 1];
		t2 = T0[s2 >> 24] ^ T1[(s3 >> 16) & 0xFF] ^ T2[(s0 >> 8) & 0xFF] ^ T3[s1 & 0xFF] ^ tableBasedKeyList[roundCount * 4 + 2];
		t3 = T0[s3 >> 24] ^ T1[(s0 >> 16) & 0xFF] ^ T2[(s1 >> 8) & 0xFF] ^ T3[s2 & 0xFF] ^ tableBasedKeyList[roundCount * 4 + 3];

		s0 = t0;
		s1 = t1;
		s2 = t2;
		s3 = t3;

		/*cout << "-- Round: " << roundCount << endl;
		printHex(s0);
		printHex(s1);
		printHex(s2);
		printHex(s3);
		cout << "-- Round Key" << endl;
		printHex(tableBasedKeyList[roundCount * 4 + 0]);
		printHex(tableBasedKeyList[roundCount * 4 + 1]);
		printHex(tableBasedKeyList[roundCount * 4 + 2]);
		printHex(tableBasedKeyList[roundCount * 4 + 3]);*/

		/*if (roundCount == 2) {
			break;
		}*/
	}

	// Last round uses s-box directly and XORs to produce output.
	s0 = (T4[t0 >> 24] & 0xFF000000) ^ (T4[(t1 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t2 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t3) & 0xFF] & 0x000000FF) ^ tableBasedKeyList[40];
	s1 = (T4[t1 >> 24] & 0xFF000000) ^ (T4[(t2 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t3 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t0) & 0xFF] & 0x000000FF) ^ tableBasedKeyList[41];
	s2 = (T4[t2 >> 24] & 0xFF000000) ^ (T4[(t3 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t0 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t1) & 0xFF] & 0x000000FF) ^ tableBasedKeyList[42];
	s3 = (T4[t3 >> 24] & 0xFF000000) ^ (T4[(t0 >> 16) & 0xff] & 0x00FF0000) ^ (T4[(t1 >> 8) & 0xff] & 0x0000FF00) ^ (T4[(t2) & 0xFF] & 0x000000FF) ^ tableBasedKeyList[43];
	
	/*printf("-- Round: 10\n");
	printHex(s0);
	printHex(s1);
	printHex(s2);
	printHex(s3);
	printf("-- Round Key\n");
	printHex(tableBasedKeyList[40]);
	printHex(tableBasedKeyList[41]);
	printHex(tableBasedKeyList[42]);
	printHex(tableBasedKeyList[43]);*/

	// Create ciphertext as byte array from 32 bit unsigned integers
	u8* cipherText = new u8[16];
	cipherText[0] = s0 >> 24;
	cipherText[1] = (s0 >> 16) & 0xff;
	cipherText[2] = (s0 >> 8) & 0xff;
	cipherText[3] = s0 & 0xff;
	cipherText[4] = s1 >> 24;
	cipherText[5] = (s1 >> 16) & 0xff;
	cipherText[6] = (s1 >> 8) & 0xff;
	cipherText[7] = s1 & 0xff;
	cipherText[8] = s2 >> 24;
	cipherText[9] = (s2 >> 16) & 0xff;
	cipherText[10] = (s2 >> 8) & 0xff;
	cipherText[11] = s2 & 0xff;
	cipherText[12] = s3 >> 24;
	cipherText[13] = (s3 >> 16) & 0xff;
	cipherText[14] = (s3 >> 8) & 0xff;
	cipherText[15] = s3 & 0xff;
	return cipherText;

}

u8** Aes128::encryptWithCtr(u8** plainTextList, int length) {
	//cout << "-- CTR mode encryption --" << endl;
	//cout << "Key: " << endl;
	//printHex(key, 16);
	//cout << "Initial Counter: " << endl;
	//printHex(iv, 16);

	u8** output = new u8*[length];

	for (int i = 0; i < length; i++) {
		//cout << "Block #" << i + 1 << endl;
		//cout << "Input Block: " << endl;
		//printHex(iv, 16);

		output[i] = encrypt(iv);
		//cout << "Output Block: " << endl;
		//printHex(output, 16);

		cout << "Plaintext: " << endl;
		printHex(plainTextList[i], 16);

		xorByteArray(output[i], plainTextList[i], BLOCK_SIZE_BYTE);

		cout << "Ciphertext: " << endl;
		printHex(output[i], 16);

		incrementCounter(15);  // Default index -> 15 (increment byte at the last index)
	}

	return output;
}

u8** Aes128::decryptWithCtr(u8** cipherTextList, int length) {
	//cout << "-- CTR mode decryption --" << endl;
	//cout << "Key: " << endl;
	//printHex(key, 16);
	//cout << "Initial Counter: " << endl;
	//printHex(iv, 16);

	u8** output = new u8*[length];

	for (int i = 0; i < length; i++) {
		//cout << "Block #" << i + 1 << endl;
		//cout << "Input Block: " << endl;
		//printHex(iv, 16);

		output[i] = encrypt(iv);
		//cout << "Output Block: " << endl;
		//printHex(output, 16);

		cout << "Ciphertext: " << endl;
		printHex(cipherTextList[i], 16);

		xorByteArray(output[i], cipherTextList[i], BLOCK_SIZE_BYTE);

		cout << "Plaintext: " << endl;
		printHex(output[i], 16);

		incrementCounter(15);
	}

	return output;
}

// Generate round keys for each round
void Aes128::keySchedule() {

	u8** initialKey = matrixFromInput(key);

	keyList = new u8*[ROUND_COUNT + 1];
	for (int i = 0; i < ROUND_COUNT + 1; i++) {
		keyList[i] = new u8[16];
	}

	keyList[0] = inputFromMatrix(initialKey);

	for (int roundCount = 1; roundCount <= ROUND_COUNT; roundCount++) {
		// Mirror key matrix for direct 4 byte partitions
		mirror(initialKey);

		// Fetch key bytes
		u8* first4Bytes = initialKey[0];
		u8* second4Bytes = initialKey[1];
		u8* third4Bytes = initialKey[2];
		u8* fourth4Bytes = initialKey[3];

		u8* processedFourth4Bytes = new u8[4];

		// Rotate the last 4 bytes and then substitute
		processedFourth4Bytes[0] = S_BOX[(int)fourth4Bytes[1]];
		processedFourth4Bytes[1] = S_BOX[(int)fourth4Bytes[2]];
		processedFourth4Bytes[2] = S_BOX[(int)fourth4Bytes[3]];
		processedFourth4Bytes[3] = S_BOX[(int)fourth4Bytes[0]];

		// RCON
		processedFourth4Bytes[0] = processedFourth4Bytes[0] ^ RCON[roundCount];

		// XOR operations
		xorByteArray(first4Bytes, processedFourth4Bytes, 4);
		xorByteArray(second4Bytes, first4Bytes, 4);
		xorByteArray(third4Bytes, second4Bytes, 4);
		xorByteArray(fourth4Bytes, third4Bytes, 4);

		// Mirror key matrix for direct 4 byte partitions
		mirror(initialKey);

		delete[] processedFourth4Bytes;

		keyList[roundCount] = inputFromMatrix(initialKey);
	}

	free2dArray(initialKey, 4);
}

// Generate round keys for each round
void Aes128::keyScheduleInv() {

	u8** initialKey = matrixFromInput(key);

	inverseKeyList = new u8*[ROUND_COUNT + 1];
	for (int i = 0; i < ROUND_COUNT + 1; i++) {
		inverseKeyList[i] = new u8[16];
	}

	inverseKeyList[ROUND_COUNT] = inputFromMatrix(initialKey);

 	for (int roundCount = 1; roundCount <= ROUND_COUNT; roundCount++) {
		// Mirror key matrix for direct 4 byte partitions
		mirror(initialKey);

		// Fetch key bytes
		u8* first4Bytes = initialKey[0];
		u8* second4Bytes = initialKey[1];
		u8* third4Bytes = initialKey[2];
		u8* fourth4Bytes = initialKey[3];

		u8* processedFourth4Bytes = new u8[4];

		// Rotate the last 4 bytes and then substitute
		processedFourth4Bytes[0] = S_BOX[(int)fourth4Bytes[1]];
		processedFourth4Bytes[1] = S_BOX[(int)fourth4Bytes[2]];
		processedFourth4Bytes[2] = S_BOX[(int)fourth4Bytes[3]];
		processedFourth4Bytes[3] = S_BOX[(int)fourth4Bytes[0]];

		// RCON
		processedFourth4Bytes[0] = processedFourth4Bytes[0] ^ RCON[roundCount];

		// XOR operations
		xorByteArray(first4Bytes, processedFourth4Bytes, 4);
		xorByteArray(second4Bytes, first4Bytes, 4);
		xorByteArray(third4Bytes, second4Bytes, 4);
		xorByteArray(fourth4Bytes, third4Bytes, 4);

		// Mirror key matrix for direct 4 byte partitions
		mirror(initialKey);

		delete[] processedFourth4Bytes;

		inverseKeyList[ROUND_COUNT - roundCount] = inputFromMatrix(initialKey);
	}

	free2dArray(initialKey, 4);

}

u32* Aes128::keyScheduleFast(u8 key[16]) {

	u32* T4 = new u32[256];
	for (int i = 0; i < 256; i++) {
		T4[i] = (S_BOX[i] << 24) |
			(S_BOX[i] << 16) |
			(S_BOX[i] << 8) |
			(S_BOX[i]);
	}

	u32* rk = new u32[TABLE_BASED_KEY_LIST_ROW_SIZE];
	rk[0] = ((u32)key[0] << 24) ^ ((u32)key[1] << 16) ^ ((u32)key[2] << 8) ^ ((u32)key[3]);
	rk[1] = ((u32)key[4] << 24) ^ ((u32)key[5] << 16) ^ ((u32)key[6] << 8) ^ ((u32)key[7]);
	rk[2] = ((u32)key[8] << 24) ^ ((u32)key[9] << 16) ^ ((u32)key[10] << 8) ^ ((u32)key[11]);
	rk[3] = ((u32)key[12] << 24) ^ ((u32)key[13] << 16) ^ ((u32)key[14] << 8) ^ ((u32)key[15]);

	cout << "-- Round 0:" << endl;
	printHex(rk[0]);
	printHex(rk[1]);
	printHex(rk[2]);
	printHex(rk[3]);

	
	for (int rc = 0; rc < ROUND_COUNT; rc++) {
		u32 temp = rk[rc * 4 + 3];
		rk[rc * 4 + 4] = rk[rc * 4] ^
			(T4[(temp >> 16) & 0xff] & 0xff000000) ^
			(T4[(temp >> 8) & 0xff] & 0x00ff0000) ^
			(T4[(temp) & 0xff] & 0x0000ff00) ^
			(T4[(temp >> 24)] & 0x000000ff) ^
			RCON32[rc];
		rk[rc * 4 + 5] = rk[rc * 4 + 1] ^ rk[rc * 4 + 4];
		rk[rc * 4 + 6] = rk[rc * 4 + 2] ^ rk[rc * 4 + 5];
		rk[rc * 4 + 7] = rk[rc * 4 + 3] ^ rk[rc * 4 + 6];

		cout << "-- Round " << rc + 1 << endl;

		printHex(rk[rc * 4 + 4]);
		printHex(rk[rc * 4 + 5]);
		printHex(rk[rc * 4 + 6]);
		printHex(rk[rc * 4 + 7]);
	}

	return tableBasedKeyList;
}

// 
void Aes128::keyScheduleTableBased() {
	if (keyList == NULL) {
		// Return if key list is not generated
		return;
	}

	tableBasedKeyList = new u32[TABLE_BASED_KEY_LIST_ROW_SIZE];

	for (int i = 0; i < ROUND_COUNT+1; i++) {
		u8** roundKey = matrixFromInput(keyList[i]);
		mirror(roundKey);  // row based -> comment this for column based
		for (int j = 0; j < 4; j++) {
			tableBasedKeyList[i*4 + j] = byteArrayToInt(roundKey[j], 4);
		}
		free2dArray(roundKey, 4);
	}

	/*for (int i = 0; i < TABLE_BASED_KEY_LIST_ROW_SIZE; i++) {
		cout << "##S" << endl;
		cout << i << endl;
		printHex(tableBasedKeyList[i]);
		cout << "##F" << endl;
	}*/
}

void Aes128::encryptFile(string fileName) {
	ifstream infile(fileName, fstream::binary);

	string newFileName;
	newFileName.append(fileName);
	newFileName.append("_encrypted");

	ofstream outfile(newFileName, ofstream::binary);

	if (infile) {
		infile.seekg(0, infile.end);
		int length = infile.tellg();
		infile.seekg(0, infile.beg);

		// Batch block size for encryption
		int batchBlockSize = 4;

		// Allocate 2d array
		u8** plainTextInputList = new u8*[batchBlockSize];
		for (int i = 0; i < batchBlockSize; i++) {
			plainTextInputList[i] = new u8[BLOCK_SIZE_BYTE];
		}

		cout << "Reading " << length << " characters.." << endl;
		char c; // For reading
		int index = 0;
		while (infile.get(c)) {
			//printHex(c);

			plainTextInputList[index / BLOCK_SIZE_BYTE][index % BLOCK_SIZE_BYTE] = c;
			index++;

			if (index == batchBlockSize * BLOCK_SIZE_BYTE) {
				// Ready to be encrypted
				cout << "Encrypting.." << endl;
				u8** cipherTextOutputList = encryptWithCtr(plainTextInputList, batchBlockSize);
				for (int i = 0; i < batchBlockSize; i++) {
					outfile.write(reinterpret_cast<char*>(cipherTextOutputList[i]), BLOCK_SIZE_BYTE);
				}
				free2dArray(cipherTextOutputList, batchBlockSize);
				index = 0; // For reallocating input byte series
			}
		}
		//cout << dec << endl;

		//TODO: There might be some blocks with empty bytes -> Insert 0 for them.. What to do?

		infile.close();
		outfile.close();

		free2dArray(plainTextInputList, batchBlockSize);
	}
}

void Aes128::decryptFile(string fileName) {
	ifstream infile(fileName, fstream::binary);

	string newFileName;
	newFileName.append(fileName);
	newFileName.append("_decrypted");

	ofstream outfile(newFileName, ofstream::binary);

	if (infile) {
		infile.seekg(0, infile.end);
		int length = infile.tellg();
		infile.seekg(0, infile.beg);

		// Batch block size for encryption
		int batchBlockSize = 4;

		// Allocate 2d array
		u8** cipherTextInputList = new u8*[batchBlockSize];
		for (int i = 0; i < batchBlockSize; i++) {
			cipherTextInputList[i] = new u8[BLOCK_SIZE_BYTE];
		}

		cout << "Reading " << length << " characters.." << endl;
		char c; // For reading
		int index = 0;
		while (infile.get(c)) {
			//printHex(c);

			cipherTextInputList[index / BLOCK_SIZE_BYTE][index % BLOCK_SIZE_BYTE] = c;
			index++;

			if (index == batchBlockSize * BLOCK_SIZE_BYTE) {
				// Ready to be decrypted
				cout << "Decrypting.." << endl;
				u8** plainTextOutputList = decryptWithCtr(cipherTextInputList, batchBlockSize);
				for (int i = 0; i < batchBlockSize; i++) {
					outfile.write(reinterpret_cast<char*>(plainTextOutputList[i]), BLOCK_SIZE_BYTE);
				}
				free2dArray(plainTextOutputList, batchBlockSize);
				index = 0; // For reallocating input byte series
			}
		}
		cout << dec << endl;

		//TODO: There might be some blocks with empty bytes -> Insert 0 for them.. What to do?

		infile.close();
		outfile.close();

		free2dArray(cipherTextInputList, batchBlockSize);
	}
}

// Increment IV by 1
void Aes128::incrementCounter(int index) {
	if (index == 0) {
		return;
	}
	if (iv[index] == 0xFF) {
		iv[index] = 0x00;
		index--;
		if (iv[index] == 0xFF) {
			incrementCounter(index);
		} else {
			iv[index]++;
		}
	} else {
		iv[index]++;
	}
}

// Return 16 byte array from 4x4 matrix
u8* Aes128::inputFromMatrix(u8** ent) {
	u8* input = new u8[16];
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			input[j * 4 + i] = ent[i][j];
		}
	}
	return input;
}

// Return 4x4 matrix from 16 byte array
u8** Aes128::matrixFromInput(u8 ent[16]) {
	u8** matrix = new u8*[4];
	for (int i = 0; i < 4; i++) {
		matrix[i] = new u8[4];
		for (int j = 0; j < 4; j++) {
			matrix[i][j] = ent[j * 4 + i];
		}
	}

	return matrix;
}

void Aes128::xorByteArray(u8* ent1, u8* ent2, int length) {
	for (int i = 0; i < length; i++) {
		ent1[i] = ent1[i] ^ ent2[i];
	}
}

// XOR ent1 and ent2, store the result in ent1
void Aes128::xorByteMatrix(u8** ent1, u8** ent2) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			ent1[i][j] = ent1[i][j] ^ ent2[i][j];
		}

	}
}

// return S-boxed version of given input
void Aes128::subBytes(u8** inp) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			inp[i][j] = S_BOX[(int)inp[i][j]];
		}

	}
}

// return inverse S-boxed version of given input
void Aes128::subBytesInv(u8** inp) {
	for (int i = 0; i < 4; i++) {
		for (int j = 0; j < 4; j++) {
			inp[i][j] = S_BOX_INV[(int)inp[i][j]];
		}

	}
}

// Shifting operation on plaintext
void Aes128::shiftBytes(u8** inp) {
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
void Aes128::shiftBytesInv(u8** inp) {
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
void Aes128::mixColumns(u8** inp) {
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
void Aes128::mixColumnsInv(u8** inp) {
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

// Mirrors given matrix
void Aes128::mirror(u8** ent) {
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


u8 Aes128::galoisMultiplication(u8 left, u8 multiplier) {
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

u8 Aes128::galoisCalculation(u8 left) {
	int input = left;
	input = input << 1;
	if (left >= 128) {
		input ^= 0x1B;
	}
	return input;
}

// Print given byte
void Aes128::printHex(u8 ent) {
	unsigned int keyByteValue = ent;
	string hexFront = "";
	if (keyByteValue < 16) {
		hexFront = "0";
	}
	cout << hexFront << hex << keyByteValue << dec << endl;
}

// Print given 32 bits integer
void Aes128::printHex(u32 ent) {
	cout << uppercase << hex << setfill('0') << setw(8) << right << ent << dec  << endl;
}

// Print given 4 bytes
void Aes128::printHex(u8* key, int length) {

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

// Print given key
void Aes128::printMatrix(u8** key) {
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

void Aes128::free2dArray(u8** arr, int row) {
	if (arr != NULL) {
		for (int i = 0; i < row; i++) {
			if (arr[i] != NULL) {
				delete[] arr[i];
			}
		}
		delete[] arr;
	}
}

void Aes128::createLookupTable() {
	// Allocate look up tables 
	T0 = new u32[256];
	T1 = new u32[256];
	T2 = new u32[256];
	T3 = new u32[256];
	T4 = new u32[256];
	// Generate tables
	for (int i = 0; i < 256; i++) {

		// TO
		T0[i] = ((u32)galoisMultiplication(S_BOX[i], 0x02) << 24) |
				((u32)galoisMultiplication(S_BOX[i], 0x01) << 16) |
				((u32)galoisMultiplication(S_BOX[i], 0x01) << 8) |
				((u32)galoisMultiplication(S_BOX[i], 0x03));

		//printHex(T0[i]);

		// T1
		T1[i] = (galoisMultiplication(S_BOX[i], 0x03) << 24) |
				(galoisMultiplication(S_BOX[i], 0x02) << 16) |
				(galoisMultiplication(S_BOX[i], 0x01) << 8) |
				(galoisMultiplication(S_BOX[i], 0x01));

		//printHex(T1[i]);

		// T2
		T2[i] = (galoisMultiplication(S_BOX[i], 0x01) << 24) |
				(galoisMultiplication(S_BOX[i], 0x03) << 16) |
				(galoisMultiplication(S_BOX[i], 0x02) << 8) |
				(galoisMultiplication(S_BOX[i], 0x01));

		//printHex(T2[i]);

		// T3
		T3[i] = (galoisMultiplication(S_BOX[i], 0x01) << 24) |
				(galoisMultiplication(S_BOX[i], 0x01) << 16) |
				(galoisMultiplication(S_BOX[i], 0x03) << 8) |
				(galoisMultiplication(S_BOX[i], 0x02));

		//printHex(T2[i]);	

		// T4
		T4[i] = (S_BOX[i] << 24) |
			(S_BOX[i] << 16) |
			(S_BOX[i] << 8) |
			(S_BOX[i]);

		//printHex(T2[i]);	
	}
}

// Returns 32 bits integer from given byte array
u32 Aes128::byteArrayToInt(u8* byteArray, int length) {
	u32 resultInt = 0;
	for (int i = 0; i < length; i++) {
		resultInt = resultInt | byteArray[i];
		if (i != length-1) {
			resultInt = resultInt << 8;
		}
	}
	return resultInt;
}

void Aes128::setKey(u8 initKey[16]) {
	key = initKey;
}