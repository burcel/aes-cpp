#include "stdafx.h"
#include "Aes128.h"
#include <fstream>
#include <iostream>
#include <string>

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

void Aes128::decryptWithCtr(u8* cipherTextList[16], int length) {
	//cout << "-- CTR mode decryption --" << endl;
	//cout << "Key: " << endl;
	//printHex(key, 16);
	//cout << "Initial Counter: " << endl;
	//printHex(iv, 16);

	u8* output = NULL;

	for (int i = 0; i < length; i++) {
		//cout << "Block #" << i + 1 << endl;
		//cout << "Input Block: " << endl;
		//printHex(iv, 16);

		output = encrypt(iv);
		//cout << "Output Block: " << endl;
		//printHex(output, 16);

		//cout << "Ciphertext: " << endl;
		//printHex(cipherTextList[i], 16);

		xorByteArray(output, cipherTextList[i], 16);

		cout << "Plaintext: " << endl;
		printHex(output, 16);

		incrementCounter(15);
	}

	delete[] output;
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

void Aes128::encryptFile(string fileName) {
	ifstream infile(fileName, fstream::binary);

	string newFileName;
	newFileName.append(fileName);
	newFileName.append("_encrypted");

	ofstream outfile(newFileName, ofstream::out);

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
				index = 0;
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
	newFileName.append("_new");

	ofstream outfile(newFileName, ofstream::out);

	if (infile) {
		infile.seekg(0, infile.end);
		int length = infile.tellg();
		infile.seekg(0, infile.beg);

		char* buffer = new char[length];

		cout << "Reading " << length << " characters.." << endl;
		infile.read(buffer, length);

		if (infile) {
			cout << "Reading is finished" << endl;
		} else {
			cout << "Error: Only " << infile.gcount() << " could be read!" << endl;
		}

		infile.close();

		for (int i = 0; i < length; i++) {
			cout << hex << (unsigned int)buffer[i] << " ";
		}
		cout << dec << endl;

		outfile.write(buffer, length);
		outfile.close();

		delete[] buffer;
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