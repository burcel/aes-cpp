#pragma once
#include "stdafx.h"
#include "aes-ni.h"
#include "aes.h"

#include <chrono>
#include <thread>

using namespace std;

int main() {

	u32 power = 30;
	u32 threadCount = 8;
	string filePath = "C://file-encryption-test//movie4.mp4";
		
	// AES-128 NI Exhaustive Search
	//mainAesNi128ExhaustiveSearch(power, threadCount);

	// AES-192 NI Exhaustive Search
	//mainAesNi192ExhaustiveSearch(power, threadCount);

	// AES-256 NI Exhaustive Search
	//mainAesNi256ExhaustiveSearch(power, threadCount);


	// AES-128 NI Counter Mode
	//mainAesNi128Ctr(power, threadCount);

	// AES-192 NI Counter Mode
	//mainAesNi192Ctr(power, threadCount);

	// AES-256 NI Counter Mode
	//mainAesNi256Ctr(power, threadCount);


	// AES NI File Encryption
	//mainAesNiFileEncryption(filePath, AES_128_KEY_LEN, threadCount);


	// AES-128 Exhaustive Search
	//mainAes128ExhaustiveSearch(power, threadCount);

	// AES-192 Exhaustive Search
	//mainAes192ExhaustiveSearch(power, threadCount);

	// AES-256 Exhaustive Search
	//mainAes256ExhaustiveSearch(power, threadCount);


	// AES-128 Counter Mode
	//mainAes128Ctr(power, threadCount);

	// AES-192 Counter Mode
	//mainAes192Ctr(power, threadCount);

	// AES-256 Counter Mode
	//mainAes256Ctr(power, threadCount);


	// AES File Encryption
	//mainAesFileEncryption(filePath, AES_128_KEY_LEN_INT, threadCount);

	return 0;
	
}