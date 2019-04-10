#pragma once
#include "stdafx.h"
#include "aes-ni.h"
#include "aes.h"

using namespace std;

int main() {

	// AES-128 NI Exhaustive Search
	//mainAesNi128ExhaustiveSearch();

	// AES-192 NI Exhaustive Search
	//mainAesNi192ExhaustiveSearch();

	// AES-256 NI Exhaustive Search
	mainAesNi256ExhaustiveSearch();



	// AES-128 NI Counter Mode
	//mainAesNi128Ctr();

	// AES-192 NI Counter Mode
	//mainAesNi192Ctr();

	// AES-256 NI Counter Mode
	//mainAesNi256Ctr();



	// AES NI File Encryption
	//mainAesNiFileEncryption();



	// AES-128 Exhaustive Search
	//mainAes128ExhaustiveSearch();

	// AES-192 Exhaustive Search
	//mainAes192ExhaustiveSearch();

	// AES-256 Exhaustive Search
	//mainAes256ExhaustiveSearch();



	// AES-128 Counter Mode
	//mainAes128Ctr();

	// AES-192 Counter Mode
	//mainAes192Ctr();

	// AES-256 Counter Mode
	//mainAes256Ctr();



	// AES File Encryption
	//mainAesFileEncryption();

	return 0;
	
}