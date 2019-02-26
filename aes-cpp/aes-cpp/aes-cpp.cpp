#include "stdafx.h"
#include "Aes128.h"
#include "aes-ni.h"

using namespace std;

int main() {
	// AES-128 NI Exhaustive Search
	mainAesNi128ExhaustiveSearch();

	// AES-192 NI Exhaustive Search
	//mainAesNi192ExhaustiveSearch();

	// AES-128 NI Exhaustive Search
	//mainAesNi256ExhaustiveSearch();

	// AES-128 NI Counter Mode
	//mainAesNi128Ctr();

	// AES-192 NI Counter Mode
	//mainAesNi192Ctr();

	// AES-256 NI Counter Mode
	//mainAesNi256Ctr();

	// AES-128 NI File Encryption
	//mainAesNiFileEncryption();


	return 0;
	


	//u8 pt[16] = { 0x32, 0x43, 0xF6, 0xA8, 0x88, 0x5A, 0x30, 0x8D, 0x31, 0x31, 0x98, 0xA2, 0xE0, 0x37, 0x07, 0x34 };
	//u8 ct[16] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };
	//u8 rk[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };

	////u8 *ct = aesNi.encrypt(pt, rk);
	////aesNi.printHex(ct, 16);

	//Aes128 aes128;
	//u32 rkExpanded[44];
	//u32 rkC[4];
	//rkC[0] = 0x2B7E1516U;
	//rkC[1] = 0x28AED2A6U;
	//rkC[2] = 0xABF71588U;
	//rkC[3] = 0x09CF4F3CU;

	//u32 ptC[4];
	////ptC[0] = 0x3243F6A8U;
	////ptC[1] = 0x885A308DU;
	////ptC[2] = 0x313198A2U;
	////ptC[3] = 0xE0370734U;

	//ptC[0] = 0x00000000U;
	//ptC[1] = 0x00000000U;
	//ptC[2] = 0x00000000U;
	//ptC[3] = 0x00000000U;

	//u32 ctC[4];
	//ctC[0] = 0x3925841DU;
	//ctC[1] = 0x02DC09FBU;
	//ctC[2] = 0xDC118597U;
	//ctC[3] = 0x196A0B32U;

	//aes128.smallAEScreateLookupTable();

	//printf("%04x\n", aes128.galoisMultiplication(0x6, 0x3));

	//u32 p = 25;
	//double keyRange = pow(2, p);
	//u32 range = ceil(keyRange);
	//cout << "POW: " << p << " Range: " << range << endl;

	//clock_t beginTime = clock();

	////aesNi.exhaustiveSearch(pt, rk, ct, range);

	//aesNi.ctr(pt, rk, range);

	////aes128.exhaustiveSearch(ptC, rkC, ctC, range);

	////aes128.keyExpansion(rkC, rkExpanded);
	////aes128.ctr(ptC, rkExpanded, range);

	//printf("Time elapsed: %f sec\n", float(clock() - beginTime) / CLOCKS_PER_SEC);

	int x;
	cin >> x;

	//free(pt);
	//free(ct);
	//free(rk);

	  // 128bits
	//u8 cipherTextInput[16] = { 0x39, 0x25, 0x84, 0x1D, 0x02, 0xDC, 0x09, 0xFB, 0xDC, 0x11, 0x85, 0x97, 0x19, 0x6A, 0x0B, 0x32 };  // 128bits
	//u8 keyInput[16] = { 0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C };  // 128bits

	//u8 plainTextInput[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };  // 128bits
	//u8 cipherTextInput[16] = { 0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A };  // 128bits
	//u8 keyInput[16] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };  // 128bits

	//encrypt(plainTextInput, keyInput);
	//decrypt(cipherTextInput, keyInput);

}