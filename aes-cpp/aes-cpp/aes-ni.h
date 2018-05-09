#pragma once
#include "stdafx.h"
#include <iostream>

using namespace std;
typedef uint8_t u8;
typedef uint32_t u32;

class AesNI {
public:
	AesNI();
	~AesNI();

	u8* encrypt(u8 *pt, u8 *rk);
	void exhaustiveSearch(u8 *pt, u8 *rk, u8 * ct, u32 range);

	void printHex(u8 *key, int length);
private:

};