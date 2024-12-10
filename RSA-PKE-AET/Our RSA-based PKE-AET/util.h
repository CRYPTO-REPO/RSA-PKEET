#ifndef UTIL_H
#define UTIL_H

#include <iostream>
#include <chrono>
#include <vector>
#include <string>
#include <algorithm>
#include <string.h>
#include <stdio.h>
#include <cmath>
#include <chrono>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/err.h>

using namespace std;

enum class secuParam{
    lambda_80 = 112, // for msg, hash
    lambda_112 = 112,
    lambda_128 = 128,
};

enum class bitLengthOfN{
    lambda_80 = 1024,
    lambda_112 = 2048,
    lambda_128 = 3072,
};

#define LAMBDA static_cast<int>(secuParam::lambda_128)

#define HLEN (LAMBDA*2)
#define BLEN static_cast<int>(bitLengthOfN::lambda_128)

#define BYTES_HLEN (HLEN/8)
#define BYTES_BLEN (BLEN/8)


struct publicKey{
    BIGNUM* N1;
    BIGNUM* N2;
    BIGNUM* e1;
    BIGNUM* e2;
};

struct secretKey{
    BIGNUM* d1;
    BIGNUM* d2;
    BIGNUM* p1;
    BIGNUM* p2;
    BIGNUM* q1;
    BIGNUM* q2;
};


void euler_phi(BIGNUM* phi, BIGNUM* p, BIGNUM* q);
void euler_phi(BIGNUM* phi, BIGNUM* N, BIGNUM* p, BIGNUM* q);

void handleErrors();

void sha3(BIGNUM* res, const BIGNUM *src, int lambda);
void sha3(BIGNUM* res, const BIGNUM *src1, const BIGNUM *src2, int lambda);
void sha3(BIGNUM* res, const BIGNUM *src1, const BIGNUM *src2, const BIGNUM *src3, const BIGNUM *src4, int lambda);

void BN_xor(BIGNUM* res, const BIGNUM* in1, const int in1len, const BIGNUM* in2, const int in2len);


#endif