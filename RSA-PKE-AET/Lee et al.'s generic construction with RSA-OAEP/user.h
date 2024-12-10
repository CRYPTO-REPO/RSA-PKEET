#ifndef USER_H
#define USER_H

#include "util.h"

class user{
    private:
    secretKey sk;
    BIGNUM* msg;

    int lambda;
    int bitLenN;

    public:
    publicKey pk;
    BIGNUM* ctx[3];
    BIGNUM* td;
    
    void setLambda(const int lambda);
    void setBitLenN(const int bitLenN);

    void initParams();
    void clearParams();
    void freeParams();

    void initMsg();
    void genMsg();

    void printMsg();
    void getMsg(BIGNUM* m);
    void setMsg(BIGNUM* m);

    void freeMsg();
    void clearMsg();

    void initCtx();
    void clearCtx();
    void freeCtx();

    void initTd();
    void freeTd();
    void clearTd();

    void keyGen();
    void keyGen_rand_e();

    void encrypt(BIGNUM* ctx[3], publicKey pk);
    void decrypt(BIGNUM* result, BIGNUM* ctx[3]);
    
    void auth();
};

#endif