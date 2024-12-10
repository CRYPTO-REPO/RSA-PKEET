#ifndef TESTER_H
#define TESTER_H

#include "util.h"

class tester{
    private:

    public:

    bool test_type1(BIGNUM* ctx_a[4], BIGNUM* td_a[2], BIGNUM* ctx_b[4], BIGNUM* td_b[2], const int lambda);

    bool test_type2(BIGNUM* ctx_a[4], const BIGNUM* td_a, BIGNUM* ctx_b[4], const BIGNUM* td_b, const int lambda);

};

#endif