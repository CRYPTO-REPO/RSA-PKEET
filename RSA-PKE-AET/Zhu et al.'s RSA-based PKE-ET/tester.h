#ifndef TESTER_H
#define TESTER_H

#include "util.h"

class tester{
    private:

    public:

    bool test(BIGNUM* ctx_a[5], const BIGNUM* td_a, const BIGNUM* N2_a, BIGNUM* ctx_b[5], const BIGNUM* td_b, const BIGNUM* N2_b, const BIGNUM* q, const int lambda);
};

#endif