#ifndef TESTER_H
#define TESTER_H

#include "util.h"

class tester{
    private:

    public:

    bool test(BIGNUM* ctx_a[3], const BIGNUM* td_a, const BIGNUM* N2_a, BIGNUM* ctx_b[3], const BIGNUM* td_b, const BIGNUM* N2_b, const int lambda);
};

#endif