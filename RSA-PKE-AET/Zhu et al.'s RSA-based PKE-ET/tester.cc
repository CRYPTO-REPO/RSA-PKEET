#include "tester.h"

bool tester::test(BIGNUM* ctx_a[5], const BIGNUM* td_a, const BIGNUM* N2_a, BIGNUM* ctx_b[5], const BIGNUM* td_b, const BIGNUM* N2_b, const BIGNUM* q, const int lambda){
    BIGNUM* r2_a = BN_new();
    BIGNUM* h3_a = BN_new();
    BIGNUM* xy_a = BN_new();
    BIGNUM* x_a = BN_new();
    BIGNUM* y_a = BN_new();
    BIGNUM* mul_a = BN_new();
    
    BIGNUM* r2_b = BN_new();
    BIGNUM* h3_b = BN_new();
    BIGNUM* xy_b = BN_new();
    BIGNUM* x_b = BN_new();
    BIGNUM* y_b = BN_new();
    BIGNUM* mul_b = BN_new();

    BN_CTX* c = BN_CTX_new();

    bool result;

    int xylen = BYTES_HLEN * 2;
    int xlen = BYTES_HLEN;
    int ylen = BYTES_HLEN;

    BN_mod_exp(r2_a, ctx_a[1], td_a, N2_a, c);
    sha3(h3_a, r2_a, ctx_a[0], ctx_a[1], ctx_a[2], ctx_a[3], lambda);
    BN_xor(xy_a, ctx_a[4], xylen, h3_a, xylen);

    BN_mod_exp(r2_b, ctx_b[1], td_b, N2_b, c);
    sha3(h3_b, r2_b, ctx_b[0], ctx_b[1], ctx_b[2], ctx_b[3], lambda);
    BN_xor(xy_b, ctx_b[4], xylen, h3_b, xylen);

    // parse x, y
    BN_parse(x_a, y_a, xy_a, xlen, ylen, xylen);
    BN_parse(x_b, y_b, xy_b, xlen, ylen, xylen);

    BN_mod_inverse(x_a, x_a, q, c);
    BN_mod_mul(mul_a, x_a, y_a, q, c);
    
    BN_mod_inverse(x_b, x_b, q, c);
    BN_mod_mul(mul_b, x_b, y_b, q, c);

    if(BN_cmp(mul_a, mul_b) == 0){
        result = true;
    }else{
        result = false;
    }

    BN_free(r2_a);
    BN_free(h3_a);
    BN_free(xy_a);
    BN_free(x_a);
    BN_free(y_a);
    BN_free(mul_a);
    
    BN_free(r2_b);
    BN_free(h3_b);
    BN_free(xy_b);
    BN_free(x_b);
    BN_free(y_b);
    BN_free(mul_b);
    
    BN_CTX_free(c);

    return result;
}