#include "tester.h"

bool tester::test_type1(BIGNUM* ctx_a[4], BIGNUM* td_a[2], BIGNUM* ctx_b[4], BIGNUM* td_b[2], const int lambda){
    BIGNUM* r2_a = BN_new();
    BIGNUM* h3_a = BN_new();
    BIGNUM* h_a = BN_new();

    BIGNUM* r2_b = BN_new();
    BIGNUM* h3_b = BN_new();
    BIGNUM* h_b = BN_new();

    BN_CTX* c = BN_CTX_new();

    bool result;
    
    BN_mod_exp(r2_a, ctx_a[1], td_a[1], td_a[0], c);
    sha3(h3_a, r2_a, ctx_a[0], ctx_a[1], ctx_a[2], lambda);
    BN_xor(h_a, ctx_a[3], HLEN, h3_a, HLEN);

    BN_mod_exp(r2_b, ctx_b[1], td_b[1], td_b[0], c);
    sha3(h3_b, r2_b, ctx_b[0], ctx_b[1], ctx_b[2], lambda);
    BN_xor(h_b, ctx_b[3], HLEN, h3_b, HLEN);


    if(BN_cmp(h_a, h_b) == 0){
        result = true;
    }else{
        result = false;
    }

    BN_free(r2_a);
    BN_free(h3_a);
    BN_free(h_a);
    
    BN_free(r2_b);
    BN_free(h3_b);
    BN_free(h_b);
    
    BN_CTX_free(c);

    return result;
}

bool tester::test_type2(BIGNUM* ctx_a[4], const BIGNUM* td_a, BIGNUM* ctx_b[4], const BIGNUM* td_b, const int lambda){
    BIGNUM* h_a = BN_new();
    BIGNUM* h_b = BN_new();

    bool result;
    
    BN_xor(h_a, ctx_a[3], HLEN, td_a, HLEN);
    BN_xor(h_b, ctx_b[3], HLEN, td_b, HLEN);

    if(BN_cmp(h_a, h_b) == 0){
        result = true;
    }else{
        result = false;
    }
    
    BN_free(h_a);
    BN_free(h_b);

    return result;
}