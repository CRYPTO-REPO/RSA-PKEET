#include "tester.h"

bool tester::test(BIGNUM* ctx_a[3], const BIGNUM* td_a, const BIGNUM* N2_a, BIGNUM* ctx_b[3], const BIGNUM* td_b, const BIGNUM* N2_b, const int lambda){
    BIGNUM* h_a = BN_new();
    BIGNUM* h_b = BN_new();

    BN_CTX* c = BN_CTX_new();

    bool result;

    const EVP_MD *md = NULL;
    switch (lambda)
    {
    case 80:
        md = EVP_sha3_224();
        break;

    case 112:
        md = EVP_sha3_224();
        break;

    case 128:
        md = EVP_sha3_256();
        break;

    default:
        handleErrors();
        break;
    }
    int md_size = EVP_MD_get_size(md);

    unsigned char* bytes_seed_a = (unsigned char*)malloc(md_size);
    unsigned char* bytes_seed_b = (unsigned char*)malloc(md_size);

    int size_h_em_ = OAEPLEN;
    unsigned char* h_em_a = (unsigned char*)malloc(size_h_em_);
    unsigned char* h_em_b = (unsigned char*)malloc(size_h_em_);
    unsigned char* bytes_h_msg_a = (unsigned char*)malloc(BYTES_HLEN);
    unsigned char* bytes_h_msg_b = (unsigned char*)malloc(BYTES_HLEN);

    BN_mod_exp(h_a, ctx_a[1], td_a, N2_a, c);
    BN_mod_exp(h_b, ctx_b[1], td_b, N2_b, c);

    BN_bn2binpad(h_a, h_em_a, size_h_em_);
    RSA_padding_check_PKCS1_OAEP_mgf1(bytes_h_msg_a, BYTES_HLEN, h_em_a, size_h_em_, size_h_em_, NULL, 0, md, md, bytes_seed_a);

    BN_bn2binpad(h_b, h_em_b, size_h_em_);
    RSA_padding_check_PKCS1_OAEP_mgf1(bytes_h_msg_b, BYTES_HLEN, h_em_b, size_h_em_, size_h_em_, NULL, 0, md, md, bytes_seed_b);

    BN_bin2bn(bytes_h_msg_a, BYTES_HLEN, h_a);
    BN_bin2bn(bytes_h_msg_b, BYTES_HLEN, h_b);

    if(BN_cmp(h_a, h_b) == 0){
        result = true;
    }else{
        result = false;
    }

    BN_free(h_a);
    BN_free(h_b);
    
    BN_CTX_free(c);

    return result;
}