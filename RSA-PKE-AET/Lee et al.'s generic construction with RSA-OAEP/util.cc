#include "util.h"

void euler_phi(BIGNUM* phi, BIGNUM* p, BIGNUM* q){
    BIGNUM* pm1 = BN_new();
    BIGNUM* qm1 = BN_new();

    BN_CTX* c = BN_CTX_new();

    BN_sub(pm1, p, BN_value_one());
    BN_sub(qm1, q, BN_value_one());
    
    BN_mul(phi, pm1, qm1, c);

    BN_free(pm1);
    BN_free(qm1);
    BN_CTX_free(c);
}

void euler_phi(BIGNUM* phi, BIGNUM* N, BIGNUM* p, BIGNUM* q){
    BN_sub(phi, N, p);
    BN_sub(phi, phi, q);
    BN_add(phi, phi, BN_value_one());
}


void handleErrors()
{
    ERR_print_errors_fp(stderr);
    abort();
}

void sha3(BIGNUM* res, const BIGNUM *src, const int lambda)
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx;
    unsigned dlen;
    unsigned char* dest;

    switch (lambda)
    {
    case 80:
        md = EVP_sha3_224();
        dlen = SHA224_DIGEST_LENGTH;
        break;

    case 112:
        md = EVP_sha3_224();
        dlen = SHA224_DIGEST_LENGTH;
        break;

    case 128:
        md = EVP_sha3_256();
        dlen = SHA256_DIGEST_LENGTH;
        break;

    default:
        handleErrors();
        break;
    }

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
    {
        handleErrors();
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    { // returns 1 if successful
        handleErrors();
    }

    unsigned char *bytes = NULL;
    size_t size = BN_num_bytes(src);
    bytes = (unsigned char*)malloc(size);
    memset(bytes, 0x00, size);
    BN_bn2binpad(src, bytes, size);
    EVP_DigestUpdate(mdctx, bytes, size);
    free(bytes);

    if ((dest = (unsigned char *)OPENSSL_malloc(dlen)) == NULL)
    {
        handleErrors();
    }

    memset(dest, 0x00, dlen);
    if (EVP_DigestFinal_ex(mdctx, dest, &dlen) != 1)
    { // returns 1 if successful
        OPENSSL_free(dest);
        handleErrors();
    }

    BN_bin2bn(dest, dlen, res);

    EVP_MD_CTX_destroy(mdctx);
    OPENSSL_free(dest);
}

void sha3(BIGNUM* res, const BIGNUM *src1, const BIGNUM *src2, const BIGNUM *src3, const BIGNUM *src4, const int lambda)
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx;
    unsigned dlen;
    unsigned char* dest;

    switch (lambda)
    {
    case 80:
        md = EVP_sha3_224();
        dlen = SHA224_DIGEST_LENGTH;
        break;

    case 112:
        md = EVP_sha3_224();
        dlen = SHA224_DIGEST_LENGTH;
        break;

    case 128:
        md = EVP_sha3_256();
        dlen = SHA256_DIGEST_LENGTH;
        break;

    default:
        handleErrors();
        break;
    }

    if ((mdctx = EVP_MD_CTX_create()) == NULL)
    {
        handleErrors();
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1)
    { // returns 1 if successful
        handleErrors();
    }

    unsigned char *bytes = NULL;
    size_t size1 = BN_num_bytes(src1);
    bytes = (unsigned char*)malloc(size1);
    memset(bytes, 0x00, size1);
    BN_bn2binpad(src1, bytes, size1);
    EVP_DigestUpdate(mdctx, bytes, size1);
    free(bytes);

    size_t size2 = BN_num_bytes(src2);
    bytes = (unsigned char*)malloc(size2);
    memset(bytes, 0x00, size2);
    BN_bn2binpad(src2, bytes, size2);
    EVP_DigestUpdate(mdctx, bytes, size2);
    free(bytes);

    size_t size3 = BN_num_bytes(src3);
    bytes = (unsigned char*)malloc(size3);
    memset(bytes, 0x00, size3);
    BN_bn2binpad(src3, bytes, size3);
    EVP_DigestUpdate(mdctx, bytes, size3);
    free(bytes);

    size_t size4 = BN_num_bytes(src4);
    bytes = (unsigned char*)malloc(size4);
    memset(bytes, 0x00, size4);
    BN_bn2binpad(src4, bytes, size4);
    EVP_DigestUpdate(mdctx, bytes, size4);
    free(bytes);


    if ((dest = (unsigned char *)OPENSSL_malloc(dlen)) == NULL)
    {
        handleErrors();
    }

    memset(dest, 0x00, dlen);
    if (EVP_DigestFinal_ex(mdctx, dest, &dlen) != 1)
    { // returns 1 if successful
        OPENSSL_free(dest);
        handleErrors();
    }
    BN_bin2bn(dest, dlen, res);

    EVP_MD_CTX_destroy(mdctx);
    OPENSSL_free(dest);
}