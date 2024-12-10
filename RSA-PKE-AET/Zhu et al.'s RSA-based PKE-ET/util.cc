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

    int total_len;
    unsigned char* total;

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

    int iteration = BYTES_BLEN / BYTES_HLEN;
    int rem = BYTES_BLEN % BYTES_HLEN;

    total_len = dlen * (iteration + 1) + rem;
    total = (unsigned char*)malloc(total_len);
    memset(total, 0x00, total_len);

    for(int i = 0; i < iteration + 2; i++){
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

        ////////////////////////////////////////// additional extra fixed value
        size_t size_addi = 1;
        bytes = (unsigned char*)malloc(size_addi);
        memset(bytes, 0x00, size_addi);
        memset(bytes, i, size_addi);
        EVP_DigestUpdate(mdctx, bytes, size_addi);
        free(bytes);
        //////////////////////////////////////////


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

        if(i == iteration + 1){
            memcpy(total + i * dlen, dest, rem);
        }else{
            memcpy(total + i * dlen, dest, dlen);
        }

        EVP_MD_CTX_destroy(mdctx);
    }

    BN_bin2bn(total, total_len, res);

    free(total);
    OPENSSL_free(dest);
}

void sha3(BIGNUM* res, const BIGNUM *src1, const BIGNUM *src2, const int lambda)
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

void sha3(BIGNUM* res, const BIGNUM *src1, const BIGNUM *src2, const BIGNUM *src3, const BIGNUM *src4, const BIGNUM* src5, const int lambda)
{
    const EVP_MD *md = NULL;
    EVP_MD_CTX *mdctx;
    unsigned dlen;
    unsigned char* dest;

    unsigned total_len;
    unsigned char* total;

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

    int iteration = 2;
    total_len = dlen * iteration;
    total = (unsigned char*)malloc(total_len);
    memset(total, 0x00, total_len);

    for(int i = 0; i < iteration; i++){
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

        size_t size5 = BN_num_bytes(src5);
        bytes = (unsigned char*)malloc(size5);
        memset(bytes, 0x00, size5);
        BN_bn2binpad(src5, bytes, size5);
        EVP_DigestUpdate(mdctx, bytes, size5);
        free(bytes);


        ////////////////////////////////////////// additional extra fixed value
        size_t size_addi = 1;
        bytes = (unsigned char*)malloc(size_addi);
        memset(bytes, 0x00, size_addi);
        memset(bytes, i, size_addi);
        EVP_DigestUpdate(mdctx, bytes, size_addi);
        free(bytes);
        //////////////////////////////////////////


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

        memcpy(total + i * dlen, dest, dlen);

        EVP_MD_CTX_destroy(mdctx);
        OPENSSL_free(dest);
    }

    BN_bin2bn(total, total_len, res);

    free(total);
}

void sha3_msg(BIGNUM* res, const BIGNUM *src, const BIGNUM* mod, const int hashNum, const int lambda)
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
    
    ////////////////////////////////////////// additional extra fixed value
    size = 1;
    bytes = (unsigned char*)malloc(size);
    memset(bytes, 0x00, size);

    switch (hashNum){
    case 4:
        memset(bytes, h4_SV, size);
        break;
    case 5:
        memset(bytes, h5_SV, size);
        break;
    default:
        free(bytes);
        handleErrors();
        break;
    }
    
    EVP_DigestUpdate(mdctx, bytes, size);
    free(bytes);
    //////////////////////////////////////////
    
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

    BN_CTX* c = BN_CTX_new();

    BN_mod(res, res, mod, c);
    
    BN_CTX_free(c);
    EVP_MD_CTX_destroy(mdctx);
    OPENSSL_free(dest);
}

void BN_xor(BIGNUM* res, const BIGNUM* in1, const int in1len, const BIGNUM* in2, const int in2len){
    if(in1len != in2len){
        cout << "in1len != in2len" << endl;
        abort();
    }

    unsigned char *buf1 = (unsigned char*)malloc(in1len);
    unsigned char *buf2 = (unsigned char*)malloc(in2len);
    unsigned char *result = (unsigned char*)malloc(in2len);

    memset(buf1, 0x00, in1len);
    memset(buf2, 0x00, in2len);
    memset(result, 0x00, in2len);

    BN_bn2binpad(in1, buf1, in1len);
    BN_bn2binpad(in2, buf2, in2len);

    for(int i = 0; i < in2len; i++){
        result[i] = buf1[i] ^ buf2[i];
    }
    BN_bin2bn(result, in2len, res);

    free(buf1);
    free(buf2);
    free(result);
}

void BN_parse(BIGNUM* x, BIGNUM* y, const BIGNUM* xy, const int xlen, const int ylen, const int xylen){
    unsigned char* bytes_xy = (unsigned char*)malloc(xylen);
    unsigned char* bytes_x = (unsigned char*)malloc(xlen);
    unsigned char* bytes_y = (unsigned char*)malloc(ylen);

    memset(bytes_xy, 0x00, xylen);
    memset(bytes_x, 0x00, xlen);
    memset(bytes_y, 0x00, ylen);

    BN_bn2binpad(xy, bytes_xy, xylen);
    memcpy(bytes_x, bytes_xy, xlen);
    memcpy(bytes_y, bytes_xy + xlen, ylen);

    BN_bin2bn(bytes_x, xlen, x);
    BN_bin2bn(bytes_y, ylen, y);

    free(bytes_xy);
    free(bytes_x);
    free(bytes_y);
}

void BN_concat(BIGNUM* res, const BIGNUM* in1, const int in1len, const BIGNUM* in2, const int in2len){
    int reslen = in1len + in2len;

    unsigned char* bytes_in1 = (unsigned char*)malloc(in1len);
    unsigned char* bytes_in2 = (unsigned char*)malloc(in2len);
    unsigned char* bytes_res = (unsigned char*)malloc(reslen);

    memset(bytes_in1, 0x00, in1len);
    memset(bytes_in2, 0x00, in2len);
    memset(bytes_res, 0x00, reslen);

    BN_bn2binpad(in1, bytes_in1, in1len);
    BN_bn2binpad(in2, bytes_in2, in2len);
    memcpy(bytes_res, bytes_in1, in1len);
    memcpy(bytes_res + in1len, bytes_in2, in2len);

    BN_bin2bn(bytes_res, reslen, res);

    free(bytes_in1);
    free(bytes_in2);
    free(bytes_res);
}