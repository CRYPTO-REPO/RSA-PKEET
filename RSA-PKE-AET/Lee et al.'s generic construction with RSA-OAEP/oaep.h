#include "internal/deprecated.h"
#include "internal/constant_time.h"

#include <stdio.h>
#include "internal/cryptlib.h"
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include "rsa_local.h"



int RSA_padding_add_PKCS1_OAEP(unsigned char *to, int tlen,
                               const unsigned char *from, int flen,
                               const unsigned char *param, int plen, unsigned char* get_seed);

int ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(OSSL_LIB_CTX *libctx,
                                            unsigned char *to, int tlen,
                                            const unsigned char *from, int flen,
                                            const unsigned char *param,
                                            int plen, const EVP_MD *md,
                                            const EVP_MD *mgf1md, unsigned char* get_seed);

int RSA_padding_add_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                    const unsigned char *from, int flen,
                                    const unsigned char *param, int plen,
                                    const EVP_MD *md, const EVP_MD *mgf1md, unsigned char* get_seed);



int RSA_padding_check_PKCS1_OAEP(unsigned char *to, int tlen,
                                 const unsigned char *from, int flen, int num,
                                 const unsigned char *param, int plen, unsigned char* get_seed);


int RSA_padding_check_PKCS1_OAEP_mgf1(unsigned char *to, int tlen,
                                      const unsigned char *from, int flen,
                                      int num, const unsigned char *param,
                                      int plen, const EVP_MD *md,
                                      const EVP_MD *mgf1md, unsigned char* get_seed);

int PKCS1_MGF1(unsigned char *mask, long len,
               const unsigned char *seed, long seedlen, const EVP_MD *dgst);



