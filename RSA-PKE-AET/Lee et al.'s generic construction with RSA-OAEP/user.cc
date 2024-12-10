#include "user.h"

void user::setLambda(const int lambda){
    this->lambda = lambda;
}

void user::setBitLenN(const int bitLenN){
    this->bitLenN = bitLenN;
}


void user::initParams(){
    this->pk.e1 = BN_new();
    this->pk.e2 = BN_new();
    this->pk.N1 = BN_new();
    this->pk.N2 = BN_new();

    this->sk.d1 = BN_new();
    this->sk.d2 = BN_new();
    this->sk.p1 = BN_new();
    this->sk.p2 = BN_new();
    this->sk.q1 = BN_new();
    this->sk.q2 = BN_new();
}

void user::clearParams(){
    BN_clear(this->pk.e1);
    BN_clear(this->pk.e2);
    BN_clear(this->pk.N1);
    BN_clear(this->pk.N2);

    BN_clear(this->sk.d1);
    BN_clear(this->sk.d2);
    BN_clear(this->sk.p1);
    BN_clear(this->sk.p2);
    BN_clear(this->sk.q1);
    BN_clear(this->sk.q2);
}

void user::freeParams(){
    BN_free(this->pk.e1);
    BN_free(this->pk.e2);
    BN_free(this->pk.N1);
    BN_free(this->pk.N2);

    BN_free(this->sk.d1);
    BN_free(this->sk.d2);
    BN_free(this->sk.p1);
    BN_free(this->sk.p2);
    BN_free(this->sk.q1);
    BN_free(this->sk.q2);
}


void user::initMsg(){
    this->msg = BN_new();
}

void user::genMsg(){
    // choose message m
    BN_rand(this->msg, HLEN, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY);
}


void user::printMsg(){
    cout << BN_bn2hex(this->msg) << endl;
}

void user::getMsg(BIGNUM* m){
    BN_copy(m, this->msg);
}

void user::setMsg(BIGNUM* m){
    BN_copy(this->msg, m);
}

void user::freeMsg(){
    BN_free(this->msg);
}

void user::clearMsg(){
    BN_clear(this->msg);
}


void user::initCtx(){
    this->ctx[0] = BN_new();
    this->ctx[1] = BN_new();
    this->ctx[2] = BN_new();
}

void user::freeCtx(){
    BN_free(this->ctx[0]);
    BN_free(this->ctx[1]);
    BN_free(this->ctx[2]);
}

void user::clearCtx(){
    BN_clear(this->ctx[0]);
    BN_clear(this->ctx[1]);
    BN_clear(this->ctx[2]);
}


void user::initTd(){
    this->td = BN_new();
}

void user::freeTd(){
    BN_free(this->td);
}

void user::clearTd(){
    BN_clear(this->td);
}


void user::keyGen(){    // fix e 65537
    BIGNUM* eulerPhi1 = BN_new();
    BIGNUM* eulerPhi2 = BN_new();
    
    BN_CTX* c = BN_CTX_new();
    
    // select p1,q1 and compute N1
    while(BN_num_bits(this->pk.N1) != BLEN){
        BN_generate_prime_ex(this->sk.p1, BLEN/2, 1, NULL, NULL, NULL);
        BN_generate_prime_ex(this->sk.q1, BLEN/2, 1, NULL, NULL, NULL);
        BN_mul(this->pk.N1, this->sk.p1, this->sk.q1, c);
    }

    // select p2,q2 and compute N2
    while(BN_num_bits(this->pk.N2) != BLEN){
        BN_generate_prime_ex(this->sk.p2, BLEN/2, 1, NULL, NULL, NULL);
        BN_generate_prime_ex(this->sk.q2, BLEN/2, 1, NULL, NULL, NULL);
        BN_mul(this->pk.N2, this->sk.p2, this->sk.q2, c);
    }
    
    // compute euler's phi function
    euler_phi(eulerPhi1, this->pk.N1, this->sk.p1, this->sk.q1);
    euler_phi(eulerPhi2, this->pk.N2, this->sk.p2, this->sk.q2);
    
    // set value e 65537
    BN_set_word(this->pk.e1,65537);
    BN_set_word(this->pk.e2,65537);

    // compute d = inverse(e) mod eulerPhi : d*e = 1 mod eulerPhi
    BN_mod_inverse(this->sk.d1, this->pk.e1, eulerPhi1, c);
    BN_mod_inverse(this->sk.d2, this->pk.e2, eulerPhi2, c);

    BN_free(eulerPhi1);
    BN_free(eulerPhi2);

    BN_CTX_free(c);
}

void user::keyGen_rand_e(){   // random e coprime with 
    BIGNUM* eulerPhi1 = BN_new();
    BIGNUM* eulerPhi2 = BN_new();
    BIGNUM* gcd = BN_new();
    BIGNUM* zero = BN_new();
    BN_zero(zero);

    BN_CTX* c = BN_CTX_new();
    
    // select p1,q1 and compute N1
    while(BN_num_bits(this->pk.N1) != BLEN){
        BN_generate_prime_ex(this->sk.p1, BLEN/2, 1, NULL, NULL, NULL);
        BN_generate_prime_ex(this->sk.q1, BLEN/2, 1, NULL, NULL, NULL);
        BN_mul(this->pk.N1, this->sk.p1, this->sk.q1, c);
    }

    // select p2,q2 and compute N2
    while(BN_num_bits(this->pk.N2) != BLEN){
        BN_generate_prime_ex(this->sk.p2, BLEN/2, 1, NULL, NULL, NULL);
        BN_generate_prime_ex(this->sk.q2, BLEN/2, 1, NULL, NULL, NULL);
        BN_mul(this->pk.N2, this->sk.p2, this->sk.q2, c);
    }
    
    // compute euler's phi function
    euler_phi(eulerPhi1, this->pk.N1, this->sk.p1, this->sk.q1);
    euler_phi(eulerPhi2, this->pk.N2, this->sk.p2, this->sk.q2);
    
    // set coprime(e, eulerPhi)
    do{
        do{
            BN_rand(this->pk.e1, BN_num_bits(eulerPhi1), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
        }while(!BN_cmp(this->pk.e1, zero) || BN_cmp(eulerPhi1, this->pk.e1) != 1);
        BN_gcd(gcd, eulerPhi1, this->pk.e1, c);
    }while(!BN_is_one(gcd));

    BN_clear(gcd);
    do{
        do{
            BN_rand(this->pk.e2, BN_num_bits(eulerPhi2), BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ODD);
        }while(!BN_cmp(this->pk.e2, zero) || BN_cmp(eulerPhi2, this->pk.e2) != 1);
        BN_gcd(gcd, eulerPhi2, this->pk.e2, c);
    }while(!BN_is_one(gcd));

    // compute d = inverse(e) mod eulerPhi : d*e = 1 mod eulerPhi
    BN_mod_inverse(this->sk.d1, this->pk.e1, eulerPhi1, c);
    BN_mod_inverse(this->sk.d2, this->pk.e2, eulerPhi2, c);

    BN_free(eulerPhi1);
    BN_free(eulerPhi2);
    BN_free(gcd);
    BN_free(zero);

    BN_CTX_free(c);
}


void user::encrypt(BIGNUM* ctx[3], publicKey pk){
    if(this->msg == NULL){
        cout << "msg is NULL" << endl;
        abort();
    }

    BIGNUM* BN_em = BN_new();
    BIGNUM* BN_h_em = BN_new();

    //ciphertext & hash
    BIGNUM* h1 = BN_new();
    BIGNUM* h2 = BN_new();

    BIGNUM* seed[2];
    seed[0] = BN_new();
    seed[1] = BN_new();

    BN_CTX* c = BN_CTX_new();

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

    unsigned char* bytes_seed1 = (unsigned char*)malloc(md_size);
    unsigned char* bytes_seed2 = (unsigned char*)malloc(md_size);

    // C1
    int size_em = OAEPLEN;

    unsigned char* em = (unsigned char*)malloc(size_em);
    unsigned char* bytes_msg = (unsigned char*)malloc(BYTES_HLEN);

    BN_bn2binpad(this->msg, bytes_msg, BYTES_HLEN);
    ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(NULL, em, size_em, bytes_msg, BYTES_HLEN, NULL, 0, md, md, bytes_seed1);
    BN_bin2bn(em, size_em, BN_em);

    BN_mod_exp(ctx[0], BN_em, pk.e1, pk.N1, c);

    // C2
    sha3(h1, this->msg, this->lambda);
    int size_h_em = OAEPLEN;
    unsigned char* h_em = (unsigned char*)malloc(size_h_em);
    unsigned char* bytes_h_msg = (unsigned char*)malloc(BYTES_HLEN);
    BN_bn2binpad(h1, bytes_h_msg, BYTES_HLEN);

    ossl_rsa_padding_add_PKCS1_OAEP_mgf1_ex(NULL, h_em, size_h_em, bytes_h_msg, BYTES_HLEN, NULL, 0, md, md, bytes_seed2);
    
    BN_bin2bn(h_em, size_h_em, BN_h_em);
    BN_mod_exp(ctx[1], BN_h_em, pk.e2, pk.N2, c);

    // seed1,2 -> BN
    BN_bin2bn(bytes_seed1, md_size, seed[0]);
    BN_bin2bn(bytes_seed2, md_size, seed[1]);


    // C3
    sha3(ctx[2], ctx[0], ctx[1], seed[0], seed[1], this->lambda);


    free(bytes_seed1);
    free(bytes_seed2);
    free(em);
    free(h_em);
    free(bytes_msg);
    free(bytes_h_msg);

    BN_free(BN_em);
    BN_free(BN_h_em);

    BN_free(seed[0]);
    BN_free(seed[1]);

    BN_free(h1);
    BN_free(h2);

    BN_CTX_free(c);
}

void user::decrypt(BIGNUM* result, BIGNUM* ctx[3]){
    BIGNUM* BN_em_ = BN_new();
    BIGNUM* BN_h_em_ = BN_new();

    BIGNUM* m_ = BN_new();
    BIGNUM* h_ = BN_new();

    BIGNUM* h1 = BN_new();
    BIGNUM* h2 = BN_new();

    BIGNUM* seed[2];
    seed[0] = BN_new();
    seed[1] = BN_new();

    BN_CTX* c = BN_CTX_new();

    const EVP_MD *md = NULL;
    switch (this->lambda)
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

    unsigned char* bytes_seed1 = (unsigned char*)malloc(md_size);
    unsigned char* bytes_seed2 = (unsigned char*)malloc(md_size);

    // C1 -> EM_m
    BN_mod_exp(BN_em_, ctx[0], this->sk.d1, this->pk.N1, c);

    int size_em_ = OAEPLEN;
    unsigned char* em_ = (unsigned char*)malloc(size_em_);
    unsigned char* bytes_msg = (unsigned char*)malloc(BYTES_HLEN);

    BN_bn2binpad(BN_em_, em_, size_em_);
    RSA_padding_check_PKCS1_OAEP_mgf1(bytes_msg, BYTES_HLEN, em_, size_em_, size_em_, NULL, 0, md, md, bytes_seed1);
    BN_bin2bn(bytes_seed1, md_size, seed[0]);


    // C2 -> EM_h_m
    BN_mod_exp(BN_h_em_, ctx[1], this->sk.d2, this->pk.N2, c);

    int size_h_em_ = OAEPLEN;
    unsigned char* h_em_ = (unsigned char*)malloc(size_h_em_);
    unsigned char* bytes_h_msg = (unsigned char*)malloc(BYTES_HLEN);

    BN_bn2binpad(BN_h_em_, h_em_, size_h_em_);
    RSA_padding_check_PKCS1_OAEP_mgf1(bytes_h_msg, BYTES_HLEN, h_em_, size_h_em_, size_em_, NULL, 0, md, md, bytes_seed2);
    BN_bin2bn(bytes_seed2, md_size, seed[1]);

    BN_bin2bn(bytes_msg, BYTES_HLEN, m_);
    BN_bin2bn(bytes_h_msg, BYTES_HLEN, h_);
    
    // check
    sha3(h1, m_, this->lambda);
    sha3(h2, ctx[0], ctx[1], seed[0], seed[1], this->lambda);

    if(BN_cmp(h_, h1) == 0 && BN_cmp(h2, ctx[2]) == 0){
        BN_copy(result, m_);
    }else{
        BN_clear(result);
    }
 
    free(bytes_seed1);
    free(bytes_seed2);
    free(em_);
    free(h_em_);
    free(bytes_msg);
    free(bytes_h_msg);

    BN_free(m_);
    BN_free(h_);

    BN_free(h1);
    BN_free(h2);

    BN_free(BN_em_);
    BN_free(BN_h_em_);

    BN_free(seed[0]);
    BN_free(seed[1]);

    BN_CTX_free(c);
}

void user::auth(){
    BN_copy(this->td, this->sk.d2);
}