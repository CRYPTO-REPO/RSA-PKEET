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
    cout << BN_bn2hex(msg) << endl;
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
    this->ctx[3] = BN_new();
}

void user::freeCtx(){
    BN_free(this->ctx[0]);
    BN_free(this->ctx[1]);
    BN_free(this->ctx[2]);
    BN_free(this->ctx[3]);
}

void user::clearCtx(){
    BN_clear(this->ctx[0]);
    BN_clear(this->ctx[1]);
    BN_clear(this->ctx[2]);
    BN_clear(this->ctx[3]);
}


void user::initTd(){
    this->td1[0] = BN_new();
    this->td1[1] = BN_new();
    this->td2 = BN_new();
}

void user::freeTd(){
    BN_free(this->td1[0]);
    BN_free(this->td1[1]);
    BN_free(this->td2);
}

void user::clearTd(){
    BN_clear(this->td1[0]);
    BN_clear(this->td1[1]);
    BN_clear(this->td2);
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


void user::encrypt(BIGNUM* ctx[4], publicKey pk){
    if(this->msg == NULL){
        cout << "msg is NULL" << endl;
        abort();
    }

    BIGNUM* r1 = BN_new();
    BIGNUM* r2 = BN_new();

    BIGNUM* zero = BN_new();
    BN_zero(zero);

    //ciphertext & hash
    BIGNUM* h2 = BN_new();
    BIGNUM* h3 = BN_new();

    BN_CTX* c = BN_CTX_new();
    
    // select r1, r2
    do{
        BN_rand_range(r1, pk.N1);
        BN_rand_range(r2, pk.N2);
    }while(!BN_cmp(r1, zero) || !BN_cmp(r2, zero));
    
    // C1
    BN_mod_exp(ctx[0], r1, pk.e1, pk.N1, c);

    // C2
    BN_mod_exp(ctx[1], r2, pk.e2, pk.N2, c);

    // C3
    sha3(ctx[2], r1, r2, lambda);
    BN_xor(ctx[2], ctx[2], BYTES_HLEN, this->msg, BYTES_HLEN);

    // C4
    sha3(h2, this->msg, lambda);
    sha3(h3, r2, ctx[0], ctx[1], ctx[2], lambda);
    BN_xor(ctx[3], h2, BYTES_HLEN, h3, BYTES_HLEN);

    BN_free(r1);
    BN_free(r2);
    BN_free(zero);

    BN_free(h2);
    BN_free(h3);

    BN_CTX_free(c);
}

void user::decrypt(BIGNUM* result, BIGNUM* ctx[4]){
    BIGNUM* m_ = BN_new();
    BIGNUM* r1 = BN_new();
    BIGNUM* r2 = BN_new();
    BN_CTX* c = BN_CTX_new();

    BIGNUM* h2 = BN_new();
    BIGNUM* h_ = BN_new();

    BN_mod_exp(r1, ctx[0], this->sk.d1, this->pk.N1, c);
    BN_mod_exp(r2, ctx[1], this->sk.d2, this->pk.N2, c);

    int hlen = BYTES_HLEN;

    sha3(m_, r1, r2, this->lambda);
    BN_xor(m_, ctx[2], hlen, m_, hlen);

    sha3(h_, r2, ctx[0], ctx[1], ctx[2], this->lambda);
    BN_xor(h_, ctx[3], hlen, h_, hlen);

    sha3(h2, m_, this->lambda);
    if(BN_cmp(h_, h2) == 0){
        BN_copy(result, m_);
    }else{
        BN_clear(result);
    }
    
    BN_free(m_);
    BN_free(r1);
    BN_free(r2);
    BN_CTX_free(c);

    BN_free(h2);
    BN_free(h_);
}

void user::auth1(){
    BN_copy(this->td1[0], this->pk.N2);
    BN_copy(this->td1[1], this->sk.d2);
}

void user::auth2(){
    BIGNUM* r2 = BN_new();
    BIGNUM* h3 = BN_new();
    BN_CTX* c = BN_CTX_new();

    BN_mod_exp(r2, this->ctx[1], this->sk.d2, this->pk.N2, c);
    sha3(h3, r2, this->ctx[0], this->ctx[1], this->ctx[2], this->lambda);
    BN_copy(this->td2, h3);

    BN_free(r2);
    BN_free(h3);
    BN_CTX_free(c);
}