#include "util.h"
#include "user.h"
#include "tester.h"

using namespace std;

int main(){
    typedef chrono::high_resolution_clock elapse_time;
    auto keygenDurationTotal = 0, encryptDurationTotal = 0, decryptDurationTotal = 0;
    auto authTotal = 0, testTotal = 0;

    int lambda = LAMBDA;
    int bitLenN = BLEN;

    BIGNUM* q = BN_new();
    BN_generate_prime_ex(q, HLEN, 1, NULL, NULL, NULL);

    tester t;
    user u1, u2;

    BIGNUM* m1Get = BN_new();
    BIGNUM* m2Get = BN_new();
    
    BIGNUM* result1_dec = BN_new();
    BIGNUM* result2_dec = BN_new();
    
    bool testResult;

    u1.setLambda(lambda);    u1.setBitLenN(bitLenN);
    u2.setLambda(lambda);    u2.setBitLenN(bitLenN);

    u1.initParams(); u2.initParams();
    u1.initMsg();   u2.initMsg();
    u1.initCtx();   u2.initCtx();
    u1.initTd();    u2.initTd();

    int iteration = 100;
    int cnt = 0;

    int keygen_elapsed = 0, enc_elapsed = 0, dec_elapsed = 0;
    int auth_elapsed = 0, test_elapsed = 0;

    for(int i = 0; i < iteration; i++){
        std::cout << cnt << endl;
        ////////////////////////////////////////// u1
        auto keygenStart = elapse_time::now();
        u1.keyGen_rand_e();
        auto keygenEnd = elapse_time::now();

        u1.genMsg();
        auto encryptStart = elapse_time::now();
        u1.encrypt(u1.ctx, u1.pk, q);
        auto encryptEnd = elapse_time::now();

        auto decryptStart = elapse_time::now();
        u1.decrypt(result1_dec, u1.ctx, q);
        auto decryptEnd = elapse_time::now();

        u1.getMsg(m1Get);
        //////////////////////////////////////////
        ////////////////////////////////////////// u2
        u2.keyGen_rand_e();

        u2.setMsg(m1Get);
        u2.encrypt(u2.ctx, u2.pk, q);
        u2.decrypt(result2_dec, u2.ctx, q);

        u2.getMsg(m2Get);
        //////////////////////////////////////////
        ////////////////////////////////////////// auth
        auto authStart = elapse_time::now();
        u1.auth();
        auto authEnd = elapse_time::now();
        
        u2.auth();
        //////////////////////////////////////////
        ////////////////////////////////////////// check original msg, decrypted msg
        
        if(BN_cmp(m1Get, result1_dec) != 0 || BN_cmp(m2Get, result2_dec) != 0){
            std::cout << cnt << " : msg is different" << endl;
            cout << BN_bn2hex(m1Get) << " : " << BN_bn2hex(result1_dec) << endl;
            cout << BN_bn2hex(m2Get) << " : " << BN_bn2hex(result2_dec) << endl;
        }
        //////////////////////////////////////// type1 test
        auto testStart = elapse_time::now();
        testResult = t.test(u1.ctx, u1.td, u1.pk.N2, u2.ctx, u2.td, u2.pk.N2, q, lambda);
        auto testEnd = elapse_time::now();

        if(testResult != true){
            cout << cnt << " : test fail" << endl;
        }
        //////////////////////////////////////////
        keygen_elapsed = chrono::duration_cast<std::chrono::milliseconds>(keygenEnd - keygenStart).count();
        enc_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(encryptEnd - encryptStart).count();
        dec_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(decryptEnd - decryptStart).count();

        auth_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(authEnd - authStart).count();
        test_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(testEnd - testStart).count();
 

        keygenDurationTotal += keygen_elapsed;
        encryptDurationTotal += enc_elapsed;
        decryptDurationTotal += dec_elapsed;

        authTotal += auth_elapsed;
        testTotal += test_elapsed;


        cnt++;

        u1.clearParams(); u2.clearParams();
        u1.clearMsg();   u2.clearMsg();
        u1.clearCtx();   u2.clearCtx();
        u1.clearTd();    u2.clearTd();
        
        BN_clear(m1Get);
        BN_clear(m2Get);
        BN_clear(result1_dec);
        BN_clear(result2_dec);
    }

    std::cout << "nanoseconds" << endl;
    std::cout << "keygen duration average time(milliseconds) : " << keygenDurationTotal / iteration << endl;
    std::cout << "encrypt duration average time : " << encryptDurationTotal / iteration << endl;
    std::cout << "decrypt duration average time : " << decryptDurationTotal / iteration << endl;
    std::cout << "-------------------------------" << endl;
    std::cout << "auth duration average time : " << authTotal / iteration << endl;
    std::cout << "-------------------------------" << endl;
    std::cout << "test duration average time : " << testTotal / iteration << endl;

    
    BN_free(m1Get);
    BN_free(m2Get);

    BN_free(result1_dec);
    BN_free(result2_dec);

    u1.freeParams(); u2.freeParams();
    u1.freeMsg();   u2.freeMsg();
    u1.freeCtx();   u2.freeCtx();
    u1.freeTd();    u2.freeTd();

    return 0;
}