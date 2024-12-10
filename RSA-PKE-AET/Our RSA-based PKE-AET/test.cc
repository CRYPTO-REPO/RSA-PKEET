#include "util.h"
#include "user.h"
#include "tester.h"

using namespace std;

int main(){
    typedef chrono::high_resolution_clock elapse_time;
    auto keygenDurationTotal = 0, encryptDurationTotal = 0, decryptDurationTotal = 0;
    auto auth1Total = 0, auth2Total = 0;
    auto testType1Total = 0, testType2Total = 0;

    int lambda = LAMBDA;
    int bitLenN = BLEN;

    tester t;
    user u1, u2;

    BIGNUM* m1Get = BN_new();
    BIGNUM* m2Get = BN_new();
    
    BIGNUM* result1_dec = BN_new();
    BIGNUM* result2_dec = BN_new();
    
    bool testType1Result, testType2Result;

    u1.setLambda(lambda);    u1.setBitLenN(bitLenN);
    u2.setLambda(lambda);    u2.setBitLenN(bitLenN);

    u1.initParams(); u2.initParams();
    u1.initMsg();   u2.initMsg();
    u1.initCtx();   u2.initCtx();
    u1.initTd();    u2.initTd();

    int iteration = 100;
    int cnt = 0;

    int keygen_elapsed = 0, enc_elapsed = 0, dec_elapsed = 0;
    int auth1_elapsed = 0, auth2_elapsed = 0;
    int testType1_elapsed = 0, testType2_elapsed = 0;

    for(int i = 0; i < iteration; i++){
        std::cout << cnt << endl;
        ////////////////////////////////////////// u1
        auto keygenStart = elapse_time::now();
        u1.keyGen();
        auto keygenEnd = elapse_time::now();

        u1.genMsg();
        auto encryptStart = elapse_time::now();
        u1.encrypt(u1.ctx, u1.pk);
        auto encryptEnd = elapse_time::now();

        auto decryptStart = elapse_time::now();
        u1.decrypt(result1_dec, u1.ctx);
        auto decryptEnd = elapse_time::now();

        u1.getMsg(m1Get);
        //////////////////////////////////////////
        ////////////////////////////////////////// u2
        u2.keyGen();

        u2.setMsg(m1Get);
        u2.encrypt(u2.ctx, u2.pk);
        u2.decrypt(result2_dec, u2.ctx);

        u2.getMsg(m2Get);
        //////////////////////////////////////////
        ////////////////////////////////////////// auth
        auto auth1Start = elapse_time::now();
        u1.auth1();
        auto auth1End = elapse_time::now();
        auto auth2Start = elapse_time::now();
        u1.auth2();
        auto auth2End = elapse_time::now();
        
        u2.auth1();
        u2.auth2();
        //////////////////////////////////////////
        ////////////////////////////////////////// check original msg, decrypted msg
        if(BN_cmp(m1Get, result1_dec) != 0 || BN_cmp(m2Get, result2_dec) != 0){
            std::cout << cnt << " : msg is different" << endl;
        }
        ////////////////////////////////////////// type1 test
        auto testType1Start = elapse_time::now();
        testType1Result = t.test_type1(u1.ctx, u1.td1, u2.ctx, u2.td1, lambda);
        auto testType1End = elapse_time::now();

        if(testType1Result != true){
            cout << cnt << " : type1 fail" << endl;
        }
        //////////////////////////////////////////
        ////////////////////////////////////////// type2 test
        auto testType2Start = elapse_time::now();
        testType2Result = t.test_type2(u1.ctx, u1.td2, u2.ctx, u2.td2, lambda);
        auto testType2End = elapse_time::now();

        if(testType2Result != true){
            cout << cnt << " : type2 fail" << endl;
        }
        //////////////////////////////////////////

        keygen_elapsed = chrono::duration_cast<std::chrono::milliseconds>(keygenEnd - keygenStart).count();
        enc_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(encryptEnd - encryptStart).count();
        dec_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(decryptEnd - decryptStart).count();

        auth1_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(auth1End - auth1Start).count();
        auth2_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(auth2End - auth2Start).count();

        testType1_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(testType1End - testType1Start).count();
        testType2_elapsed = chrono::duration_cast<std::chrono::nanoseconds>(testType2End - testType2Start).count();


        keygenDurationTotal += keygen_elapsed;
        encryptDurationTotal += enc_elapsed;
        decryptDurationTotal += dec_elapsed;

        auth1Total += auth1_elapsed;
        auth2Total += auth2_elapsed;

        testType1Total += testType1_elapsed;
        testType2Total += testType2_elapsed;


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
    std::cout << "auth1 duration average time : " << auth1Total / iteration << endl;
    std::cout << "auth2 duration average time : " << auth2Total / iteration << endl;
    std::cout << "-------------------------------" << endl;
    std::cout << "type1 duration average time : " << testType1Total / iteration << endl;
    std::cout << "type2 duration average time : " << testType2Total / iteration << endl;

    
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