#include "WEM/WEM_2EM.hpp"
#include "GF/GF28.h"
#include "utils/component.h"

#include <iostream>
#include <cstring>
#include <string>
#include <functional>
#include <random>
#include <cassert>
#include <chrono>

using std::cout;
using std::endl;

using component::printx;

constexpr int eqNum = 1 + (1 << 9); // 1 for the special equation

static void info(std::string s)
{
    static int steps;
    cout << "[" << steps << "] " << s << endl;
    ++steps;
    return;
}

static inline void swapWord(unsigned char t1[16], unsigned char t2[16])
{
    auto t1words = reinterpret_cast<unsigned int*>(t1);
    auto t2words = reinterpret_cast<unsigned int*>(t2);
    for (int i = 0; i < 4; ++i)
        if (t1words[i] != t2words[i]) {
            auto tmp = t1words[i];
            t1words[i] = t2words[i];
            t2words[i] = tmp;
            break;
        }
    return;
}

constexpr int eqSize = 256;
static inline void swapEq(unsigned char *eq1, unsigned char *eq2)
{
    unsigned char tmp[eqSize];
    memcpy(tmp, eq1, eqSize);
    memcpy(eq1, eq2, eqSize);
    memcpy(eq2, tmp, eqSize);
    return;
}
static inline void xorEq(unsigned char *eq, unsigned char *eq1, unsigned char *eq2)
{
    unsigned char tmp[eqSize];
    for (int i = 0; i < eqSize; ++i)
        tmp[i] = eq1[i] ^ eq2[i];
    memcpy(eq, tmp, eqSize);
    return;
}
static inline void mulEq(unsigned char *eq, unsigned char *eq1, unsigned char c)
{
    unsigned char tmp[eqSize];
    for (int i = 0; i < eqSize; ++i)
        tmp[i] = GF28::mul(eq1[i], c);
    memcpy(eq, tmp, eqSize);
    return;
}

static int solveLinear_old(unsigned char linearEqs[eqNum][eqSize])
{
    int rank = 0;
    for (int col = 0, firstRow = 0; col < eqSize; ++col) {
        bool hasOne = false;

        for (int row = firstRow; row < eqNum; ++row)
            if (linearEqs[row][col]) {
                swapEq(linearEqs[firstRow], linearEqs[row]);
                hasOne = true;
                break;
            }

        if (!hasOne) continue;

        ++rank;
        const auto pivot = linearEqs[firstRow][col];
        const auto invPivot = GF28::inv(pivot);
        mulEq(linearEqs[firstRow], linearEqs[firstRow], invPivot);

        for (int row = 0; row < eqNum; ++row)
            if (linearEqs[row][col] && row != firstRow) {
                unsigned char tmp[eqSize];
                mulEq(tmp, linearEqs[firstRow], linearEqs[row][col]);
                xorEq(linearEqs[row], linearEqs[row], tmp);
            }

        ++firstRow;
    }

    // Triangle form
    int oneRow;
    for (oneRow = eqNum - 1; oneRow >= 0; --oneRow) {
        bool isAny = false;
        for (int col = 0; col < eqSize; ++col)
            if (linearEqs[oneRow][col]) {
                isAny = true;
                break;
            }
        if (isAny) break;
    }
    while (!linearEqs[oneRow][oneRow]) {
        for (int i = oneRow - 1; i < eqSize; ++i)
            if (linearEqs[oneRow][i]) {
                swapEq(linearEqs[i], linearEqs[oneRow]);
                break;
            }

        --oneRow;
    }

    return rank;
}

unsigned char eqs[eqNum][256];
double bench()
{
    //info("Setup oracle");
    std::random_device rd;
    std::default_random_engine randomGen(rd());
    std::uniform_int_distribution<int> dist(0, 255);
    unsigned char secretKey[16];
    for (int i = 0; i < 16; ++i) secretKey[i] = static_cast<unsigned char>(dist(randomGen));
//    for (int i = 0; i < 16; ++i) secretKey[i] = static_cast<unsigned char>(0x00);

    WEMKey wemKey(secretKey);
    auto& wemHandler = WEM<2, 2>::instance();
    auto encOracle = std::bind(&WEM<2, 2>::WEMEncrypt, std::ref(wemHandler), std::placeholders::_1, std::placeholders::_2, wemKey);
    auto decOracle = std::bind(&WEM<2, 2>::WEMDecrypt, std::ref(wemHandler), std::placeholders::_1, std::placeholders::_2, wemKey);


    /*
    cout << endl << "===== test vector =====" << endl;
    unsigned char testvector[] = { '-', '#', '-', ' ', 'c', 'o', 'r', 'r', 'e', 'c', 't', '!', ' ', '-', '#', '-' };
    wemHandler.WEMEncrypt(testvector, testvector, wemKey);
    printx(testvector); cout << endl;
    wemHandler.WEMDecrypt(testvector, testvector, wemKey);
    for (int _vi = 0; _vi < 16; ++_vi) { cout << testvector[_vi]; } cout << endl;
    cout << "====== end  test ======" << endl << endl;
    */


    //info("Start Attack");

    //info("Query oracle");
    memset(eqs, 0x00, sizeof(eqs));

    unsigned char p1[16];
    unsigned char p2[16];
    for (int i = 0; i < 16; ++i) p1[i] = static_cast<unsigned char>(dist(randomGen));
    unsigned char randc = static_cast<unsigned char>(dist(randomGen));
    memcpy(p2, p1, 16);
    p1[12] = p1[12];
    p1[13] = p1[12];
    p1[14] = p1[12];
    p2[12] = randc;
    p2[13] = randc;
    p2[14] = randc;

    int eqCnt = 0;
    for (int c1 = 0x00; c1 <= 0xff; ++c1) {
        for (int c2 = 0x00; c2 <= 0xff; ++c2) {
            unsigned char plain1[16];
            unsigned char plain2[16];
            unsigned char cipher1[16];
            unsigned char cipher2[16];
    
            memcpy(plain1, p1, 16);
            memcpy(plain2, p2, 16);
            plain1[0] = c1;
            plain1[1] = c2;
            plain2[0] = c1;
            plain2[1] = c2;
       
            component::invSR(plain1);
            component::invSR(plain2);
            encOracle(cipher1, plain1);
            encOracle(cipher2, plain2);
        
            swapWord(cipher1, cipher2);
        
            decOracle(plain1, cipher1);
            decOracle(plain2, cipher2);
            component::SR(plain1);
            component::SR(plain2);
    
            // eq 1
            eqs[eqCnt][plain1[0]] ^= 0x01;
            eqs[eqCnt][plain1[1]] ^= 0x02;
            eqs[eqCnt][plain1[2]] ^= 0x03;
            eqs[eqCnt][plain1[3]] ^= 0x01;
    
            eqs[eqCnt][plain2[0]] ^= 0x01;
            eqs[eqCnt][plain2[1]] ^= 0x02;
            eqs[eqCnt][plain2[2]] ^= 0x03;
            eqs[eqCnt][plain2[3]] ^= 0x01;
    
            ++eqCnt;
    
            // eq 2
            eqs[eqCnt][plain1[0]] ^= 0x01;
            eqs[eqCnt][plain1[1]] ^= 0x01;
            eqs[eqCnt][plain1[2]] ^= 0x02;
            eqs[eqCnt][plain1[3]] ^= 0x03;
    
            eqs[eqCnt][plain2[0]] ^= 0x01;
            eqs[eqCnt][plain2[1]] ^= 0x01;
            eqs[eqCnt][plain2[2]] ^= 0x02;
            eqs[eqCnt][plain2[3]] ^= 0x03;
    
            ++eqCnt;

            // eq 3
            eqs[eqCnt][plain1[4]] ^= 0x01;
            eqs[eqCnt][plain1[5]] ^= 0x01;
            eqs[eqCnt][plain1[6]] ^= 0x02;
            eqs[eqCnt][plain1[7]] ^= 0x03;
    
            eqs[eqCnt][plain2[4]] ^= 0x01;
            eqs[eqCnt][plain2[5]] ^= 0x01;
            eqs[eqCnt][plain2[6]] ^= 0x02;
            eqs[eqCnt][plain2[7]] ^= 0x03;
    
            ++eqCnt;

            // eq 4
            eqs[eqCnt][plain1[4]] ^= 0x03;
            eqs[eqCnt][plain1[5]] ^= 0x01;
            eqs[eqCnt][plain1[6]] ^= 0x01;
            eqs[eqCnt][plain1[7]] ^= 0x02;
    
            eqs[eqCnt][plain2[4]] ^= 0x03;
            eqs[eqCnt][plain2[5]] ^= 0x01;
            eqs[eqCnt][plain2[6]] ^= 0x01;
            eqs[eqCnt][plain2[7]] ^= 0x02;
    
            ++eqCnt;

            // eq 5
            eqs[eqCnt][plain1[ 8]] ^= 0x02;
            eqs[eqCnt][plain1[ 9]] ^= 0x03;
            eqs[eqCnt][plain1[10]] ^= 0x01;
            eqs[eqCnt][plain1[11]] ^= 0x01;
    
            eqs[eqCnt][plain2[ 8]] ^= 0x02;
            eqs[eqCnt][plain2[ 9]] ^= 0x03;
            eqs[eqCnt][plain2[10]] ^= 0x01;
            eqs[eqCnt][plain2[11]] ^= 0x01;
    
            ++eqCnt;

            // eq 6
            eqs[eqCnt][plain1[ 8]] ^= 0x03;
            eqs[eqCnt][plain1[ 9]] ^= 0x01;
            eqs[eqCnt][plain1[10]] ^= 0x01;
            eqs[eqCnt][plain1[11]] ^= 0x02;
    
            eqs[eqCnt][plain2[ 8]] ^= 0x03;
            eqs[eqCnt][plain2[ 9]] ^= 0x01;
            eqs[eqCnt][plain2[10]] ^= 0x01;
            eqs[eqCnt][plain2[11]] ^= 0x02;
    
            ++eqCnt;

            // eq 7
            eqs[eqCnt][plain1[12]] ^= 0x02;
            eqs[eqCnt][plain1[13]] ^= 0x03;
            eqs[eqCnt][plain1[14]] ^= 0x01;
            eqs[eqCnt][plain1[15]] ^= 0x01;
    
            eqs[eqCnt][plain2[12]] ^= 0x02;
            eqs[eqCnt][plain2[13]] ^= 0x03;
            eqs[eqCnt][plain2[14]] ^= 0x01;
            eqs[eqCnt][plain2[15]] ^= 0x01;
    
            ++eqCnt;

            // eq 8
            eqs[eqCnt][plain1[12]] ^= 0x01;
            eqs[eqCnt][plain1[13]] ^= 0x02;
            eqs[eqCnt][plain1[14]] ^= 0x03;
            eqs[eqCnt][plain1[15]] ^= 0x01;
    
            eqs[eqCnt][plain2[12]] ^= 0x01;
            eqs[eqCnt][plain2[13]] ^= 0x02;
            eqs[eqCnt][plain2[14]] ^= 0x03;
            eqs[eqCnt][plain2[15]] ^= 0x01;
    
            ++eqCnt;

            if (eqCnt >= eqNum - 1) {
                break;
            }
        }
        if (eqCnt >= eqNum - 1) break;
    }
    for (int i = 0; i < 256; ++i) eqs[eqCnt][i] = 0x01; // special equation
    ++eqCnt;

    //info("Gauss Elimination");

    auto start = std::chrono::high_resolution_clock::now();
    const int rank = solveLinear_old(eqs);
    auto end = std::chrono::high_resolution_clock::now();

    //cout << "rank1: " << rank << endl;
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    //cout << duration << endl;

    return duration;
}

int main()
{
    for (int i = 0; i < 100; ++i) bench();

    double total = 0;
    for (int i = 0; i < 1000; ++i)
        total += bench();
    cout << total / 1000 << endl;
    return 0;
}

